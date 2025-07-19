import requests
import base64
import json
import yaml
import os
import re
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import logging
from typing import List, Dict, Union, Any, Optional

# --- 配置 ---
# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# GitHub raw 链接列表
# 这里的链接应该包含有效的协议头 (http:// 或 https://)
SOURCE_URLS: List[str] = [
    "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt",
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt",
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
]

# 输出文件路径
OUTPUT_DIR: str = 'input'
OUTPUT_FILENAME: str = 'output.yml'
FULL_OUTPUT_PATH: str = os.path.join(OUTPUT_DIR, OUTPUT_FILENAME)

# 请求超时时间 (秒)
REQUEST_TIMEOUT: int = 15

# --- 初始化 ---
# 配置请求重试机制
session = requests.Session()
# 429: Too Many Requests; 5xx: Server Errors
retries = Retry(total=5, backoff_factor=2, status_forcelist=[429, 500, 502, 503, 504])
session.mount('http://', HTTPAdapter(max_retries=retries))
session.mount('https://', HTTPAdapter(max_retries=retries))

# --- 辅助函数：节点解析 ---
def _decode_base64_urlsafe(encoded_string: str) -> Optional[str]:
    """
    安全地解码 URL 安全的 Base64 字符串，处理填充字符。
    """
    # 填充缺失的 '=' 字符，确保长度是 4 的倍数
    padding_needed = -len(encoded_string) % 4
    if padding_needed > 0:
        encoded_string += '=' * padding_needed
    try:
        return base64.urlsafe_b64decode(encoded_string).decode('utf-8', errors='ignore')
    except Exception as e:
        logger.debug(f"Base64 URL 安全解码失败: {e}")
        return None

def parse_ss_link(link: str) -> Optional[Dict[str, Any]]:
    """
    解析 Shadowsocks (ss://) 链接。
    """
    try:
        if not link.startswith('ss://'):
            return None

        # 分割出 Base64 编码部分和服务器信息部分
        parts = link[5:].split('@')
        if len(parts) < 2:
            logger.warning(f"SS 链接格式错误 (缺少@): {link}")
            return None

        encoded_creds = parts[0]
        server_info = parts[1].split('#')[0] # 去除备注

        decoded_creds = _decode_base64_urlsafe(encoded_creds)
        if not decoded_creds or ':' not in decoded_creds:
            logger.warning(f"SS 凭证解码失败或格式错误: {link}")
            return None

        method, password = decoded_creds.split(':', 1) # 只分割一次，防止密码中包含冒号
        server, port_str = server_info.split(':', 1)

        port = int(port_str) # 端口必须是整数

        # 尝试提取备注
        remark_match = re.search(r'#(.+)$', link)
        remark = remark_match.group(1) if remark_match else f"{server}:{port}"

        return {
            'type': 'ss',
            'method': method,
            'password': password,
            'server': server,
            'port': port,
            'name': remark # 添加备注
        }
    except ValueError as e:
        logger.error(f"SS 链接解析数值错误 ({link}): {e}")
    except IndexError as e:
        logger.error(f"SS 链接解析索引错误 ({link}): {e}")
    except Exception as e:
        logger.error(f"解析 ss:// 链接时发生未知错误 ({link}): {e}", exc_info=True)
    return None

def parse_vmess_link(link: str) -> Optional[Dict[str, Any]]:
    """
    解析 Vmess (vmess://) 链接。
    """
    try:
        if not link.startswith('vmess://'):
            return None
        encoded_json = link[8:]
        decoded_json = _decode_base64_urlsafe(encoded_json)
        if not decoded_json:
            logger.warning(f"Vmess Base64 解码失败: {link}")
            return None
        
        vmess_config = json.loads(decoded_json)
        # 提取关键信息，确保兼容常见格式
        node = {
            'type': 'vmess',
            'name': vmess_config.get('ps', 'Unnamed Vmess Node'),
            'server': vmess_config.get('add'),
            'port': int(vmess_config.get('port')),
            'uuid': vmess_config.get('id'),
            'alterId': int(vmess_config.get('aid', 0)),
            'security': vmess_config.get('scy', 'auto'),
            'network': vmess_config.get('net', 'tcp'),
            'tls': vmess_config.get('tls', ''),
            'flow': vmess_config.get('flow', ''), # 新增 flow
        }
        # 处理传输协议设置
        if node['network'] == 'ws':
            node['ws-path'] = vmess_config.get('path', '/')
            node['ws-headers'] = json.loads(vmess_config.get('host', '{}')) # host可能是JSON字符串
            if isinstance(node['ws-headers'], str): # 有些host直接是字符串
                 node['ws-headers'] = {'Host': node['ws-headers']}
        
        # 移除空值
        node = {k: v for k, v in node.items() if v is not None and v != ''}
        return node
    except (json.JSONDecodeError, ValueError) as e:
        logger.error(f"Vmess 链接 JSON 解析或类型转换失败 ({link}): {e}")
    except Exception as e:
        logger.error(f"解析 vmess:// 链接时发生未知错误 ({link}): {e}", exc_info=True)
    return None

def parse_trojan_link(link: str) -> Optional[Dict[str, Any]]:
    """
    解析 Trojan (trojan://) 链接。
    """
    try:
        if not link.startswith('trojan://'):
            return None
        
        match = re.match(r'trojan://([^@]+)@([^:]+):(\d+)(?:\?([^#]+))?(?:#(.+))?', link)
        if not match:
            logger.warning(f"Trojan 链接格式不匹配: {link}")
            return None
        
        password, server, port_str, params_str, remark = match.groups()
        port = int(port_str)
        
        node = {
            'type': 'trojan',
            'name': remark if remark else f"{server}:{port}",
            'server': server,
            'port': port,
            'password': password
        }
        
        if params_str:
            params = dict(urlparse.parse_qsl(params_str))
            node['sni'] = params.get('sni', params.get('peer-fingerprint')) # 兼容 sni/peer-fingerprint
            node['allowInsecure'] = params.get('allowInsecure', '0').lower() == '1'
            if 'alpn' in params:
                node['alpn'] = [a.strip() for a in params['alpn'].split(',')]
            if 'flow' in params:
                node['flow'] = params['flow']
        
        # 移除空值
        node = {k: v for k, v in node.items() if v is not None and v != ''}
        return node
    except ValueError as e:
        logger.error(f"Trojan 链接解析数值错误 ({link}): {e}")
    except Exception as e:
        logger.error(f"解析 trojan:// 链接时发生未知错误 ({link}): {e}", exc_info=True)
    return None

def parse_vless_link(link: str) -> Optional[Dict[str, Any]]:
    """
    解析 VLESS (vless://) 链接。
    """
    try:
        if not link.startswith('vless://'):
            return None
        
        match = re.match(r'vless://([^@]+)@([^:]+):(\d+)(?:\?([^#]+))?(?:#(.+))?', link)
        if not match:
            logger.warning(f"VLESS 链接格式不匹配: {link}")
            return None
        
        uuid, server, port_str, params_str, remark = match.groups()
        port = int(port_str)
        
        node = {
            'type': 'vless',
            'name': remark if remark else f"{server}:{port}",
            'server': server,
            'port': port,
            'uuid': uuid,
            'tls': 'tls' if 'security=tls' in params_str else '', # 简单判断TLS
            'flow': None # VLESS flow通常在URL参数中
        }
        
        if params_str:
            params = dict(urlparse.parse_qsl(params_str))
            node['flow'] = params.get('flow')
            if 'security' in params and params['security'] == 'tls':
                node['tls'] = 'tls'
                node['sni'] = params.get('sni', params.get('host')) # host也可以作为sni
                node['allowInsecure'] = params.get('allowInsecure', '0').lower() == '1'
            
            if params.get('type') == 'ws': # WebSocket
                node['network'] = 'ws'
                node['ws-path'] = params.get('path', '/')
                node['ws-headers'] = {'Host': params.get('host', '')} if 'host' in params else {}
            elif params.get('type') == 'grpc': # gRPC
                node['network'] = 'grpc'
                node['grpc-serviceName'] = params.get('serviceName')
        
        # 移除空值
        node = {k: v for k, v in node.items() if v is not None and v != ''}
        return node
    except ValueError as e:
        logger.error(f"VLESS 链接解析数值错误 ({link}): {e}")
    except Exception as e:
        logger.error(f"解析 vless:// 链接时发生未知错误 ({link}): {e}", exc_info=True)
    return None

def parse_hysteria2_link(link: str) -> Optional[Dict[str, Any]]:
    """
    解析 Hysteria2 (hysteria2://) 链接。
    """
    try:
        if not link.startswith('hysteria2://'):
            return None

        # 提取用户密码、服务器、端口和可选参数
        match = re.match(r'hysteria2://([^@]+)@([^:]+):(\d+)(?:\?([^#]+))?(?:#(.+))?', link)
        if not match:
            logger.warning(f"Hysteria2 链接格式不匹配: {link}")
            return None

        password, server, port_str, params_str, remark = match.groups()
        port = int(port_str)

        node = {
            'type': 'hysteria2',
            'name': remark if remark else f"{server}:{port}",
            'server': server,
            'port': port,
            'password': password,
            'obfs': None, # 混淆类型
            'obfs-password': None, # 混淆密码
            'up': None, # 上行带宽
            'down': None, # 下行带宽
            'sni': None,
            'fingerprint': None, # 客户端指纹
            'pinSHA256': None, # TLS 指纹
            'skipCertVerify': False # 跳过证书验证
        }

        if params_str:
            params = dict(urlparse.parse_qsl(params_str))
            
            if 'obfs' in params:
                node['obfs'] = params['obfs']
            if 'obfsParam' in params:
                node['obfs-password'] = params['obfsParam']
            if 'up' in params:
                node['up'] = params['up']
            if 'down' in params:
                node['down'] = params['down']
            if 'sni' in params:
                node['sni'] = params['sni']
            if 'fingerprint' in params:
                node['fingerprint'] = params['fingerprint']
            if 'pinSHA256' in params:
                node['pinSHA256'] = [p.strip() for p in params['pinSHA256'].split(',')]
            if params.get('skipCertVerify', '0').lower() == '1':
                node['skipCertVerify'] = True
            if 'alpn' in params:
                node['alpn'] = [a.strip() for a in params['alpn'].split(',')]

        # 移除空值
        node = {k: v for k, v in node.items() if v is not None and v != ''}
        return node
    except ValueError as e:
        logger.error(f"Hysteria2 链接解析数值错误 ({link}): {e}")
    except Exception as e:
        logger.error(f"解析 hysteria2:// 链接时发生未知错误 ({link}): {e}", exc_info=True)
    return None

def parse_general_link(link: str) -> Optional[Dict[str, Any]]:
    """
    尝试解析支持的所有代理协议链接。
    """
    if link.startswith('ss://'):
        return parse_ss_link(link)
    elif link.startswith('vmess://'):
        return parse_vmess_link(link)
    elif link.startswith('trojan://'):
        return parse_trojan_link(link)
    elif link.startswith('vless://'):
        return parse_vless_link(link)
    elif link.startswith('hysteria2://'):
        return parse_hysteria2_link(link)
    # 可以在这里添加其他协议的解析器
    return None

# --- 内容解析器 ---
def parse_text_to_dict_custom(text: str) -> Dict[str, Any]:
    """
    尝试解析纯文本为字典，主要用于处理混合了节点链接和简单键值对的文本。
    """
    config: Dict[str, Any] = {'nodes': []}
    lines = text.splitlines()
    
    # 跟踪当前所在的 YAML 样式嵌套 section
    current_yaml_sections: List[str] = []
    
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # 尝试解析为节点链接
        node = parse_general_link(line)
        if node:
            config['nodes'].append(node)
            continue

        # 尝试解析为 YAML 风格的键值对或 Section
        # 这里使用更通用的 YAML 解析逻辑来处理可能的嵌套
        try:
            # 尝试加载为 YAML
            temp_yaml = yaml.safe_load(line)
            if isinstance(temp_yaml, dict):
                # 如果是顶层键值对，直接添加到 config
                if len(current_yaml_sections) == 0:
                    for k, v in temp_yaml.items():
                        if k == 'proxies' and isinstance(v, list):
                            # 如果是 'proxies' 列表，添加到 nodes
                            config['nodes'].extend(v)
                        else:
                            config[k] = v
                else:
                    # 如果有嵌套，则更新最内层字典
                    current_dict = config
                    for sec in current_yaml_sections:
                        current_dict = current_dict.setdefault(sec, {})
                    for k, v in temp_yaml.items():
                        if k == 'proxies' and isinstance(v, list):
                            config['nodes'].extend(v) # proxies始终添加到顶层nodes
                        else:
                            current_dict[k] = v
                continue
            elif isinstance(temp_yaml, list):
                # 如果是列表，尝试将其中的字典作为节点
                for item in temp_yaml:
                    if isinstance(item, dict):
                        config['nodes'].append(item)
                continue
        except yaml.YAMLError:
            pass # 不是有效的 YAML 行

        # 尝试解析为简单键值对 (如 key=value)
        if '=' in line:
            parts = line.split('=', 1)
            if len(parts) == 2:
                key, value_str = parts[0].strip(), parts[1].strip()
                if key:
                    # 尝试类型转换
                    value: Any = value_str
                    try:
                        if value_str.lower() in ('true', 'false'):
                            value = value_str.lower() == 'true'
                        elif value_str.isdigit():
                            value = int(value_str)
                        elif value_str.replace('.', '', 1).isdigit() and value_str.count('.') == 1:
                            value = float(value_str)
                        elif value_str.startswith('[') and value_str.endswith(']'):
                            value = json.loads(value_str)
                        elif value_str.startswith('{') and value_str.endswith('}'):
                            value = json.loads(value_str)
                    except (ValueError, json.JSONDecodeError):
                        pass # 保持为字符串

                    # 将键值对添加到当前作用域（如果没有嵌套，就是顶层）
                    if len(current_yaml_sections) == 0:
                        config[key] = value
                    else:
                        current_dict = config
                        for sec in current_yaml_sections:
                            current_dict = current_dict.setdefault(sec, {})
                        current_dict[key] = value
                    continue
    return config

def parse_any_content(content: str, url: str) -> Optional[Union[Dict, List]]:
    """
    尝试解析文件内容为 YAML、JSON、Base64 解码后的 JSON/YAML，或自定义纯文本。
    解析顺序：YAML -> JSON -> Base64(YAML/JSON) -> 自定义文本解析
    """
    # 1. 尝试作为 YAML 解析
    try:
        config = yaml.safe_load(content)
        if config is not None:
            logger.debug(f"内容成功作为 YAML 解析 ({url})")
            return config
    except yaml.YAMLError as e:
        logger.debug(f"YAML 解析失败 ({url}): {e}")

    # 2. 尝试作为 JSON 解析
    try:
        config = json.loads(content)
        if config is not None:
            logger.debug(f"内容成功作为 JSON 解析 ({url})")
            return config
    except json.JSONDecodeError as e:
        logger.debug(f"JSON 解析失败 ({url}): {e}")

    # 3. 尝试作为 Base64 解码
    decoded_content = _decode_base64_urlsafe(content.strip())
    if decoded_content:
        # 尝试解码后的内容作为 YAML
        try:
            config = yaml.safe_load(decoded_content)
            if config is not None:
                logger.debug(f"内容成功作为 Base64(YAML) 解析 ({url})")
                return config
        except yaml.YAMLError as e:
            logger.debug(f"Base64(YAML) 解析失败 ({url}): {e}")

        # 尝试解码后的内容作为 JSON
        try:
            config = json.loads(decoded_content)
            if config is not None:
                logger.debug(f"内容成功作为 Base64(JSON) 解析 ({url})")
                return config
        except json.JSONDecodeError as e:
            logger.debug(f"Base64(JSON) 解析失败 ({url}): {e}")
    else:
        logger.debug(f"内容无法 Base64 解码 ({url})")

    # 4. 尝试作为自定义纯文本格式解析
    try:
        config = parse_text_to_dict_custom(content)
        if config and (config.get('nodes') or len(config) > 0): # 至少有节点或有其他键值对
            logger.debug(f"内容成功作为自定义文本解析 ({url})")
            return config
    except Exception as e:
        logger.debug(f"自定义文本解析失败 ({url}): {e}")

    logger.warning(f"无法解析来自 {url} 的内容。")
    return None

# --- 主逻辑函数 ---
def fetch_and_parse_configs(urls: List[str]) -> List[Dict[str, Any]]:
    """
    获取并解析所有链接的配置。
    """
    all_parsed_configs: List[Dict[str, Any]] = []
    for url in urls:
        logger.info(f"尝试从 {url} 获取内容...")
        try:
            response = session.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status() # 对 4xx/5xx 状态码抛出异常
            
            # 使用 response.text 获取内容，requests 会根据 HTTP 头自动处理编码
            # 除非有明确的编码问题，否则不需要手动 encode/decode
            content = response.text
            
            config = parse_any_content(content, url)
            if config:
                # 统一将顶级列表转换为 {'proxies': [...]} 结构，方便后续合并
                if isinstance(config, list):
                    all_parsed_configs.append({'proxies': config})
                else:
                    all_parsed_configs.append(config)
                logger.info(f"成功解析并添加来自 {url} 的配置。")
            else:
                logger.warning(f"跳过 {url}：内容无法识别或不包含有效配置。")

        except requests.exceptions.Timeout:
            logger.error(f"从 {url} 获取内容超时 ({REQUEST_TIMEOUT}秒)。")
        except requests.exceptions.RequestException as e:
            logger.error(f"无法从 {url} 获取内容 (请求错误): {e}")
        except Exception as e:
            logger.error(f"处理 {url} 时发生未知错误: {e}", exc_info=True)
            
    return all_parsed_configs

def merge_configs(configs: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    合并从不同来源获取的配置。
    优先合并 'proxies' (或 'nodes') 列表。
    对于其他字典或列表，进行适当合并或覆盖。
    """
    merged_config: Dict[str, Any] = {'proxies': []} # 将 'nodes' 统一命名为 'proxies' 以兼容 Clash

    for config in configs:
        if not isinstance(config, dict):
            logger.warning(f"跳过非字典类型的配置: {type(config)}")
            continue

        for key, value in config.items():
            if key in ['proxies', 'nodes']: # 兼容 nodes 和 proxies 字段
                if isinstance(value, list):
                    # 确保添加到 proxies 的是字典，过滤掉非字典项
                    valid_nodes = [item for item in value if isinstance(item, dict)]
                    merged_config['proxies'].extend(valid_nodes)
                else:
                    logger.warning(f"键 '{key}' 下的值不是列表，跳过合并。")
            elif isinstance(value, dict):
                # 如果是字典，进行深合并
                if key not in merged_config or not isinstance(merged_config[key], dict):
                    merged_config[key] = {}
                merged_config[key].update(value) # 简单 update 覆盖同名键
            elif isinstance(value, list):
                # 如果是列表 (非 proxies/nodes)，则扩展
                if key not in merged_config or not isinstance(merged_config[key], list):
                    merged_config[key] = []
                merged_config[key].extend(value)
            else:
                # 其他类型，直接赋值 (后来的覆盖前面的)
                merged_config[key] = value
                
    # 移除重复的代理节点，基于节点的唯一标识 (例如 type, server, port, name)
    # 这是一个简化的去重，更严谨的去重需要考虑所有关键属性
    unique_proxies: List[Dict[str, Any]] = []
    seen_proxies = set()
    for proxy in merged_config['proxies']:
        # 创建一个可哈希的元组作为唯一标识
        # 这里仅使用 type, server, port 作为示例，你可以根据需要添加更多字段
        # 注意：某些代理协议可能没有port，或uuid等唯一标识
        identifier_parts = []
        for k in ['type', 'server', 'port', 'uuid', 'name', 'password', 'obfs-password']:
            if k in proxy:
                identifier_parts.append(str(proxy[k]))
        
        identifier = tuple(identifier_parts)
        
        if identifier and identifier not in seen_proxies:
            unique_proxies.append(proxy)
            seen_proxies.add(identifier)
        elif not identifier: # 无法生成标识符的，也添加到列表（可能是不完整的节点）
             unique_proxies.append(proxy)

    merged_config['proxies'] = unique_proxies
    
    # 调整 Clash YAML 格式：proxies 通常是顶级键
    # 如果 top-level proxies 键是空的，可以考虑移除
    if not merged_config['proxies']:
        del merged_config['proxies']
        
    return merged_config


def main():
    logger.info("启动代理配置收集器。")

    # 确保 output 目录存在
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 获取并解析所有配置
    configs = fetch_and_parse_configs(SOURCE_URLS)

    if not configs:
        logger.warning("未能成功解析任何配置，将生成一个空的输出文件。")
        yaml_output = "# 没有有效的配置数据或无法解析的来源\nproxies: []\n"
        with open(FULL_OUTPUT_PATH, 'w', encoding='utf-8') as f:
            f.write(yaml_output)
        logger.info(f"空配置已保存到 {FULL_OUTPUT_PATH}")
        return

    # 合并配置
    merged_config = merge_configs(configs)

    # 转换为 YAML
    # allow_unicode=True 用于正确处理中文等非 ASCII 字符
    # sort_keys=False 保持字典键的原始顺序（如果可能）
    # default_flow_style=False 确保输出是块样式，而不是紧凑的流样式
    yaml_output = yaml.dump(merged_config, allow_unicode=True, sort_keys=False, default_flow_style=False, indent=2)

    # 保存到 output.yml
    with open(FULL_OUTPUT_PATH, 'w', encoding='utf-8') as f:
        f.write(yaml_output)

    logger.info(f"配置已合并并保存到 {FULL_OUTPUT_PATH}")
    logger.debug("\n合并后的 YAML 内容示例：\n" + yaml_output[:1000] + "...") # 只显示前1000字符
    logger.info("代理配置收集器运行完成。")

if __name__ == "__main__":
    main()
