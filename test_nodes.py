import asyncio
import aiohttp
import yaml
import os
import subprocess
import sys
import time
from typing import Dict, List
from yaml import SafeLoader
from urllib.parse import urlparse, unquote, parse_qs
import base64
import json
import re

# --- YAML 相关配置 (保持不变) ---
def str_constructor(loader, node):
    return str(node.value)

SafeLoader.add_constructor('!str', str_constructor)

# --- 节点解析函数 ---
def parse_node_url_to_mihomo_config(node_url: str) -> Dict | None:
    """
    解析节点URL，将其转换为Mihomo (Clash.Meta) 配置字典格式。
    支持 ss, vless, vmess, trojan, hysteria2。
    这是一个简化示例，实际解析需要更复杂的逻辑来处理不同协议和参数。
    """
    node_url = node_url.strip()
    if not node_url:
        return None

    # 统一处理标签，有些协议的标签在URL片段中
    tag_match = re.search(r'#([^#]+)$', node_url)
    tag = unquote(tag_match.group(1)) if tag_match else "Unnamed Node"

    try:
        if node_url.startswith("ss://"):
            # Shadowsocks: ss://[cipher:password@]server:port[#tag] 或 ss://base64_encoded_info[#tag]
            # 优先尝试解析 base64 编码的 SS
            if "@" not in node_url.split('#')[0]: # 可能是 base64 编码
                try:
                    # 移除 ss:// 和可能的 #tag，然后 base64 解码
                    encoded_part = node_url[5:].split('#')[0]
                    decoded_info = base64.urlsafe_b64decode(encoded_part + '==').decode('utf-8')
                    # 格式可能是 method:password@server:port
                    parts = decoded_info.split('@')
                    if len(parts) == 2:
                        cipher_password, address_port = parts
                        cipher, password = cipher_password.split(':')
                        server, port = address_port.split(':')
                        return {
                            'name': tag,
                            'type': 'ss',
                            'server': server,
                            'port': int(port),
                            'cipher': cipher,
                            'password': password,
                            'udp': True
                        }
                except Exception:
                    pass # 如果不是 base64 编码或者解析失败，尝试普通格式

            # 普通格式 ss://cipher:password@server:port#tag
            match = re.match(r'ss://([^:]+):([^@]+)@([^:]+):(\d+)(?:#(.+))?', node_url)
            if match:
                cipher, password, server, port, name_fragment = match.groups()
                return {
                    'name': unquote(name_fragment) if name_fragment else tag,
                    'type': 'ss',
                    'server': server,
                    'port': int(port),
                    'cipher': cipher,
                    'password': password,
                    'udp': True
                }

        elif node_url.startswith("vless://"):
            parsed_url = urlparse(node_url)
            uuid_host_port = parsed_url.netloc
            if '@' not in uuid_host_port:
                raise ValueError("VLESS URL 格式错误: 缺少 @ 分隔符")
            uuid, server_port_str = uuid_host_port.split('@', 1)
            server, port_str = server_port_str.split(':', 1)
            port = int(port_str)

            query_params = parse_qs(parsed_url.query)
            
            node_config = {
                'name': tag,
                'type': 'vless',
                'server': server,
                'port': port,
                'uuid': uuid,
                'network': query_params.get('type', ['tcp'])[0],
                'udp': True
            }

            if 'security' in query_params and query_params['security'][0] == 'tls':
                node_config['tls'] = True
                node_config['servername'] = query_params.get('sni', [server])[0]
                node_config['skip-cert-verify'] = query_params.get('allowInsecure', ['0'])[0] == '1' or \
                                                  query_params.get('skip-cert-verify', ['false'])[0].lower() == 'true'
                node_config['fingerprint'] = query_params.get('fp', [None])[0]

            if node_config['network'] == 'ws':
                node_config['ws-path'] = query_params.get('path', ['/'])[0]
                node_config['ws-headers'] = {'Host': query_params.get('host', [server])[0]}
            elif node_config['network'] == 'grpc':
                node_config['grpc-service-name'] = query_params.get('serviceName', [''])[0]
                node_config['grpc-enable-health-check'] = query_params.get('enableHealthCheck', ['false'])[0].lower() == 'true'

            return node_config

        elif node_url.startswith("vmess://"):
            # VMess 节点是 Base64 编码的 JSON
            try:
                decoded_str = base64.b64decode(node_url[8:] + '==').decode('utf-8') # + '==' 确保正确的填充
                vmess_data = json.loads(decoded_str)

                # 映射 VMess 字段到 Mihomo 格式
                node_config = {
                    'name': vmess_data.get('ps', tag),
                    'type': 'vmess',
                    'server': vmess_data['add'],
                    'port': int(vmess_data['port']),
                    'uuid': vmess_data['id'],
                    'alterId': int(vmess_data.get('aid', 0)),
                    'cipher': vmess_data.get('scy', 'auto'), # security
                    'network': vmess_data.get('net', 'tcp'),
                    'udp': True
                }

                if vmess_data.get('tls', '') == 'tls':
                    node_config['tls'] = True
                    node_config['servername'] = vmess_data.get('host', vmess_data['add'])
                    node_config['skip-cert-verify'] = vmess_data.get('allowInsecure', '0') == '1'
                    node_config['fingerprint'] = vmess_data.get('fp')

                if node_config['network'] == 'ws':
                    node_config['ws-path'] = vmess_data.get('path', '/')
                    node_config['ws-headers'] = {'Host': vmess_data.get('host', vmess_data['add'])}
                elif node_config['network'] == 'grpc':
                    node_config['grpc-service-name'] = vmess_data.get('serviceName', '')

                return node_config

            except Exception as e:
                print(f"VMess 解析失败 (URL: {node_url}): {e}")
                return None

        elif node_url.startswith("trojan://"):
            parsed_url = urlparse(node_url)
            password_host_port = parsed_url.netloc
            if '@' not in password_host_port:
                 raise ValueError("Trojan URL 格式错误: 缺少 @ 分隔符")
            password, server_port_str = password_host_port.split('@', 1)
            server, port_str = server_port_str.split(':', 1)
            port = int(port_str)

            query_params = parse_qs(parsed_url.query)

            node_config = {
                'name': tag,
                'type': 'trojan',
                'server': server,
                'port': port,
                'password': password,
                'udp': True
            }

            node_config['tls'] = True # Trojan 默认要求 TLS
            node_config['servername'] = query_params.get('sni', [server])[0] if 'sni' in query_params else server
            node_config['skip-cert-verify'] = query_params.get('allowInsecure', ['0'])[0] == '1' or \
                                              query_params.get('skip-cert-verify', ['false'])[0].lower() == 'true'

            return node_config

        elif node_url.startswith("hysteria2://"):
            # Hysteria2: hysteria2://password@server:port/?query_params#tag
            parsed_url = urlparse(node_url)
            password_host_port = parsed_url.netloc
            if '@' not in password_host_port:
                raise ValueError("Hysteria2 URL 格式错误: 缺少 @ 分隔符")
            password, server_port_str = password_host_port.split('@', 1)
            server, port_str = server_port_str.split(':', 1)
            port = int(port_str)

            query_params = parse_qs(parsed_url.query)

            node_config = {
                'name': tag,
                'type': 'hysteria2',
                'server': server,
                'port': port,
                'password': password,
                'udp': True,
                'obfs': query_params.get('obfs', [None])[0],
                'obfs-password': query_params.get('obfsParam', [None])[0],
                'up': int(query_params.get('up', [0])[0]), # 上行带宽
                'down': int(query_params.get('down', [0])[0]), # 下行带宽
                'auth': password # Hysteria2 的 password 也是 auth
            }
            # Hysteria2 默认加密，通常有 TLS
            node_config['tls'] = True
            node_config['servername'] = query_params.get('sni', [server])[0] if 'sni' in query_params else server
            node_config['skip-cert-verify'] = query_params.get('insecure', ['0'])[0] == '1' or \
                                              query_params.get('skip-cert-verify', ['false'])[0].lower() == 'true'

            return node_config

        else:
            print(f"警告: 未知或不支持的节点协议: {node_url}")
            return None

    except Exception as e:
        print(f"解析节点URL失败 (URL: {node_url}, 错误: {e})")
        return None

# --- 验证函数 (保持不变，但其作用会主要针对解析后的字典结构) ---
def validate_proxy(proxy: Dict, original_url: str, index: int) -> tuple[bool, str]:
    """验证代理节点格式，返回 (是否有效, 错误信息)"""
    required_fields = {
        'name': str,
        'server': str,
        'port': int,
        'type': str
    }
    protocol_specific_fields = {
        'trojan': [('password', str)],
        'vmess': [('uuid', str)],
        'vless': [('uuid', str)],
        'ss': [('cipher', str), ('password', str)],
        'hysteria2': [('password', str), ('auth', str)] # Hysteria2 特有的 auth 字段
    }

    # 检查必要字段
    for field, field_type in required_fields.items():
        if field not in proxy:
            return False, f"节点 {index} (URL: {original_url}) 缺少字段: {field}"
        if not isinstance(proxy[field], field_type):
            return False, f"节点 {index} (URL: {original_url}) 字段 {field} 类型错误，期望 {field_type.__name__}，实际 {type(proxy[field]).__name__}"

    # 检查协议特定字段
    proxy_type = proxy.get('type')
    if proxy_type in protocol_specific_fields:
        for field, field_type in protocol_specific_fields[proxy_type]:
            if field not in proxy:
                return False, f"节点 {index} ({proxy_type}, URL: {original_url}) 缺少字段: {field}"
            if not isinstance(proxy[field], field_type):
                return False, f"节点 {index} ({proxy_type}, URL: {original_url}) 字段 {field} 类型错误，期望 {field_type.__name__}，实际 {type(proxy[field]).__name__}"

    # 检查 name 唯一性（简单检查，实际应在全局验证）
    if not proxy['name'].strip():
        return False, f"节点 {index} (URL: {original_url}) name 为空"

    return True, ""

# --- 测试代理函数 (保持不变) ---
async def test_proxy(proxy: Dict, session: aiohttp.ClientSession, clash_bin: str, clash_port: int = 7890) -> Dict:
    """测试单个代理节点，返回结果"""
    proxy_name = proxy.get('name', 'unknown')
    # Store the original URL for better error reporting in the final output
    original_url = proxy.pop('original_url', 'N/A')
    print(f"测试代理节点: {proxy_name}")

    # 写入临时 Clash 配置文件
    config = {
        'port': clash_port,
        'socks-port': clash_port + 1,
        'mode': 'global',
        'proxies': [proxy],
        'proxy-groups': [{'name': 'auto', 'type': 'select', 'proxies': [proxy_name]}],
        'rules': ['MATCH,auto']
    }
    os.makedirs('temp', exist_ok=True)
    config_path = f'temp/config_{proxy_name}.yaml'
    try:
        with open(config_path, 'w') as f:
            yaml.dump(config, f, allow_unicode=True)
    except Exception as e:
        return {'name': proxy_name, 'status': '不可用', 'latency': None, 'error': f"写入配置失败: {str(e)}", 'original_url': original_url}

    # 启动 Clash
    proc = subprocess.Popen([clash_bin, '-f', config_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    await asyncio.sleep(2)  # 等待 Clash 启动

    result = {'name': proxy_name, 'status': '不可用', 'latency': None, 'error': None, 'original_url': original_url}
    try:
        start_time = time.time()
        # 测试 HTTP 代理
        async with session.get(
            'http://www.google.com',
            proxy=f'http://127.0.0.1:{clash_port}',
            timeout=5
        ) as response:
            if response.status == 200:
                result['status'] = '可用'
                result['latency'] = (time.time() - start_time) * 1000  # 毫秒
    except Exception:
        try:
            # 回退测试 SOCKS5 代理（适用于 trojan, hysteria2 等）
            async with session.get(
                'http://www.google.com',
                proxy=f'socks5://127.0.0.1:{clash_port + 1}',
                timeout=5
            ) as response:
                if response.status == 200:
                    result['status'] = '可用'
                    result['latency'] = (time.time() - start_time) * 1000  # 毫秒
        except Exception as e:
            result['error'] = f"测试失败: {str(e)}"
    finally:
        proc.terminate()
        try:
            os.remove(config_path)
        except:
            pass
    return result

# --- 主函数 (主要修改部分) ---
async def main():
    # 从 URL 下载节点列表
    node_list_url = 'https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt'
    raw_node_urls = []
    
    print(f"正在从 {node_list_url} 下载节点列表...")
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(node_list_url, timeout=10) as response:
                response.raise_for_status() # Raises an exception for HTTP errors (400 or 500)
                content = await response.text()
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'): # 忽略空行和以 # 开头的注释行
                        raw_node_urls.append(line)
            print("节点列表下载成功。")
        except aiohttp.ClientError as e:
            print(f"错误: 从 {node_list_url} 下载节点列表失败: {e}")
            sys.exit(1)
        except asyncio.TimeoutError:
            print(f"错误: 从 {node_list_url} 下载节点列表超时。")
            sys.exit(1)
        except Exception as e:
            print(f"未知错误: 下载节点列表时发生: {e}")
            sys.exit(1)

    if not raw_node_urls:
        print("未从 URL 读取到任何节点URL。")
        sys.exit(0)

    print(f"成功读取 {len(raw_node_urls)} 条节点URL。")

    # 解析并验证节点格式
    parsed_proxies = []
    invalid_node_urls = [] # 记录无法解析或验证失败的原始URL
    for i, url in enumerate(raw_node_urls):
        parsed_proxy = parse_node_url_to_mihomo_config(url)
        if parsed_proxy:
            # Add original_url to the proxy dict for better error reporting later
            parsed_proxy['original_url'] = url 
            is_valid, error = validate_proxy(parsed_proxy, url, i) # 传递原始URL以便调试
            if is_valid:
                parsed_proxies.append(parsed_proxy)
            else:
                invalid_node_urls.append({'url': url, 'error': error})
        else:
            invalid_node_urls.append({'url': url, 'error': "无法解析或不支持的节点URL格式"})

    # 记录解析或验证失败的节点
    if invalid_node_urls:
        os.makedirs('data', exist_ok=True) # 确保 data 目录存在
        with open('data/invalid_nodes.yaml', 'w', encoding='utf-8') as f:
            yaml.dump({'invalid_urls': invalid_node_urls}, f, allow_unicode=True, sort_keys=False)
        print(f"发现 {len(invalid_node_urls)} 个无法解析或无效的节点URL，详情见 data/invalid_nodes.yaml")

    if not parsed_proxies:
        print("没有可用于测试的有效代理节点。")
        sys.exit(0)

    # 创建输出文件
    os.makedirs('data', exist_ok=True)
    results_list = [] # 收集所有测试结果
    
    # 配置 aiohttp 会话 (再次创建，因为前面下载时已经关闭了)
    async with aiohttp.ClientSession() as session:
        # 分批并发测试
        batch_size = 50
        for i in range(0, len(parsed_proxies), batch_size):
            batch = parsed_proxies[i:i + batch_size]
            tasks = [test_proxy(proxy, session, './tools/clash') for proxy in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for result in results:
                if isinstance(result, dict):
                    results_list.append(result)
                    print(f"{result['name']}: {result['status']}{'，延迟: %.2fms' % result['latency'] if result['latency'] else ''} (URL: {result.get('original_url', 'N/A')})")
                else:
                    print(f"测试过程中发生未知错误: {result}")

    # 将所有测试结果写入 data/521.yaml
    final_successful_proxies = [res for res in results_list if res['status'] == '可用']
    
    try:
        with open('data/521.yaml', 'w', encoding='utf-8') as f:
            yaml.dump({'proxies': final_successful_proxies}, f, allow_unicode=True, sort_keys=False)
        print(f"已将 {len(final_successful_proxies)} 个可用节点写入 data/521.yaml")

    except Exception as e:
        print(f"写入 data/521.yaml 失败: {e}")
        sys.exit(1)

    print("测试完成。")

if __name__ == "__main__":
    asyncio.run(main())
