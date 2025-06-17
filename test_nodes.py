import asyncio
import aiohttp
import yaml
import os
import subprocess
import sys
import time
import re
import base64
import json
import socket
import logging
from typing import Dict, List
from yaml import SafeLoader
from urllib.parse import urlparse, unquote, parse_qs

# --- 日志配置 ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('test_nodes.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# --- YAML 相关配置 ---
def str_constructor(loader, node):
    return str(node.value)

SafeLoader.add_constructor('!str', str_constructor)

# --- 端口检查 ---
def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

# --- 节点解析函数 ---
def parse_node_url_to_mihomo_config(node_url: str) -> Dict | None:
    node_url = node_url.strip()
    if not node_url:
        return None

    # 清理不可见字符并处理编码问题
    node_url = node_url.encode('utf-8', errors='ignore').decode('utf-8', errors='ignore').strip()
    node_url = ''.join(char for char in node_url if ord(char) >= 32 or char == '/').strip()

    # 清理多余的 ://（如 trojan://://）
    node_url = re.sub(r'([a-zA-Z0-9]+):/+', r'\1://', node_url)

    # 检查协议格式，允许包含数字的协议（如 hysteria2）
    if not re.match(r'^[a-zA-Z0-9]+://', node_url):
        logging.warning(f"无法识别的URL格式 (非协议开头): {node_url}")
        return None

    # 处理标签（URL 片段）
    tag = "Unnamed Node"
    url_parts = node_url.split('#', 1)
    node_url_clean = url_parts[0]
    if len(url_parts) > 1:
        tag = unquote(url_parts[1])

    try:
        parsed_url = urlparse(node_url_clean)
        scheme = parsed_url.scheme.lower()
        netloc = parsed_url.netloc
        query_params = parse_qs(parsed_url.query)

        if not netloc or netloc.startswith('//'):
            raise ValueError("URL netloc 格式错误或为空")

        if scheme == "ss":
            if "@" not in netloc:
                try:
                    encoded_part = node_url_clean[len("ss://"):]
                    decoded_info = base64.urlsafe_b64decode(encoded_part + '==').decode('utf-8')
                    cipher_password, address_port = decoded_info.split('@')
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
                    pass

            match = re.match(r'([^:]+):([^@]+)@([^:]+):(\d+)', netloc)
            if match:
                cipher, password, server, port = match.groups()
                return {
                    'name': tag,
                    'type': 'ss',
                    'server': server,
                    'port': int(port),
                    'cipher': cipher,
                    'password': password,
                    'udp': True
                }

        elif scheme == "vless":
            if '@' not in netloc:
                raise ValueError("VLESS URL 格式错误: 缺少 @ 分隔符")
            uuid, server_port_str = netloc.split('@', 1)

            server, port = None, None
            if server_port_str.startswith('['):
                match_ipv6 = re.match(r'^\[([0-9a-fA-F:.]+)\](?::(\d+))?$', server_port_str)
                if match_ipv6:
                    server, port = match_ipv6.groups()
                    port = int(port) if port else 443
                else:
                    raise ValueError(f"VLESS IPv6 地址格式错误: {server_port_str}")
            else:
                if ':' not in server_port_str:
                    raise ValueError(f"VLESS 地址格式错误: 缺少端口: {server_port_str}")
                server, port = server_port_str.split(':', 1)
                port = int(port)

            node_config = {
                'name': tag,
                'type': 'vless',
                'server': server,
                'port': port,
                'uuid': uuid,
                'network': query_params.get('type', ['tcp'])[0],
                'udp': True
            }

            if query_params.get('security', [''])[0] == 'tls':
                node_config.update({
                    'tls': True,
                    'servername': query_params.get('sni', [server])[0],
                    'skip-cert-verify': query_params.get('allowInsecure', ['0'])[0] == '1' or
                                        query_params.get('skip-cert-verify', ['false'])[0].lower() == 'true',
                    'fingerprint': query_params.get('fp', [None])[0]
                })

            if node_config['network'] == 'ws':
                node_config.update({
                    'ws-path': query_params.get('path', ['/'])[0],
                    'ws-headers': {'Host': query_params.get('host', [server])[0]}
                })
            elif node_config['network'] == 'grpc':
                node_config.update({
                    'grpc-service-name': query_params.get('serviceName', [''])[0],
                    'grpc-enable-health-check': query_params.get('enableHealthCheck', ['false'])[0].lower() == 'true'
                })

            return node_config

        elif scheme == "vmess":
            try:
                decoded_str = base64.b64decode(node_url_clean[len("vmess://"):] + '==', validate=False).decode('utf-8', errors='ignore')
                vmess_data = json.loads(decoded_str)
                node_config = {
                    'name': vmess_data.get('ps', tag),
                    'type': 'vmess',
                    'server': vmess_data['add'],
                    'port': int(vmess_data['port']),
                    'uuid': vmess_data['id'],
                    'alterId': int(vmess_data.get('aid', 0)),
                    'cipher': vmess_data.get('scy', 'auto'),
                    'network': vmess_data.get('net', 'tcp'),
                    'udp': True
                }

                if vmess_data.get('tls', '') == 'tls':
                    node_config.update({
                        'tls': True,
                        'servername': vmess_data.get('host', vmess_data['add']),
                        'skip-cert-verify': vmess_data.get('allowInsecure', '0') == '1',
                        'fingerprint': vmess_data.get('fp')
                    })

                if node_config['network'] == 'ws':
                    node_config.update({
                        'ws-path': vmess_data.get('path', '/'),
                        'ws-headers': {'Host': vmess_data.get('host', vmess_data['add'])}
                    })
                elif node_config['network'] == 'grpc':
                    node_config['grpc-service-name'] = vmess_data.get('serviceName', '')

                return node_config
            except Exception as e:
                logging.warning(f"VMess 解析失败 (URL: {node_url}): {e}")
                return None

        elif scheme == "trojan":
            if '@' not in netloc:
                raise ValueError("Trojan URL 格式错误: 缺少 @ 分隔符")
            password, server_port_str = netloc.split('@', 1)

            server, port = None, None
            if server_port_str.startswith('['):
                match_ipv6 = re.match(r'^\[([0-9a-fA-F:.]+)\](?::(\d+))?$', server_port_str)
                if match_ipv6:
                    server, port = match_ipv6.groups()
                    port = int(port) if port else 443
                else:
                    raise ValueError(f"Trojan IPv6 地址格式错误: {server_port_str}")
            else:
                if ':' not in server_port_str:
                    raise ValueError(f"Trojan 地址格式错误: 缺少端口: {server_port_str}")
                server, port = server_port_str.split(':', 1)
                port = int(port)

            node_config = {
                'name': tag,
                'type': 'trojan',
                'server': server,
                'port': port,
                'password': password,
                'udp': True,
                'tls': True,
                'servername': query_params.get('sni', [server])[0],
                'skip-cert-verify': query_params.get('allowInsecure', ['0'])[0] == '1' or
                                    query_params.get('skip-cert-verify', ['false'])[0].lower() == 'true'
            }
            return node_config

        elif scheme == "hysteria2":
            if '@' not in netloc:
                raise ValueError("Hysteria2 URL 格式错误: 缺少 @ 分隔符")
            password, server_port_str = netloc.split('@', 1)

            server, port = None, None
            if server_port_str.startswith('['):
                match_ipv6 = re.match(r'^\[([0-9a-fA-F:.]+)\](?::(\d+))?$', server_port_str)
                if match_ipv6:
                    server, port = match_ipv6.groups()
                    port = int(port) if port else 443
                else:
                    raise ValueError(f"Hysteria2 IPv6 地址格式错误: {server_port_str}")
            else:
                if ':' not in server_port_str:
                    raise ValueError(f"Hysteria2 地址格式错误: 缺少端口: {server_port_str}")
                server, port = server_port_str.split(':', 1)
                port = int(port)

            node_config = {
                'name': tag,
                'type': 'hysteria2',
                'server': server,
                'port': port,
                'password': password,
                'udp': True,
                'obfs': query_params.get('obfs', [None])[0],
                'obfs-password': query_params.get('obfsParam', [None])[0],
                'up': int(query_params.get('up', ['0'])[0]),
                'down': int(query_params.get('down', ['0'])[0]),
                'auth': password,
                'tls': True,
                'servername': query_params.get('sni', [server])[0],
                'skip-cert-verify': query_params.get('insecure', ['0'])[0] == '1' or
                                    query_params.get('skip-cert-verify', ['false'])[0].lower() == 'true'
            }
            return node_config

        elif scheme == "ssr":
            try:
                encoded_params = node_url_clean[len("ssr://"):]
                decoded_params = base64.urlsafe_b64decode(encoded_params + '==').decode('utf-8')
                parts = decoded_params.split(':')
                if len(parts) < 6:
                    raise ValueError("SSR URL 基础格式错误: 部分不足6个")

                server, port, protocol, method, obfs, password_base64 = parts
                password_base64, query_string = password_base64.split('/', 1) if '/' in password_base64 else (password_base64, '')
                query_params = parse_qs(query_string.split('#')[0]) if query_string else {}
                password = unquote(base64.urlsafe_b64decode(password_base64 + '==').decode('utf-8'))

                ssr_config = {
                    'name': tag,
                    'type': 'ssr',
                    'server': server,
                    'port': int(port),
                    'cipher': method,
                    'password': password,
                    'protocol': protocol,
                    'obfs': obfs,
                    'udp': True
                }

                if 'obfsparam' in query_params:
                    ssr_config['obfs-param'] = unquote(base64.urlsafe_b64decode(query_params['obfsparam'][0] + '==').decode('utf-8'))
                if 'protoparam' in query_params:
                    ssr_config['protocol-param'] = unquote(base64.urlsafe_b64decode(query_params['protoparam'][0] + '==').decode('utf-8'))

                return ssr_config
            except Exception as e:
                logging.warning(f"SSR 解析失败 (URL: {node_url}): {e}")
                return None

        else:
            logging.warning(f"未知或不支持的节点协议: {scheme} ({node_url})")
            return None

    except Exception as e:
        logging.warning(f"解析节点URL失败 (URL: {node_url}, 错误: {e})")
        return None

# --- 验证函数 ---
def validate_proxy(proxy: Dict, original_url: str, index: int) -> tuple[bool, str]:
    required_fields = {'name': str, 'server': str, 'port': int, 'type': str}
    protocol_specific_fields = {
        'trojan': [('password', str)],
        'vmess': [('uuid', str)],
        'vless': [('uuid', str)],
        'ss': [('cipher', str), ('password', str)],
        'hysteria2': [('password', str), ('auth', str)],
        'ssr': [('cipher', str), ('password', str), ('protocol', str), ('obfs', str)]
    }

    for field, field_type in required_fields.items():
        if field not in proxy:
            return False, f"节点 {index} (URL: {original_url}) 缺少字段: {field}"
        if not isinstance(proxy[field], field_type):
            return False, f"节点 {index} (URL: {original_url}) 字段 {field} 类型错误，期望 {field_type.__name__}，实际 {type(proxy[field]).__name__}"

    proxy_type = proxy.get('type')
    if proxy_type in protocol_specific_fields:
        for field, field_type in protocol_specific_fields[proxy_type]:
            if field not in proxy:
                return False, f"节点 {index} ({proxy_type}, URL: {original_url}) 缺少字段: {field}"
            if not isinstance(proxy[field], field_type):
                return False, f"节点 {index} ({proxy_type}, URL: {original_url}) 字段 {field} 类型错误，期望 {field_type.__name__}，实际 {type(proxy[field]).__name__}"

    if not proxy['name'].strip():
        return False, f"节点 {index} (URL: {original_url}) name 为空"

    return True, ""

# --- 测试代理函数 ---
async def test_proxy(proxy: Dict, session: aiohttp.ClientSession, clash_bin: str, clash_port: int = 7890) -> Dict:
    proxy_name = proxy.get('name', 'unknown')
    if is_port_in_use(clash_port) or is_port_in_use(clash_port + 1):
        return {'name': proxy_name, 'status': '不可用', 'latency': None, 'error': f"端口 {clash_port} 或 {clash_port + 1} 被占用", 'original_url': proxy.get('original_url', 'N/A')}

    config = {
        'port': clash_port,
        'socks-port': clash_port + 1,
        'mode': 'global',
        'proxies': [proxy],
        'proxy-groups': [{'name': 'auto', 'type': 'select', 'proxies': [proxy_name]}],
        'rules': ['MATCH,auto']
    }

    os.makedirs('temp', exist_ok=True)
    clean_proxy_name = re.sub(r'[^\w.-]', '_', proxy_name)[:100]
    config_path = f'temp/config_{clean_proxy_name}.yaml'

    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True)
    except Exception as e:
        return {'name': proxy_name, 'status': '不可用', 'latency': None, 'error': f"写入配置失败: {str(e)}", 'original_url': proxy.get('original_url', 'N/A')}

    proc = subprocess.Popen([clash_bin, '-f', config_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
    await asyncio.sleep(2)

    result = {'name': proxy_name, 'status': '不可用', 'latency': None, 'error': None, 'original_url': proxy.get('original_url', 'N/A')}
    try:
        start_time = time.time()
        async with session.get(
            'http://ipinfo.io',
            proxy=f'http://127.0.0.1:{clash_port}',
            timeout=5
        ) as response:
            if response.status == 200:
                result['status'] = '可用'
                result['latency'] = (time.time() - start_time) * 1000
    except Exception:
        try:
            async with session.get(
                'http://ipinfo.io',
                proxy=f'socks5://127.0.0.1:{clash_port + 1}',
                timeout=5
            ) as response:
                if response.status == 200:
                    result['status'] = '可用'
                    result['latency'] = (time.time() - start_time) * 1000
        except Exception as e:
            result['error'] = f"测试失败: {str(e)}"
    finally:
        if proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), subprocess.signal.SIGTERM)
                proc.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                os.killpg(os.getpgid(proc.pid), subprocess.signal.SIGKILL)
        if os.path.exists(config_path):
            try:
                os.remove(config_path)
            except OSError as e:
                logging.warning(f"删除临时文件 {config_path} 失败: {e}")
    return result

# --- 主函数 ---
async def main():
    nodes_url = "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
    raw_node_urls = []

    async with aiohttp.ClientSession() as session:
        try:
            logging.info(f"尝试从 URL 下载节点列表: {nodes_url}")
            async with session.get(nodes_url, timeout=10) as response:
                response.raise_for_status()
                content = await response.text(encoding='utf-8')
                raw_node_urls = [line.strip() for line in content.splitlines() if line.strip() and not line.startswith('#')]
                raw_node_urls = [
                    line for line in raw_node_urls
                    if re.match(r'^[a-zA-Z0-9]+://[^\s]+$', line) and len(line) < 2048
                ]
            logging.info(f"过滤后剩余 {len(raw_node_urls)} 条节点URL。")
        except aiohttp.ClientError as e:
            logging.error(f"从 URL 下载节点列表失败 ({nodes_url}): {e}")
            sys.exit(1)
        except Exception as e:
            logging.error(f"发生未知错误: {e}")
            sys.exit(1)

    if not raw_node_urls:
        logging.info("未从 URL 读取到任何节点URL。")
        sys.exit(0)

    parsed_proxies = []
    invalid_node_urls = []
    for i, url in enumerate(raw_node_urls):
        parsed_proxy = parse_node_url_to_mihomo_config(url)
        if parsed_proxy:
            parsed_proxy['original_url'] = url
            is_valid, error = validate_proxy(parsed_proxy, url, i)
            if is_valid:
                parsed_proxies.append(parsed_proxy)
            else:
                invalid_node_urls.append({'url': url, 'error': error})
        else:
            invalid_node_urls.append({'url': url, 'error': "无法解析或不支持的节点URL格式"})

    # 去重
    unique_proxies = []
    seen = set()
    for proxy in parsed_proxies:
        key = (proxy['server'], proxy['port'])
        if key not in seen:
            seen.add(key)
            unique_proxies.append(proxy)
    parsed_proxies = unique_proxies
    logging.info(f"去重后剩余 {len(parsed_proxies)} 个代理节点。")

    if invalid_node_urls:
        os.makedirs('data', exist_ok=True)
        with open('data/invalid_nodes.yaml', 'w', encoding='utf-8') as f:
            yaml.dump({'invalid_urls': invalid_node_urls}, f, allow_unicode=True, sort_keys=False)
        logging.info(f"发现 {len(invalid_node_urls)} 个无法解析或无效的节点URL，详情见 data/invalid_nodes.yaml")

    if not parsed_proxies:
        logging.info("没有可用于测试的有效代理节点。")
        sys.exit(0)

    os.makedirs('data', exist_ok=True)
    results_list = []
    semaphore = asyncio.Semaphore(5)
    batch_size = 5

    async def test_proxy_with_semaphore(proxy, session, clash_bin, semaphore):
        async with semaphore:
            return await test_proxy(proxy, session, clash_bin)

    for i in range(0, len(parsed_proxies), batch_size):
        batch = parsed_proxies[i:i + batch_size]
        tasks = [test_proxy_with_semaphore(proxy, session, './tools/clash', semaphore) for proxy in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict):
                results_list.append(result)
                logging.info(f"{result['name']}: {result['status']}{'，延迟: %.2fms' % result['latency'] if result['latency'] else ''} (原始URL: {result['original_url']})")
            else:
                logging.error(f"测试过程中发生未知错误: {result}")

    final_successful_proxies = [res for res in results_list if res['status'] == '可用']
    try:
        with open('data/521.yaml', 'w', encoding='utf-8') as f:
            yaml.dump({'proxies': final_successful_proxies}, f, allow_unicode=True, sort_keys=False)
        logging.info(f"已将 {len(final_successful_proxies)} 个可用节点写入 data/521.yaml")
    except Exception as e:
        logging.error(f"写入 data/521.yaml 失败: {e}")
        sys.exit(1)

    logging.info("测试完成。")

if __name__ == "__main__":
    asyncio.run(main())
