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
# 自定义 YAML 构造函数，处理 !<str> 标签
def str_constructor(loader, node):
    return str(node.value)

# 注册自定义构造函数
SafeLoader.add_constructor('!str', str_constructor)

# --- 节点解析函数 ---
def parse_node_url_to_mihomo_config(node_url: str) -> Dict | None:
    """
    解析节点URL，将其转换为Mihomo (Clash.Meta) 配置字典格式。
    支持 ss, vless, vmess, trojan, hysteria2, ssr。
    这是一个简化示例，实际解析需要更复杂的逻辑来处理不同协议和参数。
    """
    node_url = node_url.strip()
    if not node_url:
        return None

    # Handle completely malformed URLs that don't even look like a protocol
    if not re.match(r'^[a-zA-Z]+://', node_url):
        print(f"警告: 无法识别的URL格式 (非协议开头): {node_url}")
        return None

    # 统一处理标签，有些协议的标签在URL片段中
    tag = "Unnamed Node"
    # Find fragment (tag) and remove it temporarily for robust URL parsing
    url_parts_no_fragment = node_url.split('#', 1)
    if len(url_parts_no_fragment) == 2:
        tag = unquote(url_parts_no_fragment[1])
        node_url_clean = url_parts_no_fragment[0]
    else:
        node_url_clean = node_url

    try:
        parsed_url = urlparse(node_url_clean)
        scheme = parsed_url.scheme.lower()
        netloc = parsed_url.netloc
        query_params = parse_qs(parsed_url.query)

        # Common check for malformed netloc (e.g., trojan://://)
        if not netloc or netloc.startswith('//'):
            raise ValueError("URL netloc 格式错误或为空")

        if scheme == "ss":
            # Shadowsocks: ss://[cipher:password@]server:port[#tag] 或 ss://base64_encoded_info[#tag]
            # Prioritize base64 encoded SS
            if "@" not in netloc: # Possibly base64 encoded
                try:
                    # Remove ss:// and possible #tag, then base64 decode
                    encoded_part = node_url_clean[len("ss://"):]
                    # Base64 decode might fail if padding is incorrect. Add padding to be safe.
                    decoded_info = base64.urlsafe_b64decode(encoded_part + '==').decode('utf-8')
                    # Format might be method:password@server:port
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
                    pass # If not base64 encoded or parsing fails, try normal format

            # Normal format ss://cipher:password@server:port#tag
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
            uuid_host_port = netloc
            
            if '@' not in uuid_host_port:
                raise ValueError("VLESS URL 格式错误: 缺少 @ 分隔符")
            
            uuid, server_port_str = uuid_host_port.split('@', 1)

            server = None
            port = None
            if server_port_str.startswith('['): # Potential IPv6 address
                # Look for the closing bracket and then the port
                match_ipv6 = re.match(r'^\[([0-9a-fA-F:.]+)\]:(\d+)<span class="math-inline">', server\_port\_str\)
if match\_ipv6\:
server \= match\_ipv6\.group\(1\)
port \= int\(match\_ipv6\.group\(2\)\)
else\:
raise ValueError\(f"VLESS IPv6 地址格式错误或不完整 \(期望 \[ipv6\]\:port\)\: \{server\_port\_str\}"\)
else\: \# IPv4 address or domain
if '\:' not in server\_port\_str\:
raise ValueError\(f"VLESS IPv4/Domain 地址格式错误\: 缺少端口\: \{server\_port\_str\}"\)
server, port\_str \= server\_port\_str\.split\('\:', 1\)
port \= int\(port\_str\)
node\_config \= \{
'name'\: tag,
'type'\: 'vless',
'server'\: server,
'port'\: port,
'uuid'\: uuid,
'network'\: query\_params\.get\('type', \['tcp'\]\)\[0\],
'udp'\: True
\}
if 'security' in query\_params and query\_params\['security'\]\[0\] \=\= 'tls'\:
node\_config\['tls'\] \= True
node\_config\['servername'\] \= query\_params\.get\('sni', \[server\]\)\[0\]
node\_config\['skip\-cert\-verify'\] \= query\_params\.get\('allowInsecure', \['0'\]\)\[0\] \=\= '1' or \\
query\_params\.get\('skip\-cert\-verify', \['false'\]\)\[0\]\.lower\(\) \=\= 'true'
node\_config\['fingerprint'\] \= query\_params\.get\('fp', \[None\]\)\[0\]
if node\_config\['network'\] \=\= 'ws'\:
node\_config\['ws\-path'\] \= query\_params\.get\('path', \['/'\]\)\[0\]
node\_config\['ws\-headers'\] \= \{'Host'\: query\_params\.get\('host', \[server\]\)\[0\]\}
elif node\_config\['network'\] \=\= 'grpc'\:
node\_config\['grpc\-service\-name'\] \= query\_params\.get\('serviceName', \[''\]\)\[0\]
node\_config\['grpc\-enable\-health\-check'\] \= query\_params\.get\('enableHealthCheck', \['false'\]\)\[0\]\.lower\(\) \=\= 'true'
return node\_config
elif scheme \=\= "vmess"\:
\# VMess node is Base64 encoded JSON
try\:
\# Remove scheme and decode
decoded\_str \= base64\.b64decode\(node\_url\_clean\[len\("vmess\://"\)\:\] \+ '\=\='\)\.decode\('utf\-8'\) \# \+ '\=\=' for padding
vmess\_data \= json\.loads\(decoded\_str\)
\# Map VMess fields to Mihomo format
node\_config \= \{
'name'\: vmess\_data\.get\('ps', tag\),
'type'\: 'vmess',
'server'\: vmess\_data\['add'\],
'port'\: int\(vmess\_data\['port'\]\),
'uuid'\: vmess\_data\['id'\],
'alterId'\: int\(vmess\_data\.get\('aid', 0\)\),
'cipher'\: vmess\_data\.get\('scy', 'auto'\), \# security
'network'\: vmess\_data\.get\('net', 'tcp'\),
'udp'\: True
\}
if vmess\_data\.get\('tls', ''\) \=\= 'tls'\:
node\_config\['tls'\] \= True
node\_config\['servername'\] \= vmess\_data\.get\('host', vmess\_data\['add'\]\)
node\_config\['skip\-cert\-verify'\] \= vmess\_data\.get\('allowInsecure', '0'\) \=\= '1'
node\_config\['fingerprint'\] \= vmess\_data\.get\('fp'\)
if node\_config\['network'\] \=\= 'ws'\:
node\_config\['ws\-path'\] \= vmess\_data\.get\('path', '/'\)
node\_config\['ws\-headers'\] \= \{'Host'\: vmess\_data\.get\('host', vmess\_data\['add'\]\)\}
elif node\_config\['network'\] \=\= 'grpc'\:
node\_config\['grpc\-service\-name'\] \= vmess\_data\.get\('serviceName', ''\)
return node\_config
except Exception as e\:
print\(f"VMess 解析失败 \(URL\: \{node\_url\}\)\: \{e\}"\)
return None
elif scheme \=\= "trojan"\:
password\_host\_port \= netloc
if '@' not in password\_host\_port\:
raise ValueError\("Trojan URL 格式错误\: 缺少 @ 分隔符"\)
password, server\_port\_str \= password\_host\_port\.split\('@', 1\)
server \= None
port \= None
if server\_port\_str\.startswith\('\['\)\: \# Potential IPv6 address
match\_ipv6 \= re\.match\(r'^\\\[\(\[0\-9a\-fA\-F\:\.\]\+\)\\\]\:\(\\d\+\)</span>', server_port_str)
                if match_ipv6:
                    server = match_ipv6.group(1)
                    port = int(match_ipv6.group(2))
                else:
                    raise ValueError(f"Trojan IPv6 地址格式错误或不完整 (期望 [ipv6]:port): {server_port_str}")
            else: # IPv4 address or domain
                if ':' not in server_port_str:
                    raise ValueError(f"Trojan IPv4/Domain 地址格式错误: 缺少端口: {server_port_str}")
                server, port_str = server_port_str.split(':', 1)
                port = int(port_str)

            node_config = {
                'name': tag,
                'type': 'trojan',
                'server': server,
                'port': port,
                'password': password,
                'udp': True
            }

            node_config['tls'] = True # Trojan defaults to TLS
            node_config['servername'] = query_params.get('sni', [server])[0] if 'sni' in query_params else server
            node_config['skip-cert-verify'] = query_params.get('allowInsecure', ['0'])[0] == '1' or \
                                              query_params.get('skip-cert-verify', ['false'])[0].lower() == 'true'

            return node_config

        elif scheme == "hysteria2":
            # Hysteria2: hysteria2://password@server:port/?query_params#tag
            password_host_port = netloc
            
            if '@' not in password_host_port:
                raise ValueError("Hysteria2 URL 格式错误: 缺少 @ 分隔符")
            
            password, server_port_str = password_host_port.split('@', 1)

            server = None
            port = None
            if server_port_str.startswith('['): # Potential IPv6 address
                match_ipv6 = re.match(r'^\[([0-9a-fA-F:.]+)\]:(\d+)$', server_port_str)
                if match_ipv6:
                    server = match_ipv6.group(1)
                    port = int(match_ipv6.group(2))
                else:
                    raise ValueError(f"Hysteria2 IPv6 地址格式错误或不完整 (期望 [ipv6]:port): {server_port_str}")
            else: # IPv4 address or domain
                if ':' not in server_port_str:
                    raise ValueError(f"Hysteria2 IPv4/Domain 地址格式错误: 缺少端口: {server_port_str}")
                server, port_str = server_port_str.split(':', 1)
                port = int(port_str)

            node_config = {
                'name': tag,
                'type': 'hysteria2',
                'server': server,
                'port': port,
                'password': password,
                'udp': True,
                'obfs': query_params.get('obfs', [None])[0],
                'obfs-password': query_params.get('obfsParam', [None])[0],
                'up': int(query_params.get('up', ['0'])[0]), # Upstream bandwidth
                'down': int(query_params.get('down', ['0'])[0]), # Downstream bandwidth
                'auth': password # Hysteria2's password is also used as auth
            }
            # Hysteria2 default encryption, usually with TLS
            node_config['tls'] = True
            node_config['servername'] = query_params.get('sni', [server])[0] if 'sni' in query_params else server
            node_config['skip-cert-verify'] = query_params.get('insecure', ['0'])[0] == '1' or \
                                              query_params.get('skip-cert-verify', ['false'])[0].lower() == 'true'

            return node_config

        elif scheme == "ssr":
            # SSR protocol parsing
            try:
                # SSR link is ssr://base64_encoded_params
                encoded_params = node_url_clean[len("ssr://"):]
                # SSR's base64 encoding is usually URL safe base64, without padding. Add padding to be safe.
                decoded_params = base64.urlsafe_b64decode(encoded_params + '==').decode('utf-8')

                # Format: server:port:protocol:method:obfs:password_base64/?params
                parts = decoded_params.split(':')
                if len(parts) < 6:
                    raise ValueError("SSR URL 基础格式错误: 部分不足6个")

                server = parts[0]
                port = int(parts[1])
                protocol = parts[2]
                method = parts[3]
                obfs = parts[4]
                
                # password is base64 encoded
                password_base64_part = parts[5]
                # Check if password_base64_part contains /
                if '/' in password_base64_part:
                    password_base64, query_string_with_fragment = password_base64_part.split('/', 1)
                    # Process query string and fragment
                    query_params = parse_qs(query_string_with_fragment.split('#')[0])
                else:
                    password_base64 = password_base64_part
                    query_params = {}

                password = unquote(base64.urlsafe_b64decode(password_base64 + '==').decode('utf-8'))

                # Mihomo's SSR configuration
                ssr_config = {
                    'name': tag,
                    'type': 'ssr',
                    'server': server,
                    'port': port,
                    'cipher': method,
                    'password': password,
                    'protocol': protocol,
                    'obfs': obfs,
                    'udp': True
                }

                # Handle obfsparam and protoparam
                if 'obfsparam' in query_params:
                    # obfsparam is usually also base64 encoded
                    ssr_config['obfs-param'] = unquote(base64.urlsafe_b64decode(query_params['obfsparam'][0] + '==').decode('utf-8'))
                if 'protoparam' in query_params:
                    # protoparam is usually also base64 encoded
                    ssr_config['protocol-param'] = unquote(base64.urlsafe_b64decode(query_params['protoparam'][0] + '==').decode('utf-8'))
                
                return ssr_config

            except Exception as e:
                print(f"SSR 解析失败 (URL: {node_url}): {e}")
                return None
        else:
            print(f"警告: 未知或不支持的节点协议: {node_url}")
            return None

    except Exception as e:
        print(f"解析节点URL失败 (URL: {node_url}, 错误: {e})")
        return None

# --- Validation function (kept unchanged, but its role will primarily be for the parsed dictionary structure) ---
def validate_proxy(proxy: Dict, original_url: str, index: int) -> tuple[bool, str]:
    """Validate proxy node format, returns (is_valid, error_message)"""
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
        'hysteria2': [('password', str), ('auth', str)], # Hysteria2 specific auth field
        'ssr': [('cipher', str), ('password', str), ('protocol', str), ('obfs', str)] # SSR fields
    }

    # Check required fields
    for field, field_type in required_fields.items():
        if field not in proxy:
            return False, f"节点 {index} (URL: {original_url}) 缺少字段: {field}"
        if not isinstance(proxy[field], field_type):
            return False, f"节点 {index} (URL: {original_url}) 字段 {field} 类型错误，期望 {field_type.__name__}，实际 {type(proxy[field]).__name__}"

    # Check protocol-specific fields
    proxy_type = proxy.get('type')
    if proxy_type in protocol_specific_fields:
        for field, field_type in protocol_specific_fields[proxy_type]:
            if field not in proxy:
                return False, f"节点 {index} ({proxy_type}, URL: {original_url}) 缺少字段: {field}"
            if not isinstance(proxy[field], field_type):
                return False, f"节点 {index} ({proxy_type}, URL: {original_url}) 字段 {field} 类型错误，期望 {field_type.__name__}，实际 {type(proxy[field]).__name__}"

    # Check name uniqueness (simple check, should ideally be global validation)
    if not proxy['name'].strip():
        return False, f"节点 {index} (URL: {original_url}) name 为空"

    return True, ""

# --- Test proxy function (kept unchanged) ---
async def test_proxy(proxy: Dict, session: aiohttp.ClientSession, clash_bin: str, clash_port: int = 7890) -> Dict:
    """Test a single proxy node, return result"""
    proxy_name = proxy.get('name', 'unknown')
    # print(f"测试代理节点: {proxy_name}") # Suppress for cleaner output during large runs

    # Write temporary Clash configuration file
    config = {
        'port': clash_port,
        'socks-port': clash_port + 1,
        'mode': 'global',
        'proxies': [proxy],
        'proxy-groups': [{'name': 'auto', 'type': 'select', 'proxies': [proxy_name]}],
        'rules': ['MATCH,auto']
    }
    os.makedirs('temp', exist_ok=True)
    # Clean name for filename, limit length for filenames
    clean_proxy_name = re.sub(r'[^\w.-]', '_', proxy_name)[:100]
    config_path = f'temp/config_{clean_proxy_name}.yaml'
    try:
        with open(config_path, 'w') as f:
            yaml.dump(config, f, allow_unicode=True)
    except Exception as e:
        return {'name': proxy_name, 'status': '不可用', 'latency': None, 'error': f"写入配置失败: {str(e)}", 'original_url': proxy.get('original_url', 'N/A')}

    # Start Clash
    proc = subprocess.Popen([clash_bin, '-f', config_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
    # Use preexec_fn=os.setsid to create a new session, preventing child process from receiving signals from parent
    await asyncio.sleep(2)  # Wait for Clash to start

    result = {'name': proxy_name, 'status': '不可用', 'latency': None, 'error': None, 'original_url': proxy.get('original_url', 'N/A')}
    try:
        start_time = time.time()
        # Test HTTP proxy
        async with session.get(
            'http://www.google.com', # Use a reliable public endpoint
            proxy=f'http://127.0.0.1:{clash_port}',
            timeout=5
        ) as response:
            if response.status == 200:
                result['status'] = '可用'
                result['latency'] = (time.time() - start_time) * 1000  # milliseconds
    except Exception:
        try:
            # Fallback to test SOCKS5 proxy (for trojan, hysteria2, etc.)
            async with session.get(
                'http://www.google.com', # Use a reliable public endpoint
                proxy=f'socks5://127.0.0.1:{clash_port + 1}',
                timeout=5
            ) as response:
                if response.status == 200:
                    result['status'] = '可用'
                    result['latency'] = (time.time() - start_time) * 1000  # milliseconds
        except Exception as e:
            result['error'] = f"测试失败: {str(e)}"
    finally:
        # Terminate the process group to ensure all child processes are killed
        if proc.poll() is None: # Check if process is still running
            try:
                os.killpg(os.getpgid(proc.pid), subprocess.SIGNAL.SIGTERM)
                # print(f"Terminated Clash process group for {proxy_name}")
            except OSError as e:
                # print(f"Error terminating process group for {proxy_name}: {e}")
                pass
        
        try:
            os.remove(config_path)
        except OSError as e:
            # print(f"Error removing config file {config_path}: {e}")
            pass
    return result

# --- Main function ---
async def main():
    # Download node list from URL
    nodes_url = "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
    raw_node_urls = []

    async with aiohttp.ClientSession() as session:
        try:
            print(f"尝试从 URL 下载节点列表: {nodes_url}")
            async with session.get(nodes_url, timeout=10) as response:
                response.raise_for_status() # Raises an HTTPError for bad responses (4xx or 5xx)
                content = await response.text(encoding='utf-8')
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'): # Ignore empty lines and lines starting with #
                        raw_node_urls.append(line)
            print(f"成功从 URL 下载 {len(raw_node_urls)} 条节点URL。")
        except aiohttp.ClientError as e:
            print(f"错误: 从 URL 下载节点列表失败 ({nodes_url}): {e}")
            sys.exit(1)
        except Exception as e:
            print(f"发生未知错误: {e}")
            sys.exit(1)

    if not raw_node_urls:
        print("未从 URL 读取到任何节点URL。")
        sys.exit(0)

    # Parse and validate node format
    parsed_proxies = []
    invalid_node_urls = [] # Record original URLs that failed to parse or validate
    for i, url in enumerate(raw_node_urls):
        parsed_proxy = parse_node_url_to_mihomo_config(url)
        if parsed_proxy:
            # Add original URL to proxy dictionary for tracking in test results
            parsed_proxy['original_url'] = url
            is_valid, error = validate_proxy(parsed_proxy, url, i) # Pass original URL for debugging
            if is_valid:
                parsed_proxies.append(parsed_proxy)
            else:
                invalid_node_urls.append({'url': url, 'error': error})
        else:
            invalid_node_urls.append({'url': url, 'error': "无法解析或不支持的节点URL格式"})

    # Record nodes that failed to parse or validate
    if invalid_node_urls:
        os.makedirs('data', exist_ok=True) # Ensure data directory exists
        with open('data/invalid_nodes.yaml', 'w', encoding='utf-8') as f:
            yaml.dump({'invalid_urls': invalid_node_urls}, f, allow_unicode=True, sort_keys=False)
        print(f"发现 {len(invalid_node_urls)} 个无法解析或无效的节点URL，详情见 data/invalid_nodes.yaml")

    if not parsed_proxies:
        print("没有可用于测试的有效代理节点。")
        sys.exit(0)

    # Create output file
    os.makedirs('data', exist_ok=True)
    results_list = [] # Collect all test results
    
    # Batch and concurrently test
    batch_size = 50
    for i in range(0, len(parsed_proxies), batch_size):
        batch = parsed_proxies[i:i + batch_size]
        tasks = [test_proxy(proxy, session, './tools/clash') for proxy in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, dict):
                results_list.append(result)
                # Print original URL for tracking
                original_url_in_result = result.get('original_url', 'N/A')
                print(f"{result['name']}: {result['status']}{'，延迟: %.2fms' % result['latency'] if result['latency'] else ''} (原始URL: {original_url_in_result})")
            else:
                print(f"测试过程中发生未知错误: {result}")

    # Write all test results to data/521.yaml
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
