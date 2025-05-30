import aiohttp
import asyncio
import os
import re
import base64
import yaml
import json
import time
from urllib.parse import quote, urlencode
from datetime import datetime, timezone # Keep timezone here for clarity, though datetime.timezone.utc is used

# 环境变量
GITHUB_TOKEN = os.getenv("BOT")
TEST_ENABLED = os.getenv("TEST_NODES", "true").lower() == "true"
TEST_MAX_NODES = int(os.getenv("TEST_MAX_NODES", 50))
TEST_TIMEOUT = float(os.getenv("TEST_TIMEOUT", 5))

# 文件路径
input_file = "data/hy2.txt"
invalid_urls_file = "data/invalid_urls.txt"
protocol_output_file = "data/protocol_nodes.txt"
yaml_output_file = "data/yaml_nodes.yaml"
debug_log_file = "data/extract_debug.log"
temp_nodes_file = "data/temp_nodes.txt"

os.makedirs("data", exist_ok=True)

protocol_nodes = []
yaml_nodes = []
debug_logs = []
url_node_map = {}

def load_invalid_urls():
    invalid_urls = set()
    try:
        with open(invalid_urls_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    invalid_urls.add(line.split("|")[0].strip())
        debug_logs.append(f"加载 {len(invalid_urls)} 个无效 URL")
        debug_logs.append(f"无效 URL 列表: {invalid_urls}")
    except FileNotFoundError:
        debug_logs.append(f"{invalid_urls_file} 未找到，将创建新文件")
    return invalid_urls

async def test_node_async(node, timeout=TEST_TIMEOUT):
    server, port = parse_node(node)
    if not server or not port:
        debug_logs.append(f"节点 {node[:50]}... 无效服务器或端口")
        return False
    uuid_pattern = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
    if node.startswith('vless://') and not uuid_pattern.search(node):
        debug_logs.append(f"节点 {node[:50]}... 无效 UUID")
        return False
    try:
        async with aiohttp.ClientSession() as session:
            # For testing, we often don't need to hit the actual server for all protocols.
            # A simple connection attempt or a mock HTTP request might be sufficient.
            # Given the original code's intent, it's trying to hit the server directly.
            # This might not work for all proxy types (e.g., SS, Trojan, VLESS) as they
            # are not standard HTTP servers.
            # For a more robust test, you'd need to implement protocol-specific checks.
            # For now, I'll keep the original HTTP GET attempt, but be aware of its limitations.
            url = f"http://{server}:{port}"
            async with session.get(url, timeout=timeout) as response:
                if response.status in [200, 404, 403]: # 404/403 might indicate a server is alive but not serving HTTP
                    debug_logs.append(f"节点 {server}:{port} 测试成功 (HTTP {response.status})")
                    return True
                debug_logs.append(f"节点 {server}:{port} 测试失败: HTTP {response.status}")
    except Exception as e:
        debug_logs.append(f"节点 {server}:{port} 测试失败: {e}")
    return False

def parse_node(node):
    try:
        if node.startswith(("ss://", "hysteria2://", "trojan://", "vless://")):
            # Updated regex to correctly capture server and port for various protocols
            # It handles cases with or without userinfo (e.g., password@server:port)
            match = re.match(r'^(?:ss|hysteria2|trojan|vless)://(?:[^@]+@)?([^:]+):(\d+)', node)
            if match:
                return match.group(1), match.group(2)
        elif node.startswith("vmess://"):
            decoded = base64.b64decode(node[8:]).decode('utf-8')
            config = json.loads(decoded)
            return config.get('add'), config.get('port')
    except Exception as e:
        debug_logs.append(f"解析节点失败: {node[:50]}... ({e})")
    return None, None

headers = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "Mozilla/5.0 (compatible; NodeExtractor/1.0)"
}
if GITHUB_TOKEN:
    headers["Authorization"] = f"token {GITHUB_TOKEN}"
else:
    debug_logs.append("警告：未找到 BOT 环境变量")

async def check_rate_limit(session):
    try:
        async with session.get("https://api.github.com/rate_limit", headers=headers) as response:
            response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
            rate_limit = await response.json()
            debug_logs.append(f"速率限制: {rate_limit['rate']['remaining']} 剩余")
    except Exception as e:
        debug_logs.append(f"检查速率限制失败: {e}")

protocol_pattern = re.compile(r'(ss|hysteria2|vless|vmess|trojan)://[^\s<>\'"]+', re.MULTILINE | re.IGNORECASE)
# Refined base64 pattern to be more strict and avoid matching random strings
# It checks for typical base64 characters and padding, and ensures it's not too short
base64_pattern = re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$', re.MULTILINE)


try:
    with open(input_file, "r", encoding="utf-8") as f:
        urls = [line.strip().split("|")[0] for line in f if line.strip()]
    invalid_urls = load_invalid_urls()
    urls = [url for url in urls if url not in invalid_urls]
    debug_logs.append(f"从 {input_file} 读取 {len(urls)} 个有效 URL")
except FileNotFoundError:
    debug_logs.append(f"错误：未找到 {input_file}")
    exit(1)

def yaml_to_protocol(proxy):
    proxy_type = proxy.get('type', '').lower()
    server = proxy.get('server', '')
    port = proxy.get('port', 0)
    name = proxy.get('name', '')

    if not server or not port:
        return None

    try:
        if proxy_type == 'ss':
            cipher = proxy.get('cipher', 'chacha20-ietf-poly1305')
            password = proxy.get('password', '')
            if password:
                auth_str = f"{cipher}:{password}"
                encoded_auth = base64.b64encode(auth_str.encode('utf-8')).decode('utf-8')
                node = f"ss://{encoded_auth}@{server}:{port}"
                if name:
                    node += f"#{quote(name, safe='')}"
                return node
        elif proxy_type == 'hysteria2':
            password = proxy.get('password', '')
            node = f"hysteria2://{password}@{server}:{port}"
            params = {}
            if proxy.get('obfs'):
                params['obfs'] = proxy.get('obfs')
            if proxy.get('obfs-password'):
                params['obfsParam'] = proxy.get('obfs-password')
            if params:
                node += "?" + urlencode(params)
            if name:
                node += f"#{quote(name, safe='')}"
            return node
        elif proxy_type == 'trojan':
            password = proxy.get('password', '')
            node = f"trojan://{password}@{server}:{port}"
            params = {}
            if proxy.get('network'):
                params['type'] = proxy.get('network')
            if proxy.get('tls'):
                params['security'] = 'tls'
            if proxy.get('servername'):
                params['sni'] = proxy.get('servername')
            if params:
                node += "?" + urlencode(params)
            if name:
                node += f"#{quote(name, safe='')}"
            return node
        elif proxy_type == 'vmess':
            vmess_config = {
                "v": "2",
                "ps": name,
                "add": server,
                "port": port,
                "id": proxy.get('uuid', ''),
                "aid": proxy.get('alterId', 0),
                "net": proxy.get('network', 'tcp'),
                "type": proxy.get('headerType', 'none'),
                "tls": proxy.get('tls', ''),
                "sni": proxy.get('servername', '')
            }
            # Filter out empty values to keep the JSON clean
            vmess_config = {k: v for k, v in vmess_config.items() if v or k in ['port', 'aid']} # Keep port and aid even if 0/empty
            encoded_vmess = base64.b64encode(json.dumps(vmess_config).encode('utf-8')).decode('utf-8')
            node = f"vmess://{encoded_vmess}"
            return node
        elif proxy_type == 'vless':
            uuid = proxy.get('uuid', '')
            node = f"vless://{uuid}@{server}:{port}"
            params = {}
            if proxy.get('tls'):
                params['security'] = 'tls'
            if proxy.get('servername'):
                params['sni'] = proxy.get('servername')
            if proxy.get('network'):
                params['type'] = proxy.get('network')
            if proxy.get('flow'):
                params['flow'] = proxy.get('flow')
            if params:
                node += "?" + urlencode(params)
            if name:
                node += f"#{quote(name, safe='')}"
            return node
    except Exception as e:
        debug_logs.append(f"YAML 转换失败: {proxy.get('name', '未知')} ({e})")
    return None

async def extract_nodes_from_url(session, url, index, total_urls):
    extracted_protocol_nodes = []
    extracted_yaml_nodes = []
    start_time = time.time()
    debug_logs.append(f"\n处理 URL {index+1}/{total_urls}: {url}")

    try:
        raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        async with session.get(raw_url, headers=headers, timeout=15) as response:
            response.raise_for_status()
            content = await response.text()
            content = content[:1000000] # Limit content size to prevent excessive memory usage
            debug_logs.append(f"获取 {url} 内容成功，长度: {len(content)}")
            debug_logs.append(f"内容前100字符: {content[:100].replace('\n', ' ')}")

            protocol_matches = protocol_pattern.finditer(content)
            for match in protocol_matches:
                node = match.group(0).strip()
                # Basic validation for extracted protocol nodes
                if protocol_pattern.match(node) and len(node) > 10:
                    extracted_protocol_nodes.append(node)
                    url_node_map[node] = url
                    debug_logs.append(f"提取明文节点: {node[:50]}...")

            base64_matches = base64_pattern.findall(content)
            debug_logs.append(f"找到 {len(base64_matches)} 个 Base64 字符串")
            skip_params = ['encryption=', 'security=', 'sni=', 'type=', 'mode=', 'serviceName=', 'fp=', 'pbk=', 'sid=']
            for b64_str in base64_matches:
                # Skip strings that look like base64 but are actually URL parameters
                if any(param in b64_str.lower() for param in skip_params):
                    debug_logs.append(f"跳过非 Base64 参数: {b64_str[:20]}...")
                    continue
                try:
                    # Attempt to decode, then check if it contains a protocol pattern
                    decoded = base64.b64decode(b64_str, validate=True).decode('utf-8', errors='ignore')
                    if protocol_pattern.search(decoded):
                        node = decoded.strip()
                        if protocol_pattern.match(node) and len(node) > 10:
                            extracted_protocol_nodes.append(node)
                            url_node_map[node] = url
                            debug_logs.append(f"提取 Base64 解码节点: {node[:50]}...")
                    # Also try to parse as JSON for VMess
                    try:
                        json_data = json.loads(decoded)
                        if isinstance(json_data, dict) and any(key in json_data for key in ['v', 'ps', 'add', 'port', 'id']):
                            node = f"vmess://{base64.b64encode(json.dumps(json_data).encode('utf-8')).decode('utf-8')}"
                            extracted_protocol_nodes.append(node)
                            url_node_map[node] = url
                            debug_logs.append(f"提取 Base64 JSON 节点: {node[:50]}...")
                    except json.JSONDecodeError:
                        pass # Not a JSON, continue
                except (base64.binascii.Error, UnicodeDecodeError) as e:
                    debug_logs.append(f"Base64 解码失败: {b64_str[:20]}... ({e})")
                    continue

            file_extension = os.path.splitext(url)[1].lower()
            debug_logs.append(f"尝试解析 YAML/JSON: {url}, 扩展名: {file_extension}")
            # Consider more common extensions for configs, or if no extension, try parsing
            if file_extension in ['.yaml', '.yml', '.txt', '.conf', '.json'] or not file_extension:
                # Try YAML parsing first
                try:
                    yaml_data = yaml.safe_load(content)
                    if isinstance(yaml_data, dict):
                        # Look for common keys where proxy configurations might be stored
                        for key in ['proxies', 'proxy', 'nodes', 'servers', 'outbounds', 'inbounds', 'proxy-groups', 'http', 'socks', 'socks5']:
                            if key in yaml_data:
                                proxies = yaml_data[key]
                                if isinstance(proxies, list):
                                    for proxy in proxies:
                                        if isinstance(proxy, dict) and any(k in proxy for k in ['server', 'port', 'type', 'cipher', 'password', 'uuid']):
                                            protocol_node = yaml_to_protocol(proxy)
                                            if protocol_node:
                                                extracted_protocol_nodes.append(protocol_node)
                                                url_node_map[protocol_node] = url
                                                debug_logs.append(f"提取 YAML 协议节点: {protocol_node[:50]}...")
                                            extracted_yaml_nodes.append(proxy)
                                            debug_logs.append(f"提取 YAML 节点: {yaml.dump([proxy], allow_unicode=True, sort_keys=False)[:50]}...")
                                elif isinstance(proxies, dict): # Handle single proxy object at top level
                                    if any(k in proxies for k in ['server', 'port', 'type', 'cipher', 'password', 'uuid']):
                                        protocol_node = yaml_to_protocol(proxies)
                                        if protocol_node:
                                            extracted_protocol_nodes.append(protocol_node)
                                            url_node_map[protocol_node] = url
                                            debug_logs.append(f"提取 YAML 协议节点: {protocol_node[:50]}...")
                                        extracted_yaml_nodes.append(proxies)
                                        debug_logs.append(f"提取 YAML 节点: {yaml.dump([proxies], allow_unicode=True, sort_keys=False)[:50]}...")
                    debug_logs.append(f"YAML 数据类型: {type(yaml_data)}")
                except yaml.YAMLError as e:
                    debug_logs.append(f"YAML 解析失败: {url} ({e})")
                
                # Try JSON parsing if YAML failed or if it's a JSON file
                if file_extension in ['.json'] or not extracted_protocol_nodes and not extracted_yaml_nodes: # Only try JSON if no YAML nodes were found or it's explicitly JSON
                    try:
                        json_data = json.loads(content)
                        if isinstance(json_data, dict):
                            for key in ['proxies', 'servers', 'nodes']:
                                if key in json_data and isinstance(json_data[key], list):
                                    for proxy in json_data[key]:
                                        if isinstance(proxy, dict) and any(k in proxy for k in ['server', 'port', 'type']):
                                            protocol_node = yaml_to_protocol(proxy) # Reuse YAML to protocol conversion for JSON proxies
                                            if protocol_node:
                                                extracted_protocol_nodes.append(protocol_node)
                                                url_node_map[protocol_node] = url
                                                debug_logs.append(f"提取 JSON 协议节点: {protocol_node[:50]}...")
                                            extracted_yaml_nodes.append(proxy) # Store as YAML-like dict for consistency
                                            debug_logs.append(f"提取 JSON 节点: {json.dumps([proxy], ensure_ascii=False)[:50]}...")
                        debug_logs.append(f"JSON 数据类型: {type(json_data)}")
                    except json.JSONDecodeError as e:
                        debug_logs.append(f"JSON 解析失败: {url} ({e})")

    except Exception as e:
        debug_logs.append(f"获取 {url} 内容失败: {e}")
        debug_logs.append(f"URL {url} 提取失败，将在测试阶段处理其有效性。")

    elapsed = time.time() - start_time
    debug_logs.append(f"URL {index+1} 处理完成，耗时 {elapsed:.2f} 秒")
    return extracted_protocol_nodes, extracted_yaml_nodes

async def test_and_save_nodes():
    debug_logs.append("\nPhase 2: 开始测试已提取的节点...")

    temp_protocol_nodes = []
    global url_node_map # Declare global to modify the global variable
    try:
        with open(temp_nodes_file, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split('|', 1)
                if len(parts) == 2:
                    node, source_url = parts
                    temp_protocol_nodes.append(node)
                    url_node_map[node] = source_url
                else:
                    debug_logs.append(f"警告: 临时文件格式不正确: {line.strip()}")
        debug_logs.append(f"加载 {len(temp_protocol_nodes)} 个待测试节点")
    except FileNotFoundError:
        debug_logs.append(f"错误：未找到 {temp_nodes_file}，跳过节点测试。")
        return

    valid_protocol_nodes = []
    invalid_urls_to_add = set()

    nodes_to_test = temp_protocol_nodes[:TEST_MAX_NODES] if TEST_ENABLED else temp_protocol_nodes
    tasks = [test_node_async(node) for node in nodes_to_test]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for i, (node, result) in enumerate(zip(nodes_to_test, results)):
        if result is True:
            valid_protocol_nodes.append(node)
        else:
            source_url = url_node_map.get(node)
            if source_url:
                invalid_urls_to_add.add(source_url)
        debug_logs.append(f"测试节点 {i+1}/{len(nodes_to_test)} 完成")

    if invalid_urls_to_add:
        current_invalid_urls = load_invalid_urls() # Reload to get the latest state
        new_invalid_urls = invalid_urls_to_add - current_invalid_urls
        if new_invalid_urls:
            with open(invalid_urls_file, "a", encoding="utf-8") as f:
                for url in new_invalid_urls:
                    # Corrected: Use datetime.timezone.utc for timezone object
                    f.write(f"{url}|{datetime.now(datetime.timezone.utc).isoformat()}\n")
            debug_logs.append(f"记录 {len(new_invalid_urls)} 个新的无效 URL")
        else:
            debug_logs.append("没有新的无效 URL 需要记录。")
    else:
        debug_logs.append("没有因节点测试失败而需要记录的无效 URL。")

    with open(protocol_output_file, "w", encoding="utf-8") as f:
        for node in valid_protocol_nodes:
            f.write(f"{node}\n")
    debug_logs.append(f"保存 {len(valid_protocol_nodes)} 个有效协议节点到 {protocol_output_file}")
    print(f"提取并测试 {len(valid_protocol_nodes)} 个有效协议节点，已保存到 {protocol_output_file}")

async def main():
    async with aiohttp.ClientSession() as session:
        await check_rate_limit(session)
        # Limiting to 50 URLs for debugging as per your comment, remove for full run
        urls_set = sorted(list(set(urls)))[:50]
        total_urls = len(urls_set)
        tasks = []

        debug_logs.append("Phase 1: 开始从所有URL提取节点...")
        for i, url in enumerate(urls_set):
            tasks.append(extract_nodes_from_url(session, url, i, total_urls))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(results):
            if isinstance(result, tuple):
                p_nodes, y_nodes = result
                protocol_nodes.extend(p_nodes)
                yaml_nodes.extend(y_nodes)
            else:
                debug_logs.append(f"URL {i+1} 提取时发生错误: {result}")

        protocol_nodes_set = list(dict.fromkeys(protocol_nodes))
        # Convert YAML nodes to a string representation for deduplication, then back to dict
        yaml_nodes_set = list({yaml.dump(node, allow_unicode=True, sort_keys=False): node for node in yaml_nodes}.values())

        debug_logs.append(f"提取 {len(protocol_nodes_set)} 个原始协议节点 (待测试)")
        debug_logs.append(f"提取 {len(yaml_nodes_set)} 个原始 YAML 节点")

        with open(temp_nodes_file, "w", encoding="utf-8") as f:
            for node in protocol_nodes_set:
                f.write(f"{node}|{url_node_map.get(node, 'unknown')}\n")
        debug_logs.append(f"保存 {len(protocol_nodes_set)} 个未测试协议节点到 {temp_nodes_file}")
        print(f"提取 {len(protocol_nodes_set)} 个原始协议节点，已保存到 {temp_nodes_file} (待测试)")

        with open(yaml_output_file, "w", encoding="utf-8") as f:
            if yaml_nodes_set:
                yaml.dump({"proxies": yaml_nodes_set}, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
            else:
                f.write("# No YAML nodes found\n")
        debug_logs.append(f"保存 {len(yaml_nodes_set)} 个 YAML 节点到 {yaml_output_file}")
        print(f"提取 {len(yaml_nodes_set)} 个 YAML 节点，已保存到 {yaml_output_file}")

        await test_and_save_nodes()

        with open(debug_log_file, "w", encoding="utf-8") as f:
            f.write("\n".join(debug_logs))
        print(f"调试日志已保存到 {debug_log_file}")

if __name__ == "__main__":
    asyncio.run(main())
