import aiohttp
import asyncio
import os
import re
import base64
import yaml
import json
import socket
import time # Ensure time is imported for measuring elapsed time
from urllib.parse import quote, urlencode
from datetime import datetime

# GitHub API 基础 URL (Not directly used in this script but kept for context)
SEARCH_API_URL = "https://api.github.com/search/code"

# 环境变量
GITHUB_TOKEN = os.getenv("BOT")
TEST_ENABLED = os.getenv("TEST_NODES", "true").lower() == "true"
TEST_MAX_NODES = int(os.getenv("TEST_MAX_NODES", 50))
TEST_TIMEOUT = float(os.getenv("TEST_TIMEOUT", 1))

# 文件路径
input_file = "data/hy2.txt"
invalid_urls_file = "data/invalid_urls.txt"
protocol_output_file = "data/protocol_nodes.txt"
yaml_output_file = "data/yaml_nodes.yaml"
debug_log_file = "data/extract_debug.log"
temp_nodes_file = "data/temp_nodes.txt" # 用于保存所有提取但未测试的协议节点

# 确保 data 目录存在
os.makedirs("data", exist_ok=True)

# 数据存储
# protocol_nodes 和 yaml_nodes 现在只用于存储当前批次从URL提取的节点，不直接用于测试
protocol_nodes = []
yaml_nodes = []
debug_logs = []
url_node_map = {}  # 节点到源 URL 的映射

# 加载无效 URL
def load_invalid_urls():
    invalid_urls = set()
    try:
        with open(invalid_urls_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    invalid_urls.add(line.split("|")[0])
        debug_logs.append(f"加载 {len(invalid_urls)} 个无效 URL")
    except FileNotFoundError:
        debug_logs.append(f"{invalid_urls_file} 未找到，将创建新文件")
    return invalid_urls

# 测试节点
def test_node(server, port, timeout=TEST_TIMEOUT):
    try:
        sock = socket.create_connection((server, int(port)), timeout=timeout)
        sock.close()
        debug_logs.append(f"节点 {server}:{port} 测试成功")
        return True
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, ValueError) as e:
        debug_logs.append(f"节点 {server}:{port} 测试失败: {e}")
        return False

# 解析节点，从协议字符串中提取服务器和端口
def parse_node(node):
    try:
        if node.startswith(("ss://", "hysteria2://", "trojan://", "vless://")):
            # 兼容带有@符号的协议，提取@之后的部分作为host:port
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

# 请求头
headers = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "Mozilla/5.0 (compatible; NodeExtractor/1.0)"
}
if GITHUB_TOKEN:
    headers["Authorization"] = f"token {GITHUB_TOKEN}"
else:
    debug_logs.append("警告：未找到 BOT 环境变量")

# 检查 GitHub API 速率限制
async def check_rate_limit(session):
    try:
        async with session.get("https://api.github.com/rate_limit", headers=headers) as response:
            rate_limit = await response.json()
            debug_logs.append(f"速率限制: {rate_limit['rate']['remaining']} 剩余")
    except Exception as e:
        debug_logs.append(f"检查速率限制失败: {e}")

# 正则表达式
# 匹配常见的协议前缀，并确保后面是非空白、非尖括号、非引号的字符
protocol_pattern = re.compile(r'(ss|hysteria2|vless|vmess|trojan)://[^\s<>\'"]+', re.MULTILINE | re.IGNORECASE)
# 匹配长度至少为8的Base64字符串
base64_pattern = re.compile(r'[A-Za-z0-9+/=]{8,}', re.MULTILINE)

# 读取 data/hy2.txt
try:
    with open(input_file, "r", encoding="utf-8") as f:
        urls = [line.strip().split("|")[0] for line in f if line.strip()]
    invalid_urls = load_invalid_urls()
    urls = [url for url in urls if url not in invalid_urls] # 过滤掉已知的无效URL
    debug_logs.append(f"从 {input_file} 读取 {len(urls)} 个有效 URL")
except FileNotFoundError:
    debug_logs.append(f"错误：未找到 {input_file}")
    exit(1)

# 将 YAML 格式的代理配置转换为标准协议字符串
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
            if name:
                node += f"#{quote(name, safe='')}"
            # Add other Hysteria2 parameters if needed, e.g., 'obfs', 'obfs-password'
            params = {}
            if proxy.get('obfs'):
                params['obfs'] = proxy.get('obfs')
            if proxy.get('obfs-password'):
                params['obfsParam'] = proxy.get('obfs-password') # Hysteria2 uses obfsParam
            if params:
                node += "?" + urlencode(params)
            return node
        elif proxy_type == 'trojan':
            password = proxy.get('password', '')
            node = f"trojan://{password}@{server}:{port}"
            if name:
                node += f"#{quote(name, safe='')}"
            # Add other Trojan parameters if needed, e.g., 'network', 'tls'
            params = {}
            if proxy.get('network'):
                params['type'] = proxy.get('network') # Often used for network type in client configs
            if proxy.get('tls'):
                params['security'] = 'tls' # Common parameter for TLS
            if proxy.get('servername'):
                params['sni'] = proxy.get('servername')
            if params:
                node += "?" + urlencode(params)
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
            # Remove empty values to keep the config cleaner if desired
            vmess_config = {k: v for k, v in vmess_config.items() if v}
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
            if proxy.get('flow'): # VLESS flow parameter
                params['flow'] = proxy.get('flow')
            if params:
                node += "?" + urlencode(params)
            if name:
                node += f"#{quote(name, safe='')}"
            return node
    except Exception as e:
        debug_logs.append(f"YAML 转换失败: {proxy.get('name', '未知')} ({e})")
    return None

# 提取节点逻辑：从单个 URL 获取内容并解析协议和 YAML 节点
async def extract_nodes_from_url(session, url, index, total_urls):
    extracted_protocol_nodes = []
    extracted_yaml_nodes = []
    start_time = time.time()
    debug_logs.append(f"\n处理 URL {index+1}/{total_urls}: {url}")

    try:
        raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        async with session.get(raw_url, headers=headers, timeout=10) as response:
            response.raise_for_status()
            content = await response.text()
            # 限制内容长度以避免处理过大的文件和潜在的内存问题
            content = content[:500000] # Increased limit to 500KB
            debug_logs.append(f"获取 {url} 内容成功，长度: {len(content)}")
            debug_logs.append(f"内容前100字符: {content[:100].replace('\n', ' ')}")

            # 提取明文协议
            protocol_matches = protocol_pattern.finditer(content)
            for match in protocol_matches:
                node = match.group(0).strip()
                extracted_protocol_nodes.append(node)
                url_node_map[node] = url # 映射节点到源URL
                debug_logs.append(f"提取明文节点: {node[:50]}...")

            # 提取 Base64 编码的节点
            base64_matches = base64_pattern.findall(content)
            debug_logs.append(f"找到 {len(base64_matches)} 个 Base64 字符串")
            for b64_str in base64_matches:
                try:
                    decoded = base64.b64decode(b64_str, validate=True).decode('utf-8')
                    # 检查解码后的内容是否包含协议链接
                    if protocol_pattern.search(decoded):
                        node = decoded.strip()
                        extracted_protocol_nodes.append(node)
                        url_node_map[node] = url
                        debug_logs.append(f"提取 Base64 解码节点: {node[:50]}...")
                    # 尝试解析为 VMess JSON配置
                    try:
                        json_data = json.loads(decoded)
                        if isinstance(json_data, dict) and any(key in json_data for key in ['v', 'ps', 'add', 'port', 'id']):
                            node = f"vmess://{base64.b64encode(json.dumps(json_data).encode('utf-8')).decode('utf-8')}"
                            extracted_protocol_nodes.append(node)
                            url_node_map[node] = url
                            debug_logs.append(f"提取 Base64 JSON 节点: {node[:50]}...")
                    except json.JSONDecodeError:
                        pass # Not a valid JSON, move on
                except (base64.binascii.Error, UnicodeDecodeError) as e:
                    debug_logs.append(f"Base64 解码失败: {b64_str[:20]}... ({e})")

            # 提取 YAML 格式的节点
            file_extension = os.path.splitext(url)[1].lower()
            # 针对常见的YAML或文本文件扩展名进行YAML解析，或者当没有明确扩展名时也尝试
            if file_extension in ['.yaml', '.yml', '.txt'] or not file_extension:
                try:
                    yaml_data = yaml.safe_load(content)
                    if isinstance(yaml_data, dict):
                        # 查找常见的代理列表键
                        for key in ['proxies', 'proxy', 'nodes', 'servers']:
                            if key in yaml_data and isinstance(yaml_data[key], list):
                                for proxy in yaml_data[key]:
                                    if isinstance(proxy, dict) and any(k in proxy for k in ['server', 'port', 'type', 'cipher', 'password', 'uuid']):
                                        protocol_node = yaml_to_protocol(proxy)
                                        if protocol_node:
                                            extracted_protocol_nodes.append(protocol_node)
                                            url_node_map[protocol_node] = url
                                            debug_logs.append(f"提取 YAML 协议节点: {protocol_node[:50]}...")
                                        extracted_yaml_nodes.append(proxy)
                                        debug_logs.append(f"提取 YAML 节点: {yaml.dump([proxy], allow_unicode=True, sort_keys=False)[:50]}...")
                            elif key in yaml_data and isinstance(yaml_data[key], dict): # Handle single proxy dict
                                proxy = yaml_data[key]
                                if isinstance(proxy, dict) and any(k in proxy for k in ['server', 'port', 'type', 'cipher', 'password', 'uuid']):
                                    protocol_node = yaml_to_protocol(proxy)
                                    if protocol_node:
                                        extracted_protocol_nodes.append(protocol_node)
                                        url_node_map[protocol_node] = url
                                        debug_logs.append(f"提取 YAML 协议节点: {protocol_node[:50]}...")
                                    extracted_yaml_nodes.append(proxy)
                                    debug_logs.append(f"提取 YAML 节点: {yaml.dump([proxy], allow_unicode=True, sort_keys=False)[:50]}...")
                    else:
                        debug_logs.append(f"YAML 数据不是字典或列表: {type(yaml_data)}")
                except yaml.YAMLError as e:
                    debug_logs.append(f"YAML 解析失败: {url} ({e})")

    except Exception as e:
        debug_logs.append(f"获取 {url} 内容失败: {e}")
        # 在提取阶段不立即将URL标记为无效，因为可能只是暂时的网络问题，实际节点可能在其他地方找到。
        # 无效URL的记录将只发生在节点测试失败后。
        debug_logs.append(f"URL {url} 提取失败，将在测试阶段处理其有效性。")

    elapsed = time.time() - start_time
    debug_logs.append(f"URL {index+1} 处理完成，耗时 {elapsed:.2f} 秒")
    return extracted_protocol_nodes, extracted_yaml_nodes

# 新增函数：测试已提取的节点并保存有效节点
async def test_and_save_nodes():
    debug_logs.append("\nPhase 2: 开始测试已提取的节点...")

    # 从临时文件加载所有协议节点
    temp_protocol_nodes = []
    # 重新构建 url_node_map，因为它是全局的，但在此阶段可能被重置
    global url_node_map
    url_node_map = {}
    try:
        with open(temp_nodes_file, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split("|", 1) # 只在第一个 '|' 处分割
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
    invalid_urls_to_add = set() # 记录因节点测试失败而需要标记为无效的URL

    # 根据 TEST_MAX_NODES 限制要测试的节点数量
    nodes_to_test = temp_protocol_nodes
    if TEST_ENABLED:
        nodes_to_test = temp_protocol_nodes[:TEST_MAX_NODES]

    for i, node in enumerate(nodes_to_test):
        if not TEST_ENABLED: # 如果测试被禁用，所有节点都视为有效
            valid_protocol_nodes.append(node)
            continue
        server, port = parse_node(node)
        if server and port:
            if test_node(server, port):
                valid_protocol_nodes.append(node)
            else:
                source_url = url_node_map.get(node, None)
                if source_url:
                    invalid_urls_to_add.add(source_url) # 节点测试失败，将源URL标记为无效
        debug_logs.append(f"测试节点 {i + 1}/{len(nodes_to_test)} 完成")

    # 将因测试失败而产生的无效 URL 追加写入文件
    if invalid_urls_to_add:
        # 获取当前已有的无效URL，避免重复写入
        current_invalid_urls = load_invalid_urls()
        new_invalid_urls = invalid_urls_to_add - current_invalid_urls # 只添加新的无效URL

        if new_invalid_urls:
            with open(invalid_urls_file, "a", encoding="utf-8") as f:
                for url in new_invalid_urls:
                    f.write(f"{url}|{datetime.utcnow().isoformat()}\n")
            debug_logs.append(f"记录 {len(new_invalid_urls)} 个新的无效 URL")
        else:
            debug_logs.append("没有新的无效 URL 需要记录。")
    else:
        debug_logs.append("没有因节点测试失败而需要记录的无效 URL。")

    # 保存有效协议节点
    with open(protocol_output_file, "w", encoding="utf-8") as f:
        for node in valid_protocol_nodes:
            f.write(node + "\n")
    debug_logs.append(f"保存 {len(valid_protocol_nodes)} 个有效协议节点到 {protocol_output_file}")
    print(f"提取并测试 {len(valid_protocol_nodes)} 个有效协议节点，已保存到 {protocol_output_file}")


# 主流程
async def main():
    async with aiohttp.ClientSession() as session:
        await check_rate_limit(session)
        urls_set = list(set(urls))  # 对输入URL进行去重
        total_urls = len(urls_set)
        tasks = []

        # Phase 1: 提取所有节点（不进行测试）
        debug_logs.append("Phase 1: 开始从所有URL提取节点...")
        for i, url in enumerate(urls_set):
            tasks.append(extract_nodes_from_url(session, url, i, total_urls))

        results = await asyncio.gather(*tasks, return_exceptions=True) # 并行执行URL内容提取

        # 收集提取结果
        for i, result in enumerate(results):
            if isinstance(result, tuple):
                p_nodes, y_nodes = result
                protocol_nodes.extend(p_nodes)
                yaml_nodes.extend(y_nodes)
            else:
                debug_logs.append(f"URL {i + 1} 提取时发生错误: {result}")

        # 对提取的节点进行去重
        # 使用 dict.fromkeys() 可以保持原始顺序去重
        protocol_nodes_set = list(dict.fromkeys(protocol_nodes))
        # 对于 YAML 节点，需要先转储成字符串作为key来去重，再取回值
        yaml_nodes_set = list({yaml.dump(node, allow_unicode=True, sort_keys=False): node for node in yaml_nodes}.values())

        debug_logs.append(f"\n提取 {len(protocol_nodes_set)} 个原始协议节点 (待测试)")
        debug_logs.append(f"提取 {len(yaml_nodes_set)} 个原始 YAML 节点")

        # 将所有提取到的协议节点保存到临时文件，供后续测试使用
        with open(temp_nodes_file, "w", encoding="utf-8") as f:
            for node in protocol_nodes_set:
                f.write(f"{node}|{url_node_map.get(node, 'unknown')}\n") # 保存节点及其源URL
        debug_logs.append(f"保存 {len(protocol_nodes_set)} 个未测试协议节点到 {temp_nodes_file}")
        print(f"提取 {len(protocol_nodes_set)} 个原始协议节点，已保存到 {temp_nodes_file} (待测试)")

        # 保存所有提取到的 YAML 节点
        with open(yaml_output_file, "w", encoding="utf-8") as f:
            if yaml_nodes_set:
                yaml.dump({"proxies": yaml_nodes_set}, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
            else:
                f.write("# No YAML nodes found\n")
        debug_logs.append(f"保存 {len(yaml_nodes_set)} 个 YAML 节点到 {yaml_output_file}")
        print(f"提取 {len(yaml_nodes_set)} 个 YAML 节点，已保存到 {yaml_output_file}")

    # Phase 2: 测试已提取的节点并保存结果
    await test_and_save_nodes()

    # 保存所有调试日志
    with open(debug_log_file, "w", encoding="utf-8") as f:
        f.write("\n".join(debug_logs)) # 写入所有日志
    print(f"调试日志已保存到 {debug_log_file}")

if __name__ == "__main__":
    # 启动主异步函数
    asyncio.run(main())
