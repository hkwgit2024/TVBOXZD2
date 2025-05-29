import requests
import base64
import yaml
import json
import os
import re
import asyncio
import aiohttp
from datetime import datetime, timezone
from datetime import timedelta
from urllib.parse import urlparse, quote

# 配置
GITHUB_API_URL = "https://api.github.com/search/code"
TOKEN = os.getenv("BOT")
if not TOKEN:
    print("错误: 环境变量 BOT 未设置或为空")
    exit(1)
print("调试: BOT 环境变量已加载（前8位）: " + TOKEN[:8] + "...")
HEADERS = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "Mozilla/5.0 (compatible; NodeSearchBot/1.0)",
    "Accept-Encoding": "gzip, deflate"
}
RAW_HEADERS = {
    "Authorization": f"token {TOKEN}",
    "User-Agent": "Mozilla/5.0 (compatible; NodeSearchBot/1.0)",
    "Accept": "application/octet-stream"
}
SEARCH_QUERIES = [
    "clash proxies extension:yaml in:file -in:path manifest -in:path skaffold -in:path locale",
    "v2ray outbounds extension:json in:file",
    "trojan nodes extension:txt in:file",
    "hysteria hy2 extension:txt",
    "ssr shadowsocksr extension:txt",
    "vless server extension:txt",
    "free proxy subscription extension:txt",
    "clash subs user:dongchengjie extension:yaml",
    "clash config user:freefq extension:yaml",
    "v2ray nodes user:Alvin9999 extension:txt",
    "xray config extension:json in:file"
]
OUTPUT_DIR = "data"
NODES_FILE = os.path.join(OUTPUT_DIR, "hy2.txt")
URLS_FILE = os.path.join(OUTPUT_DIR, "url.txt")
NODE_PROTOCOLS = ["ss://", "vmess://", "trojan://", "hy2://", "ssr://", "vless://", "http://", "https://", "socks5://", "wg://"]
VALID_EXTENSIONS = {".yaml", ".yml", ".txt", ".json"}

# 确保输出目录存在
if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

# 去重集合
unique_nodes = set()
unique_urls = {}

# 读取已有的 URL 和时间戳
def load_existing_urls():
    if os.path.exists(URLS_FILE):
        with open(URLS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        url, timestamp = line.strip().split(" | ", 1)
                        unique_urls[url] = timestamp
                    except:
                        continue
    print(f"调试: 加载了 {len(unique_urls)} 个现有 URL")
    return unique_urls

# 获取仓库默认分支
def get_default_branch(repo):
    repo_url = f"https://api.github.com/repos/{repo}"
    try:
        response = requests.get(repo_url, headers=HEADERS)
        if response.status_code == 200:
            return response.json().get("default_branch", "main")
        print(f"获取 {repo} 默认分支失败: {response.status_code}, {response.text}")
        return "main"
    except Exception as e:
        print(f"获取 {repo} 默认分支异常: {e}")
        return "main"

# 检查文件是否更新
def is_file_updated(repo, path, existing_timestamp):
    commit_url = f"https://api.github.com/repos/{repo}/commits?path={quote(path, safe='')}&per_page=1"
    try:
        response = requests.get(commit_url, headers=HEADERS)
        if response.status_code == 200:
            commits = response.json()
            if not commits:
                print(f"调试: {repo}/{path} 无提交历史，视为新文件")
                return True, datetime.now(timezone.utc).isoformat()
            commit_date = commits[0]["commit"]["committer"]["date"]
            commit_time = datetime.fromisoformat(commit_date.replace("Z", "+00:00"))
            if not existing_timestamp:
                return True, commit_time.isoformat()
            existing_time = datetime.fromisoformat(existing_timestamp.replace("Z", "+00:00"))
            return commit_time > existing_time, commit_time.isoformat()
        else:
            print(f"检查文件更新失败: {response.status_code}, {response.text}")
            return False, None
    except Exception as e:
        print(f"检查文件更新异常: {e}")
        return False, None

# 异步测试 URL 连通性
async def test_url_connection(url, timeout=5):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=timeout) as response:
                return response.status == 200
    except Exception as e:
        print(f"测试 URL {url} 连通性失败: {e}")
        return False

# 异步测试节点连通性
async def test_node_connection(node, timeout=5):
    try:
        for protocol in NODE_PROTOCOLS:
            if node.startswith(protocol):
                if protocol in ["hy2://", "wg://", "trojan://"]:
                    return True  # 跳过复杂协议测试
                if protocol == "vmess://":
                    try:
                        vmess_data = base64.b64decode(node[len("vmess://"):]).decode("utf-8")
                        vmess_json = json.loads(vmess_data)
                        host = vmess_json.get("add")
                        port = int(vmess_json.get("port", 0))
                    except:
                        return False
                elif protocol == "vless://":
                    match = re.match(r"vless://([^@]+)@([^:]+):(\d+)", node)
                    if match:
                        host, port = match.group(2), int(match.group(3))
                    else:
                        return False
                elif protocol in ["http://", "https://"]:
                    try:
                        async with aiohttp.ClientSession() as session:
                            async with session.head(node, timeout=timeout) as response:
                                return response.status == 200
                    except:
                        return False
                else:
                    match = re.match(r"(ss|ssr|socks5)://[^@]+@([^:]+):(\d+)", node)
                    if match:
                        host, port = match.group(2), int(match.group(3))
                    else:
                        return False
                async with aiohttp.ClientSession() as session:
                    async with session.head(f"http://{host}:{port}", timeout=timeout) as response:
                        return response.status == 200
        return False
    except Exception as e:
        print(f"测试节点 {node} 连通性失败: {e}")
        return False

# 解析 Base64 编码
def decode_base64(content):
    try:
        decoded = base64.b64decode(content).decode("utf-8")
        return decoded
    except:
        return None

# 递归解码 Base64
def recursive_decode_base64(content, depth=0, max_depth=3):
    if depth >= max_depth:
        return content
    decoded = decode_base64(content)
    if decoded:
        return recursive_decode_base64(decoded, depth + 1, max_depth)
    return content

# 解析 YAML 或 JSON 内容
def parse_config(content):
    try:
        # 尝试 YAML 解析
        data = yaml.safe_load(content)
        if data:
            return data
        # 尝试 JSON 解析
        data = json.loads(content)
        return data
    except:
        return None

# 清理节点中的 # 后内容
def clean_node(node):
    return re.split(r"#", node)[0].strip()

# 获取文件内容
def get_file_content(repo, path, branch="main"):
    if not any(path.lower().endswith(ext) for ext in VALID_EXTENSIONS):
        print(f"调试: 跳过无效文件扩展名: {path}")
        return None
    raw_url = f"https://raw.githubusercontent.com/{repo}/{branch}/{quote(path, safe='')}"
    print(f"调试: 尝试获取文件: {raw_url}")
    try:
        response = requests.get(raw_url, headers=RAW_HEADERS)
        if response.status_code == 200:
            print(f"调试: 成功获取文件 {raw_url}")
            return response.text
        else:
            print(f"获取文件 {raw_url} 失败: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        print(f"获取文件 {raw_url} 异常: {e}")
        return None

# 保存结果
def save_results():
    if unique_nodes or unique_urls:
        with open(NODES_FILE, "w", encoding="utf-8") as f:
            for node in unique_nodes:
                f.write(node + "\n")
        with open(URLS_FILE, "w", encoding="utf-8") as f:
            for url, timestamp in unique_urls.items():
                f.write(f"{url} | {timestamp}\n")
        print(f"调试: 保存了 {len(unique_nodes)} 个节点到 {NODES_FILE}，{len(unique_urls)} 个 URL 到 {URLS_FILE}")
    else:
        print("调试: 无节点或 URL 保存，跳过文件写入")

# 主逻辑
async def main():
    # 加载已有 URL 和时间戳
    load_existing_urls()

    # 逐个执行搜索查询
    for query in SEARCH_QUERIES:
        print(f"调试: 执行搜索查询: {query}")
        for page in range(1, 3):  # 获取前2页
            params = {"q": query, "per_page": 50, "page": page}
            try:
                response = requests.get(GITHUB_API_URL, headers=HEADERS, params=params)
                if response.status_code != 200:
                    print(f"GitHub API 请求失败 (查询: {query}, 页: {page}): {response.status_code}, {response.text}")
                    continue
                print(f"调试: 查询 {query} 页 {page} 获取 {len(response.json().get('items', []))} 条结果")
            except Exception as e:
                print(f"GitHub API 请求异常 (查询: {query}, 页: {page}): {e}")
                continue

            data = response.json()
            items = data.get("items", [])

            for item in items:
                repo = item["repository"]["full_name"]
                path = item["path"]
                branch = get_default_branch(repo)
                raw_url = f"https://raw.githubusercontent.com/{repo}/{branch}/{quote(path, safe='')}"

                # 检查是否需要更新
                existing_timestamp = unique_urls.get(raw_url)
                should_update, new_timestamp = is_file_updated(repo, path, existing_timestamp)
                if not should_update and existing_timestamp:
                    print(f"调试: 跳过未更新的 URL: {raw_url}")
                    continue

                # 获取文件内容
                file_content = get_file_content(repo, path, branch)
                if not file_content:
                    continue

                # 测试 URL 连通性
                if await test_url_connection(raw_url):
                    unique_urls[raw_url] = new_timestamp or datetime.now(timezone.utc).astimezone(timezone(timedelta(hours=8))).isoformat()
                    print(f"调试: URL {raw_url} 可连通，时间戳: {unique_urls[raw_url]}")
                else:
                    print(f"调试: URL {raw_url} 不可连通，跳过")
                    continue

                # 处理文件内容
                lines = file_content.splitlines()
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue

                    # 尝试递归解析 Base64
                    decoded = recursive_decode_base64(line)
                    if decoded != line:
                        sub_lines = decoded.splitlines()
                        for sub_line in sub_lines:
                            sub_line = sub_line.strip()
                            if not sub_line:
                                continue
                            is_node = any(sub_line.startswith(protocol) for protocol in NODE_PROTOCOLS)
                            if is_node:
                                cleaned_node = clean_node(sub_line)
                                if cleaned_node not in unique_nodes and await test_node_connection(cleaned_node):
                                    unique_nodes.add(cleaned_node)
                                    print(f"调试: 添加节点: {cleaned_node}")

                    # 检查是否为节点链接
                    is_node = any(line.startswith(protocol) for protocol in NODE_PROTOCOLS)
                    if is_node:
                        cleaned_node = clean_node(line)
                        if cleaned_node not in unique_nodes and await test_node_connection(cleaned_node):
                            unique_nodes.add(cleaned_node)
                            print(f"调试: 添加节点: {cleaned_node}")

                    # 尝试解析 YAML 或 JSON
                    config_data = parse_config(line)
                    if config_data and isinstance(config_data, dict):
                        proxies = (config_data.get("proxies", []) or 
                                  config_data.get("servers", []) or 
                                  config_data.get("nodes", []) or 
                                  config_data.get("outbounds", []) or 
                                  config_data.get("proxy-groups", []))
                        for proxy in proxies:
                            if isinstance(proxy, dict):
                                node = None
                                proxy_type = proxy.get("type") or proxy.get("protocol")
                                server = proxy.get("server")
                                port = proxy.get("port")
                                if server and port:
                                    if proxy_type in ["ss", "shadowsocks"]:
                                        node = f"ss://{proxy.get('cipher')}:{proxy.get('password')}@{server}:{port}"
                                    elif proxy_type == "vmess":
                                        vmess_data = {
                                            "v": "2",
                                            "add": server,
                                            "port": port,
                                            "id": proxy.get("uuid"),
                                            "aid": proxy.get("alterId", 0),
                                            "type": "none"
                                        }
                                        node = f"vmess://{base64.b64encode(json.dumps(vmess_data).encode('utf-8')).decode('utf-8')}"
                                    elif proxy_type == "trojan":
                                        node = f"trojan://{proxy.get('password')}@{server}:{port}"
                                    elif proxy_type in ["hysteria2", "hy2"]:
                                        node = f"hy2://{proxy.get('password')}@{server}:{port}"
                                    elif proxy_type == "vless":
                                        node = f"vless://{proxy.get('uuid')}@{server}:{port}"
                                    elif proxy_type == "socks5":
                                        node = f"socks5://{proxy.get('username', '')}:{proxy.get('password', '')}@{server}:{port}"
                                    elif proxy_type == "wireguard":
                                        node = f"wg://{server}:{port}"
                                    if node and clean_node(node) not in unique_nodes and await test_node_connection(clean_node(node)):
                                        unique_nodes.add(clean_node(node))
                                        print(f"调试: 添加 YAML/JSON 节点: {clean_node(node)}")
                        # 检查根节点
                        if not proxies and (server := config_data.get("server")) and (port := config_data.get("port")):
                            proxy_type = config_data.get("type") or config_data.get("protocol")
                            if proxy_type in ["ss", "shadowsocks"]:
                                node = f"ss://{config_data.get('cipher')}:{config_data.get('password')}@{server}:{port}"
                                if node and clean_node(node) not in unique_nodes and await test_node_connection(clean_node(node)):
                                    unique_nodes.add(clean_node(node))
                                    print(f"调试: 添加根节点: {clean_node(node)}")

    # 保存结果
    save_results()
    print(f"处理完成！节点保存到 {NODES_FILE}，URL 和时间戳保存到 {URLS_FILE}")

# 运行异步主函数
if __name__ == "__main__":
    asyncio.run(main())
