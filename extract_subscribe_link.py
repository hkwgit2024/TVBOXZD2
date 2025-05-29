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
from urllib.parse import urlparse

# 配置
GITHUB_API_URL = "https://api.github.com/search/code"
TOKEN = os.getenv("BOT")
if not TOKEN:
    print("错误: 环境变量 BOT 未设置")
    exit(1)
HEADERS = {
    "Authorization": f"token {TOKEN}",
    "Accept": "application/vnd.github.v3+json"
}
# 扩展搜索关键词
SEARCH_QUERY = "v2ray shadowsocks trojan hysteria hy2 ssr clash vless wireguard socks5 http https proxy vpn shadowsocksr free server relay tunnel config subscription proxies nodes"
OUTPUT_DIR = "data"
NODES_FILE = os.path.join(OUTPUT_DIR, "hy2.txt")
URLS_FILE = os.path.join(OUTPUT_DIR, "url.txt")
# 扩展节点协议
NODE_PROTOCOLS = ["ss://", "vmess://", "trojan://", "hy2://", "ssr://", "vless://", "http://", "https://", "socks5://", "wg://"]

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
    return unique_urls

# 检查文件是否更新
def is_file_updated(repo, path, existing_timestamp):
    commit_url = f"https://api.github.com/repos/{repo}/commits?path={path}&per_page=1"
    try:
        response = requests.get(commit_url, headers=HEADERS)
        if response.status_code == 200 and response.json():
            commit_date = response.json()[0]["commit"]["committer"]["date"]
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
                elif protocol == "wg://":
                    # WireGuard 通常不使用 HTTP 测试，跳过连通性测试
                    return True
                else:
                    match = re.match(r"(ss|trojan|hy2|ssr|socks5)://[^@]+@([^:]+):(\d+)", node)
                    if match:
                        host, port = match.group(2), int(match.group(3))
                    else:
                        return False
                if protocol not in ["http://", "https://", "wg://"]:
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

# 解析 YAML 内容
def parse_yaml(content):
    try:
        data = yaml.safe_load(content)
        return data
    except:
        return None

# 清理节点中的 # 后内容
def clean_node(node):
    return re.split(r"#", node)[0].strip()

# 获取文件内容
def get_file_content(repo, path):
    raw_url = f"https://raw.githubusercontent.com/{repo}/{path}"
    try:
        response = requests.get(raw_url)
        if response.status_code == 200:
            return response.text
        else:
            print(f"获取文件 {raw_url} 失败: {response.status_code}, {response.text}")
            return None
    except Exception as e:
        print(f"获取文件 {raw_url} 异常: {e}")
        return None

# 保存结果
def save_results():
    with open(NODES_FILE, "w", encoding="utf-8") as f:
        for node in unique_nodes:
            f.write(node + "\n")
    with open(URLS_FILE, "w", encoding="utf-8") as f:
        for url, timestamp in unique_urls.items():
            f.write(f"{url} | {timestamp}\n")

# 主逻辑
async def main():
    # 加载已有 URL 和时间戳
    load_existing_urls()

    # 搜索 GitHub
    params = {"q": SEARCH_QUERY, "per_page": 100}
    try:
        response = requests.get(GITHUB_API_URL, headers=HEADERS, params=params)
        if response.status_code != 200:
            print(f"GitHub API 请求失败: {response.status_code}, {response.text}")
            return
    except Exception as e:
        print(f"GitHub API 请求异常: {e}")
        return

    data = response.json()
    items = data.get("items", [])

    for item in items:
        repo = item["repository"]["full_name"]
        path = item["path"]
        raw_url = f"https://raw.githubusercontent.com/{repo}/{path}"

        # 检查是否需要更新
        existing_timestamp = unique_urls.get(raw_url)
        should_update, new_timestamp = is_file_updated(repo, path, existing_timestamp)
        if not should_update and existing_timestamp:
            continue

        # 获取文件内容
        file_content = get_file_content(repo, path)
        if not file_content:
            continue

        # 测试 URL 连通性
        if await test_url_connection(raw_url):
            unique_urls[raw_url] = new_timestamp or datetime.now(timezone.utc).astimezone(timezone(timedelta(hours=8))).isoformat()

        # 处理文件内容
        lines = file_content.splitlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # 尝试解析 Base64
            decoded = decode_base64(line)
            if decoded:
                line = decoded

            # 检查是否为节点链接
            is_node = any(line.startswith(protocol) for protocol in NODE_PROTOCOLS)
            if is_node:
                cleaned_node = clean_node(line)
                if cleaned_node not in unique_nodes and await test_node_connection(cleaned_node):
                    unique_nodes.add(cleaned_node)

            # 尝试解析 YAML
            yaml_data = parse_yaml(line)
            if yaml_data and isinstance(yaml_data, dict):
                proxies = yaml_data.get("proxies", [])
                for proxy in proxies:
                    if isinstance(proxy, dict):
                        node = None
                        proxy_type = proxy.get("type")
                        server = proxy.get("server")
                        port = proxy.get("port")
                        if server and port:
                            if proxy_type == "ss":
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
                            elif proxy_type == "hysteria2":
                                node = f"hy2://{proxy.get('password')}@{server}:{port}"
                            elif proxy_type == "vless":
                                node = f"vless://{proxy.get('uuid')}@{server}:{port}"
                            elif proxy_type == "socks5":
                                node = f"socks5://{proxy.get('username', '')}:{proxy.get('password', '')}@{server}:{port}"
                            elif proxy_type == "wireguard":
                                node = f"wg://{server}:{port}"
                            if node and clean_node(node) not in unique_nodes and await test_node_connection(clean_node(node)):
                                unique_nodes.add(clean_node(node))

    # 保存结果
    save_results()
    print(f"处理完成！节点保存到 {NODES_FILE}，URL 和时间戳保存到 {URLS_FILE}")

# 运行异步主函数
if __name__ == "__main__":
    asyncio.run(main())
