import os
import re
import base64
import json
import yaml
import time
import requests
import sys
from urllib.parse import urlparse, parse_qs, unquote # 导入 unquote

# 节点下载 URL
NODE_URL = "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/success_count.txt"
# Mihomo 控制器地址
MIHOMO_CONTROLLER_URL = "http://127.0.0.1:9090"
# Mihomo Socks5 代理地址
MIHOMO_SOCKS5_PROXY = "socks5h://127.0.0.1:7891"
# Mihomo 配置文件路径
MIHOMO_CONFIG_PATH = "config.yaml"
# 成功节点保存路径
SUCCESS_NODES_PATH = "data/all.txt"

def parse_vmess(link):
    """解析 vmess 链接"""
    try:
        encoded_str = link.replace("vmess://", "")
        # vmess 链接是 base64(json) 格式，但有时不是标准 base64
        # 尝试标准 base64 解码，如果失败则尝试 urlsafe 解码
        try:
            decoded_bytes = base64.b64decode(encoded_str)
        except Exception:
            decoded_bytes = base64.urlsafe_b64decode(encoded_str + "=" * ((4 - len(encoded_str) % 4) % 4))
        
        config = json.loads(decoded_bytes.decode('utf-8'))
        
        # 解码节点名称中的URL编码
        name = unquote(config.get("ps", f"vmess_{config.get('add', 'unknown')}"))
        
        return {
            "name": name,
            "type": "vmess",
            "server": config.get("add"),
            "port": int(config.get("port")),
            "uuid": config.get("id"),
            "alterId": int(config.get("aid", 0)),
            "security": config.get("scy", "auto"),
            "network": config.get("net", "tcp"),
            "tls": config.get("tls", "") == "tls",
            "sni": config.get("sni", ""),
            "ws-path": config.get("path", ""),
            "ws-headers": {"Host": config.get("host", "")}
        }
    except Exception as e:
        print(f"Error parsing vmess link '{link}': {e}")
        return None

def parse_trojan(link):
    """解析 trojan 链接"""
    # trojan://password@server:port?params#name
    match = re.match(r"trojan://([^@]+)@([^:]+):(\d+)(.*)", link)
    if match:
        password = match.group(1)
        server = match.group(2)
        port = int(match.group(3))
        
        # 解析 # 后面的名称
        name_match = re.search(r"#([^#&]+)", link)
        name = unquote(name_match.group(1)) if name_match else f"trojan_{server}"

        # 进一步解析查询参数，例如 sni
        parsed_url = urlparse(link)
        query_params = parse_qs(parsed_url.query)
        sni = query_params.get('sni', [None])[0]

        trojan_config = {
            "name": name,
            "type": "trojan",
            "server": server,
            "port": port,
            "password": password
        }
        if sni:
            trojan_config["sni"] = sni
            trojan_config["tls"] = True # trojan 默认带 tls

        return trojan_config
    return None

def parse_ss(link):
    """解析 ss 链接"""
    try:
        # ss://base64(method:password@server:port)#name
        # 移除非编码部分的名称
        link_parts = link.replace("ss://", "").split('#', 1)
        encoded_part = link_parts[0]
        
        # 尝试鲁棒的 Base64 解码，处理非标准填充
        decoded_bytes = base64.urlsafe_b64decode(encoded_part + "=" * ((4 - len(encoded_part) % 4) % 4))
        decoded_str = decoded_bytes.decode('utf-8')
        
        parts = decoded_str.split('@')
        if len(parts) == 2:
            auth_part = parts[0]
            server_port_part = parts[1]

            method, password = auth_part.split(':', 1)
            server, port = server_port_part.rsplit(':', 1)

            # 提取名称，并进行URL解码
            name = unquote(link_parts[1]) if len(link_parts) > 1 else f"ss_{server}"

            return {
                "name": name,
                "type": "ss",
                "server": server,
                "port": int(port),
                "cipher": method,
                "password": password
            }
    except Exception as e:
        print(f"Error parsing ss link '{link}': {e}")
    return None

def parse_hysteria2(link):
    """解析 hysteria2 链接"""
    # 允许 hy2:// 或 hysteria2://
    link = link.replace("hy2://", "hysteria2://") 
    
    # hysteria2://password@server:port?obfs=obfs_name&obfs-password=obfs_pass#name
    match = re.match(r"hysteria2://([^@]+)@([^:]+):(\d+)(\?.*)?(#(.*))?", link)
    if match:
        password = match.group(1)
        server = match.group(2)
        port = int(match.group(3))
        query_string = match.group(4) if match.group(4) else ""
        
        # 解码名称
        name = unquote(match.group(6)) if match.group(6) else f"hysteria2_{server}"

        params = {}
        if query_string:
            for param in query_string[1:].split('&'):
                if '=' in param: # 确保参数是键值对
                    key, value = param.split('=', 1)
                    params[key] = value
        
        return {
            "name": name,
            "type": "hysteria2",
            "server": server,
            "port": port,
            "password": password,
            "obfs": params.get("obfs"),
            "obfs-password": params.get("obfs-password"),
            "up": int(params.get("up", 0)),
            "down": int(params.get("down", 0)),
            "alpn": params.get("alpn"),
            "tls": params.get("insecure") != "1", # insecure=1 表示不安全
            "sni": params.get("sni")
        }
    return None

def parse_vless(link):
    """解析 vless 链接"""
    # vless://UUID@SERVER:PORT?params#NAME
    match = re.match(r"vless://([^@]+)@([^:]+):(\d+)(\?.*)?(#(.*))?", link)
    if match:
        uuid = match.group(1)
        server = match.group(2)
        port = int(match.group(3))
        query_string = match.group(4) if match.group(4) else ""
        
        # 解码名称
        name = unquote(match.group(6)) if match.group(6) else f"vless_{server}"

        params = {}
        if query_string:
            for param in query_string[1:].split('&'):
                if '=' in param:
                    key, value = param.split('=', 1)
                    params[key] = value

        vless_config = {
            "name": name,
            "type": "vless",
            "server": server,
            "port": port,
            "uuid": uuid,
            "network": params.get("type", "tcp"),
            "tls": params.get("security", "") == "tls",
            "flow": params.get("flow", ""),
            "udp": True # VLESS通常支持UDP
        }

        if params.get("security") == "reality":
            vless_config["reality-opts"] = {
                "dest": params.get("dest", ""), # dest = host:port
                "xver": int(params.get("xver", 0)),
                "sni": params.get("sni", ""),
                "fingerprint": params.get("fp", ""), # reality fingerprint
                "publicKey": params.get("pbk", "") # reality public key
            }
        
        # WebSocket settings
        if vless_config["network"] == "ws":
            vless_config["ws-path"] = params.get("path", "")
            vless_config["ws-headers"] = {"Host": params.get("host", "")}
        
        return vless_config
    return None


def parse_node_link(link):
    """根据协议类型解析节点链接"""
    if link.startswith("vmess://"):
        return parse_vmess(link)
    elif link.startswith("trojan://"):
        return parse_trojan(link)
    elif link.startswith("ss://"):
        return parse_ss(link)
    elif link.startswith("hysteria2://") or link.startswith("hy2://"): # 兼容 hy2://
        return parse_hysteria2(link)
    elif link.startswith("vless://"):
        return parse_vless(link)
    # TODO: 添加 SSR 解析逻辑，SSR 通常需要更复杂的解析库
    elif link.startswith("ssr://"):
        print(f"Skipping SSR link (complex parsing not implemented): {link}")
        return None
    else:
        print(f"Unknown protocol or invalid link: {link}")
        return None

def generate_mihomo_config(parsed_nodes):
    """生成 Mihomo 配置文件"""
    config = {
        "port": 7890,
        "socks-port": 7891,
        "redir-port": 7892,
        "tproxy-port": 7893,
        "mixed-port": 7890,
        "mode": "rule",
        "log-level": "info",
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "external-controller": "127.0.0.1:9090",
        "dns": {
            "enable": True,
            "listen": "0.0.0.0:53",
            "default-nameserver": ["114.114.114.114", "8.8.8.8"],
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "use-hosts": True,
            "fallback": ["tls://1.1.1.1:853", "tls://8.8.8.8:853"],
            "fallback-filter": {
                "geoip": True,
                "ipcidr": ["240.0.0.0/4"]
            }
        },
        "proxies": [],
        "proxy-groups": [
            {
                "name": "🔰 节点选择",
                "type": "select",
                "proxies": ["DIRECT"]
            }
        ],
        "rules": ["MATCH,🔰 节点选择"]
    }

    proxy_names = []
    for node in parsed_nodes:
        if node: # 确保节点解析成功
            config["proxies"].append(node)
            proxy_names.append(node["name"])
    
    # 将所有解析出的代理添加到节点选择组中
    config["proxy-groups"][0]["proxies"].extend(proxy_names)

    with open(MIHOMO_CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)
    print(f"Generated Mihomo config: {MIHOMO_CONFIG_PATH}")

def test_nodes(original_links_map):
    """测试节点连接"""
    successful_nodes = []
    
    # 从生成的配置中读取代理名称
    with open(MIHOMO_CONFIG_PATH, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    
    proxies = config.get("proxies", [])
    
    print("Starting node testing...")
    for proxy in proxies:
        proxy_name = proxy["name"]
        
        print(f"Testing node: {proxy_name}...")
        try:
            # 切换 Mihomo 代理
            # 确保 Mihomo 控制器是可达的，增加重试机制
            for _ in range(3): # 尝试3次连接 Mihomo API
                try:
                    response = requests.put(
                        f"{MIHOMO_CONTROLLER_URL}/proxies/%E2%9C%A8%20%E8%8A%82%E7%82%B9%E9%80%89%E6%8B%A9",
                        json={"name": proxy_name},
                        timeout=5
                    )
                    response.raise_for_status()
                    break # 成功连接并切换，跳出重试循环
                except requests.exceptions.ConnectionError:
                    print(f"Connection to Mihomo controller refused, retrying...")
                    time.sleep(2) # 等待一段时间再重试
            else:
                raise ConnectionError("Failed to connect to Mihomo controller after multiple retries.")
            
            time.sleep(1) # 等待代理切换

            # 使用 Mihomo 代理测试 Google
            test_response = requests.get(
                "https://www.google.com",
                proxies={"http": MIHOMO_SOCKS5_PROXY, "https": MIHOMO_SOCKS5_PROXY},
                timeout=10
            )
            test_response.raise_for_status()
            print(f"✅ Node '{proxy_name}' is working.")
            
            # 找到原始链接并保存
            if proxy_name in original_links_map:
                successful_nodes.append(original_links_map[proxy_name])
            else:
                print(f"Warning: Could not find original link for proxy name '{proxy_name}' in map. Skipping.")
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Node '{proxy_name}' is NOT working. Error: {e}")
        except Exception as e:
            print(f"An unexpected error occurred during testing node '{proxy_name}': {e}")
            
    return successful_nodes

def main():
    # 1. 下载节点
    print(f"Downloading nodes from {NODE_URL}...")
    try:
        response = requests.get(NODE_URL, timeout=10)
        response.raise_for_status() # 检查 HTTP 错误
        node_links = response.text.strip().split('\n')
        node_links = [link.strip() for link in node_links if link.strip()] # 过滤空行
        print(f"Downloaded {len(node_links)} nodes.")
    except requests.exceptions.RequestException as e:
        print(f"Error downloading nodes: {e}")
        sys.exit(1)

    if not node_links:
        print("No nodes found in the downloaded file. Exiting.")
        sys.exit(0)

    # 2. 解析节点
    parsed_nodes = []
    original_links_map = {} # 用于存储代理名称到原始链接的映射
    for i, link in enumerate(node_links):
        parsed = parse_node_link(link)
        if parsed:
            # 确保名称唯一
            original_name_for_map = parsed["name"] # 用原始解析的名称作为key
            unique_name_for_mihomo_config = original_name_for_map
            count = 1
            while unique_name_for_mihomo_config in [p["name"] for p in parsed_nodes]:
                unique_name_for_mihomo_config = f"{original_name_for_map}_{count}"
                count += 1
            
            parsed["name"] = unique_name_for_mihomo_config
            
            parsed_nodes.append(parsed)
            # 这里的 original_links_map 应该存储的是 Mihomo 配置中的唯一名称到原始链接的映射
            original_links_map[unique_name_for_mihomo_config] = link
    
    if not parsed_nodes:
        print("No valid nodes parsed. Exiting.")
        sys.exit(0)

    # 3. 生成 Mihomo 配置
    generate_mihomo_config(parsed_nodes)

    # 4. 启动 Mihomo (在 GitHub Actions 中由外部脚本启动)
    # 此脚本仅负责生成配置和测试，Mihomo 的启动和停止由 GH Actions 工作流处理

    # 5. 测试节点
    successful_nodes = test_nodes(original_links_map)

    # 6. 保存成功节点
    os.makedirs(os.path.dirname(SUCCESS_NODES_PATH), exist_ok=True)
    with open(SUCCESS_NODES_PATH, "w", encoding="utf-8") as f:
        for node_link in successful_nodes:
            f.write(f"{node_link}\n")
    print(f"Successfully saved {len(successful_nodes)} working nodes to {SUCCESS_NODES_PATH}")

if __name__ == "__main__":
    main()
