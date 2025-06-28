import os
import re
import base64
import json
import yaml
import time
import requests
import sys
from urllib.parse import urlparse, parse_qs, unquote, quote

# 节点下载 URL
NODE_URL = "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/success_count.txt"
# Mihomo Core 控制器地址
CLASH_CONTROLLER_URL = "http://127.0.0.1:9090"
# Mihomo Core SOCKS5 代理地址
CLASH_SOCKS5_PROXY = "socks5://127.0.0.1:7891"
# Mihomo Core 配置文件路径
CLASH_CONFIG_PATH = "config.yaml"
# 保存成功节点的路径
SUCCESS_NODES_PATH = "data/all.txt"

def clean_proxy_name(name):
    """清理代理名称，移除或替换特殊字符，确保其适合作为YAML键和API参数"""
    # 替换所有非字母、数字、点、横线的字符为单个下划线
    cleaned_name = re.sub(r'[^\w.-]+', '_', name)
    # 移除连续的下划线，替换为单个下划线
    cleaned_name = re.sub(r'_+', '_', cleaned_name)
    # 移除开头和结尾的下划线
    cleaned_name = cleaned_name.strip('_')
    # 确保名称以字母或数字开头
    if not cleaned_name or not cleaned_name[0].isalnum():
        cleaned_name = 'proxy_' + cleaned_name
    # 限制名称长度
    cleaned_name = cleaned_name[:64]
    return cleaned_name

def parse_vmess(link):
    """解析 vmess 链接为 Clash 格式"""
    try:
        encoded_str = link.replace("vmess://", "")
        try:
            decoded_bytes = base64.b64decode(encoded_str)
        except Exception:
            decoded_bytes = base64.urlsafe_b64decode(encoded_str + "=" * ((4 - len(encoded_str) % 4) % 4))
        
        config = json.loads(decoded_bytes.decode('utf-8'))
        
        name = unquote(config.get("ps", f"vmess_{config.get('add', 'unknown')}"))
        name = clean_proxy_name(name)
        
        proxy = {
            "name": name,
            "type": "vmess",
            "server": config.get("add"),
            "port": int(config.get("port")),
            "uuid": config.get("id"),
            "alterId": int(config.get("aid", 0)),
            "cipher": config.get("scy", "auto"),
            "network": config.get("net", "tcp"),
        }

        if config.get("tls", "") == "tls":
            proxy["tls"] = True
            proxy["skip-cert-verify"] = config.get("allowInsecure", False)
            proxy["servername"] = config.get("sni", config.get("host", ""))

        if proxy["network"] == "ws":
            proxy["ws-opts"] = {
                "path": config.get("path", "/"),
                "headers": {"Host": config.get("host", "")}
            }
        
        return proxy
    except Exception as e:
        print(f"Error parsing vmess link '{link}': {e}")
        return None

def parse_trojan(link):
    """解析 trojan 链接为 Clash 格式"""
    match = re.match(r"trojan://([^@]+)@([^:]+):(\d+)(.*)", link)
    if match:
        password = match.group(1)
        server = match.group(2)
        port = int(match.group(3))
        
        name_match = re.search(r"#([^#&]+)", link)
        name = unquote(name_match.group(1)) if name_match else f"trojan_{server}"
        name = clean_proxy_name(name)

        parsed_url = urlparse(link)
        query_params = parse_qs(parsed_url.query)
        sni = query_params.get('sni', [None])[0]
        alpn = query_params.get('alpn', [None])[0]

        trojan_config = {
            "name": name,
            "type": "trojan",
            "server": server,
            "port": port,
            "password": password
        }
        if sni:
            trojan_config["sni"] = sni
        if alpn:
            trojan_config["alpn"] = [alpn]
        
        return trojan_config
    return None

def parse_ss(link):
    """解析 ss 链接为 Clash 格式"""
    try:
        link_parts = link.replace("ss://", "").split('#', 1)
        encoded_part = link_parts[0]
        
        encoded_part += "=" * ((4 - len(encoded_part) % 4) % 4)
        try:
            decoded_bytes = base64.urlsafe_b64decode(encoded_part)
        except Exception as e:
            print(f"Error decoding ss link Base64 '{link}': {e}")
            return None
        
        decoded_str = decoded_bytes.decode('utf-8')
        
        parts = decoded_str.split('@')
        if len(parts) != 2:
            print(f"Invalid ss link format '{link}'")
            return None
        
        auth_part = parts[0]
        server_port_part = parts[1]

        try:
            method, password = auth_part.split(':', 1)
            server, port = server_port_part.rsplit(':', 1)
        except ValueError as e:
            print(f"Error parsing ss link components '{link}': {e}")
            return None

        name = unquote(link_parts[1]) if len(link_parts) > 1 else f"ss_{server}"
        name = clean_proxy_name(name)

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
    """解析 hysteria2 链接为 Clash 格式"""
    link = link.replace("hy2://", "hysteria2://")
    
    match = re.match(r"hysteria2://([^@]+)@([^:]+):(\d+)(\?.*)?(#(.*))?", link)
    if match:
        password = match.group(1)
        server = match.group(2)
        port = int(match.group(3))
        query_string = match.group(4) if match.group(4) else ""
        
        name = unquote(match.group(6)) if match.group(6) else f"hysteria2_{server}"
        name = clean_proxy_name(name)

        params = {}
        if query_string:
            for param in query_string[1:].split('&'):
                if '=' in param:
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
            "down": int(params.get("down", 0)),
            "up": int(params.get("up", 0)),
            "alpn": [params.get("alpn")] if params.get("alpn") else None,
            "tls": True,
            "skip-cert-verify": params.get("insecure") == "1",
            "sni": params.get("sni")
        }
    return None

def parse_vless(link):
    """解析 vless 链接为 Clash 格式"""
    match = re.match(r"vless://([^@]+)@([^:]+):(\d+)(\?.*)?(#(.*))?", link)
    if match:
        uuid = match.group(1)
        server = match.group(2)
        port = int(match.group(3))
        query_string = match.group(4) if match.group(4) else ""
        
        name = unquote(match.group(6)) if match.group(6) else f"vless_{server}"
        name = clean_proxy_name(name)

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
            "udp": True,
        }

        if vless_config["tls"]:
            vless_config["servername"] = params.get("sni", "")
            vless_config["skip-cert-verify"] = params.get("allowInsecure") == "1"

        if params.get("security") == "reality":
            vless_config["reality-opts"] = {
                "public-key": params.get("pbk", ""),
                "short-id": params.get("sid", ""),
                "fingerprint": params.get("fp", ""),
                "dest": params.get("dest", "")
            }
            vless_config["servername"] = params.get("sni", "")
            vless_config["tls"] = True

        if vless_config["network"] == "ws":
            vless_config["ws-opts"] = {
                "path": params.get("path", "/"),
                "headers": {"Host": params.get("host", "")}
            }
            if vless_config["tls"] and not vless_config.get("servername") and vless_config["ws-opts"]["headers"].get("Host"):
                vless_config["servername"] = vless_config["ws-opts"]["headers"]["Host"]
        
        if vless_config["network"] == "grpc":
            vless_config["grpc-opts"] = {
                "service-name": params.get("serviceName", "")
            }
            
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
    elif link.startswith("hysteria2://") or link.startswith("hy2://"):
        return parse_hysteria2(link)
    elif link.startswith("vless://"):
        return parse_vless(link)
    elif link.startswith("ssr://"):
        print(f"Skipping SSR link (complex parsing not implemented for Clash Core): {link}")
        return None
    else:
        print(f"Unknown protocol or invalid link: {link}")
        return None

def generate_clash_config(parsed_nodes):
    """生成 Mihomo Core 配置文件"""
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
                "name": "GLOBAL",
                "type": "select",
                "proxies": ["DIRECT"]
            },
            {
                "name": "Node Select",
                "type": "select",
                "proxies": ["DIRECT"]
            },
            {
                "name": "Auto Select",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "proxies": ["DIRECT"]
            }
        ],
        "rules": [
            "PROCESS-NAME,clash,GLOBAL",
            "PROCESS-NAME,Clash,GLOBAL",
            "PROCESS-NAME,clash-core,GLOBAL",
            "DOMAIN-SUFFIX,googlevideo.com,GLOBAL",
            "DOMAIN-SUFFIX,googleusercontent.com,GLOBAL",
            "DOMAIN-SUFFIX,google.com,GLOBAL",
            "DOMAIN-SUFFIX,github.com,DIRECT",
            "MATCH,GLOBAL"
        ]
    }

    proxy_names = []
    for node in parsed_nodes:
        if node:
            config["proxies"].append(node)
            proxy_names.append(node["name"])
    
    config["proxy-groups"][0]["proxies"].extend(proxy_names)
    config["proxy-groups"][1]["proxies"].extend(proxy_names)
    config["proxy-groups"][2]["proxies"].extend(proxy_names)

    with open(CLASH_CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)
    print(f"Generated Clash config: {CLASH_CONFIG_PATH} with {len(parsed_nodes)} nodes.")

def test_nodes(original_links_map):
    """测试节点连通性"""
    successful_nodes = []
    
    try:
        with open(CLASH_CONFIG_PATH, "r", encoding="utf-8") as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"Error: {CLASH_CONFIG_PATH} not found. Ensure generate_clash_config ran successfully.")
        return []
    except yaml.YAMLError as e:
        print(f"Error parsing {CLASH_CONFIG_PATH}: {e}")
        return []

    proxies = config.get("proxies", [])
    if not proxies:
        print("No proxies found in the generated Clash config. Skipping node testing.")
        return []

    main_proxy_group_to_switch = "GLOBAL"

    try:
        response = requests.get(f"{CLASH_CONTROLLER_URL}/proxies", timeout=5)
        response.raise_for_status()
        available_proxies_info = response.json().get("proxies", {})
        if main_proxy_group_to_switch not in available_proxies_info:
            print(f"Error: Main proxy group '{main_proxy_group_to_switch}' not found in Mihomo API response.")
            print(f"Available proxy groups: {list(available_proxies_info.keys())}")
            sys.exit(1)
        print(f"Using main proxy group for switching: '{main_proxy_group_to_switch}'.")
    except requests.exceptions.RequestException as e:
        print(f"Error: Failed to connect to Mihomo API to get proxy groups. Please check Mihomo status. Error: {e}")
        sys.exit(1)
    
    print(f"Starting connectivity test for {len(proxies)} nodes...")

    for i, proxy in enumerate(proxies):
        proxy_name = proxy["name"]
        print(f"[{i+1}/{len(proxies)}] Testing node: '{proxy_name}'...")
        try:
            switched_successfully = False
            for attempt in range(1, 6):
                try:
                    response = requests.put(
                        f"{CLASH_CONTROLLER_URL}/proxies/{quote(main_proxy_group_to_switch)}",
                        json={"name": proxy_name},
                        timeout=5
                    )
                    response.raise_for_status()
                    print(f"  Switched main group '{main_proxy_group_to_switch}' to node '{proxy_name}' (Attempt {attempt}).")
                    switched_successfully = True
                    break
                except requests.exceptions.RequestException as e:
                    print(f"  Failed to switch main group to node '{proxy_name}' (Attempt {attempt}/5). Error: {e}")
                    time.sleep(2)

            if not switched_successfully:
                print(f"❌ Failed to switch to node '{proxy_name}' after multiple retries. Skipping test for this node.")
                continue

            time.sleep(1)

            test_success = False
            for test_attempt in range(1, 4):
                try:
                    test_response = requests.get(
                        "http://www.gstatic.com/generate_204",
                        proxies={"http": CLASH_SOCKS5_PROXY, "https": CLASH_SOCKS5_PROXY},
                        timeout=20
                    )
                    test_response.raise_for_status()
                    print(f"✅ Node '{proxy_name}' is working (Test Attempt {test_attempt}).")
                    test_success = True
                    break
                except requests.exceptions.Timeout:
                    print(f"  Node '{proxy_name}' timed out (Test Attempt {test_attempt}/3).")
                except requests.exceptions.RequestException as e:
                    print(f"  Node '{proxy_name}' failed (Test Attempt {test_attempt}/3). Error: {e}")
                time.sleep(3)

            if test_success:
                if proxy_name in original_links_map:
                    successful_nodes.append(original_links_map[proxy_name])
                else:
                    print(f"Warning: Could not find original link for proxy name '{proxy_name}'. Skipping.")
            else:
                print(f"❌ Node '{proxy_name}' is NOT working after all attempts.")
                
        except Exception as e:
            print(f"An unexpected error occurred during testing node '{proxy_name}': {e}")
            
    return successful_nodes

def main():
    print(f"Downloading nodes from {NODE_URL}...")
    try:
        response = requests.get(NODE_URL, timeout=10)
        response.raise_for_status()
        node_links = response.text.strip().split('\n')
        node_links = [link.strip() for link in node_links if link.strip()]
        print(f"Downloaded {len(node_links)} nodes.")
    except requests.exceptions.RequestException as e:
        print(f"Error downloading nodes: {e}")
        sys.exit(1)

    if not node_links:
        print("No nodes found in the downloaded file. Exiting.")
        sys.exit(0)

    parsed_nodes = []
    original_links_map = {}
    for i, link in enumerate(node_links):
        parsed = parse_node_link(link)
        if parsed:
            original_name = parsed.get("name", f"unknown_node_{i}")
            unique_name = original_name
            count = 1
            while unique_name in [p["name"] for p in parsed_nodes]:
                unique_name = f"{original_name}_{count}"
                count += 1
            
            parsed["name"] = unique_name
            parsed_nodes.append(parsed)
            original_links_map[unique_name] = link
    
    if not parsed_nodes:
        print("No valid nodes parsed. Exiting.")
        sys.exit(0)

    generate_clash_config(parsed_nodes)

    successful_nodes = test_nodes(original_links_map)

    os.makedirs(os.path.dirname(SUCCESS_NODES_PATH), exist_ok=True)
    with open(SUCCESS_NODES_PATH, "w", encoding="utf-8") as f:
        for node_link in successful_nodes:
            f.write(f"{node_link}\n")
    print(f"Successfully saved {len(successful_nodes)} working nodes to {SUCCESS_NODES_PATH}")

if __name__ == "__main__":
    main()
