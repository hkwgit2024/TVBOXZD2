import os
import re
import base64
import json
import yaml
import time
import requests
import sys
from urllib.parse import urlparse, parse_qs, unquote, quote

# Node download URL
NODE_URL = "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/success_count.txt"
# Clash Core controller address
CLASH_CONTROLLER_URL = "http://127.0.0.1:9090"
# Clash Core Socks5 proxy address
CLASH_SOCKS5_PROXY = "socks5://127.0.0.1:7891"
# Clash Core config file path
CLASH_CONFIG_PATH = "config.yaml"
# Path to save successful nodes
SUCCESS_NODES_PATH = "data/all.txt"

def parse_vmess(link):
    """Parse vmess link for Clash format"""
    try:
        encoded_str = link.replace("vmess://", "")
        try:
            decoded_bytes = base64.b64decode(encoded_str)
        except Exception:
            decoded_bytes = base64.urlsafe_b64decode(encoded_str + "=" * ((4 - len(encoded_str) % 4) % 4))
        
        config = json.loads(decoded_bytes.decode('utf-8'))
        
        name = unquote(config.get("ps", f"vmess_{config.get('add', 'unknown')}"))
        
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
    """Parse trojan link for Clash format"""
    match = re.match(r"trojan://([^@]+)@([^:]+):(\d+)(.*)", link)
    if match:
        password = match.group(1)
        server = match.group(2)
        port = int(match.group(3))
        
        name_match = re.search(r"#([^#&]+)", link)
        name = unquote(name_match.group(1)) if name_match else f"trojan_{server}"

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
    """Parse ss link for Clash format"""
    try:
        link_parts = link.replace("ss://", "").split('#', 1)
        encoded_part = link_parts[0]
        
        # Ensure proper padding for Base64 decoding
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
    """Parse hysteria2 link for Clash format"""
    link = link.replace("hy2://", "hysteria2://") 
    
    match = re.match(r"hysteria2://([^@]+)@([^:]+):(\d+)(\?.*)?(#(.*))?", link)
    if match:
        password = match.group(1)
        server = match.group(2)
        port = int(match.group(3))
        query_string = match.group(4) if match.group(4) else ""
        
        name = unquote(match.group(6)) if match.group(6) else f"hysteria2_{server}"

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
    """Parse vless link for Clash format"""
    match = re.match(r"vless://([^@]+)@([^:]+):(\d+)(\?.*)?(#(.*))?", link)
    if match:
        uuid = match.group(1)
        server = match.group(2)
        port = int(match.group(3))
        query_string = match.group(4) if match.group(4) else ""
        
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
    """Parse node link based on protocol type"""
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
    """Generate Clash Core configuration file"""
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
                "name": "Node Select",
                "type": "select",
                "proxies": ["DIRECT"]
            },
            {
                "name": "Auto Select",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "proxies": []
            }
        ],
        "rules": [
            "PROCESS-NAME,clash,DIRECT",
            "PROCESS-NAME,Clash,DIRECT",
            "PROCESS-NAME,clash-core,DIRECT",
            "DOMAIN-SUFFIX,googlevideo.com,Node Select",
            "DOMAIN-SUFFIX,googleusercontent.com,Node Select",
            "DOMAIN-SUFFIX,google.com,Node Select",
            "DOMAIN-SUFFIX,github.com,DIRECT",
            "MATCH,Node Select"
        ]
    }

    proxy_names = []
    for node in parsed_nodes:
        if node:
            config["proxies"].append(node)
            proxy_names.append(node["name"])
    
    config["proxy-groups"][0]["proxies"].extend(proxy_names)
    config["proxy-groups"][1]["proxies"].extend(proxy_names)

    with open(CLASH_CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)
    print(f"Generated Clash config: {CLASH_CONFIG_PATH}")

def test_nodes(original_links_map):
    """Test node connectivity"""
    successful_nodes = []
    
    with open(CLASH_CONFIG_PATH, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    
    proxies = config.get("proxies", [])
    proxy_group = next((group for group in config.get("proxy-groups", []) if group["type"] == "select"), None)
    if not proxy_group:
        print("Error: No select-type proxy group found in config.")
        sys.exit(1)
    proxy_group_name = proxy_group["name"]
    
    # Debug: List available proxy groups
    try:
        response = requests.get(f"{CLASH_CONTROLLER_URL}/proxies", timeout=5)
        response.raise_for_status()
        available_groups = response.json().get("proxies", {})
        print(f"Available proxy groups: {list(available_groups.keys())}")
    except requests.exceptions.RequestException as e:
        print(f"Error: Failed to connect to Mihomo API: {e}")
        sys.exit(1)

    print(f"Using proxy group: {proxy_group_name}")
    print("Starting node testing...")
    for proxy in proxies:
        proxy_name = proxy["name"]
        
        print(f"Testing node: {proxy_name}...")
        try:
            # Switch to the current node
            for _ in range(5):
                try:
                    response = requests.put(
                        f"{CLASH_CONTROLLER_URL}/proxies/{quote(proxy_group_name)}",
                        json={"name": proxy_name},
                        timeout=5
                    )
                    response.raise_for_status()
                    print(f"Switched to node: {proxy_name}")
                    break
                except requests.exceptions.RequestException as e:
                    print(f"Connection to Mihomo controller failed for {proxy_name}, retrying... Error: {e}")
                    time.sleep(2)
            else:
                raise ConnectionError(f"Failed to switch to node {proxy_name} after multiple retries.")
            
            time.sleep(1)

            # Test connectivity
            test_response = requests.get(
                "http://www.gstatic.com/generate_204",
                proxies={"http": CLASH_SOCKS5_PROXY, "https": CLASH_SOCKS5_PROXY},
                timeout=15
            )
            test_response.raise_for_status()
            print(f"✅ Node '{proxy_name}' is working.")
            
            if proxy_name in original_links_map:
                successful_nodes.append(original_links_map[proxy_name])
            else:
                print(f"Warning: Could not find original link for proxy name '{proxy_name}'. Skipping.")
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Node '{proxy_name}' is NOT working. Error: {e}")
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
            original_name = parsed["name"]
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
