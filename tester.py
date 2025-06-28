import os
import re
import base64
import json
import yaml
import time
import requests
import sys
from urllib.parse import urlparse, parse_qs, unquote

# Node download URL
NODE_URL = "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/success_count.txt"
# Clash Core controller address
CLASH_CONTROLLER_URL = "http://127.0.0.1:9090"
# Clash Core Socks5 proxy address
CLASH_SOCKS5_PROXY = "socks5h://127.0.0.1:7891"
# Clash Core config file path (this file will be overwritten at runtime)
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
            proxy["skip-cert-verify"] = config.get("allowInsecure", False) # allowInsecure parameter
            proxy["servername"] = config.get("sni", config.get("host", "")) # host or sni both as servername

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
            trojan_config["alpn"] = [alpn] # Clash alpn is a list
        
        return trojan_config
    return None

def parse_ss(link):
    """Parse ss link for Clash format"""
    try:
        link_parts = link.replace("ss://", "").split('#', 1)
        encoded_part = link_parts[0]
        
        decoded_bytes = base64.urlsafe_b64decode(encoded_part + "=" * ((4 - len(encoded_part) % 4) % 4))
        decoded_str = decoded_bytes.decode('utf-8')
        
        parts = decoded_str.split('@')
        if len(parts) == 2:
            auth_part = parts[0]
            server_port_part = parts[1]

            method, password = auth_part.split(':', 1)
            server, port = server_port_part.rsplit(':', 1)

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
            "down": int(params.get("down", 0)), # Clash Hysteria2 uses down and up
            "up": int(params.get("up", 0)),
            "alpn": [params.get("alpn")] if params.get("alpn") else None, # Clash alpn is a list
            "tls": True, # Hysteria2 is TLS by default
            "skip-cert-verify": params.get("insecure") == "1", # insecure=1 means skip certificate verification
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
            vless_config["skip-cert-verify"] = params.get("allowInsecure") == "1" # allowInsecure parameter

        # Reality settings for VLESS
        if params.get("security") == "reality":
            vless_config["reality-opts"] = {
                "public-key": params.get("pbk", ""),
                "short-id": params.get("sid", ""), # Clash uses short-id
                "fingerprint": params.get("fp", ""),
                "dest": params.get("dest", "")
            }
            # Reality usually implies TLS and a servername
            vless_config["servername"] = params.get("sni", "")
            vless_config["tls"] = True

        # WebSocket settings
        if vless_config["network"] == "ws":
            vless_config["ws-opts"] = {
                "path": params.get("path", "/"),
                "headers": {"Host": params.get("host", "")}
            }
            if vless_config["tls"] and not vless_config.get("servername") and vless_config["ws-opts"]["headers"].get("Host"):
                vless_config["servername"] = vless_config["ws-opts"]["headers"]["Host"]
        
        # gRPC settings
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
                "name": "🔰 节点选择",
                "type": "select",
                "proxies": ["DIRECT"]
            },
            {
                "name": "🚀 自动选择", # Add an auto-select group for latency testing
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204", # Google 204 no-content test address
                "interval": 300, # Test every 5 minutes
                "proxies": []
            }
        ],
        "rules": [
            "PROCESS-NAME,clash,DIRECT", # Prevent clash itself from looping
            "PROCESS-NAME,Clash,DIRECT",
            "PROCESS-NAME,clash-core,DIRECT",
            "DOMAIN-SUFFIX,googlevideo.com,🔰 节点选择",
            "DOMAIN-SUFFIX,googleusercontent.com,🔰 节点选择",
            "DOMAIN-SUFFIX,google.com,🔰 节点选择",
            "DOMAIN-SUFFIX,github.com,DIRECT", # GitHub direct connection, avoid proxy interference
            "MATCH,🔰 节点选择"
        ]
    }

    proxy_names = []
    for node in parsed_nodes:
        if node: # Ensure node parsing was successful
            config["proxies"].append(node)
            proxy_names.append(node["name"])
    
    # Add all parsed proxies to the select group and auto-select group
    config["proxy-groups"][0]["proxies"].extend(proxy_names)
    config["proxy-groups"][1]["proxies"].extend(proxy_names)


    with open(CLASH_CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, sort_keys=False)
    print(f"Generated Clash config: {CLASH_CONFIG_PATH}")

def test_nodes(original_links_map):
    """Test node connectivity"""
    successful_nodes = []
    
    # Read proxy names from the generated config
    with open(CLASH_CONFIG_PATH, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    
    proxies = config.get("proxies", [])
    
    print("Starting node testing...")
    for proxy in proxies:
        proxy_name = proxy["name"]
        
        print(f"Testing node: {proxy_name}...")
        try:
            # Switch Clash proxy to the current node for testing
            # Ensure Clash controller is reachable, add retry mechanism
            for _ in range(5): # Try to connect to Clash API 5 times
                try:
                    response = requests.put(
                        f"{CLASH_CONTROLLER_URL}/proxies/%E2%9C%A8%20%E8%8A%82%E7%82%B9%E9%80%89%E6%8B%A9", # Switch 'Node Select' group
                        json={"name": proxy_name},
                        timeout=5
                    )
                    response.raise_for_status()
                    break # Successfully connected and switched, break retry loop
                except requests.exceptions.ConnectionError:
                    print(f"Connection to Clash controller refused, retrying...")
                    time.sleep(2) # Wait some time before retrying
            else:
                raise ConnectionError("Failed to connect to Clash controller after multiple retries.")
            
            time.sleep(1) # Wait for proxy switch to take effect

            # Test Google using Clash proxy
            test_response = requests.get(
                "https://www.google.com",
                proxies={"http": CLASH_SOCKS5_PROXY, "https": CLASH_SOCKS5_PROXY},
                timeout=15 # Increase test timeout
            )
            test_response.raise_for_status()
            print(f"✅ Node '{proxy_name}' is working.")
            
            # Find original link and save
            if proxy_name in original_links_map:
                successful_nodes.append(original_links_map[proxy_name])
            else:
                print(f"Warning: Could not find original link for proxy name '{proxy_name}' in map. This should not happen if parsing is correct. Skipping.")
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Node '{proxy_name}' is NOT working. Error: {e}")
        except Exception as e:
            print(f"An unexpected error occurred during testing node '{proxy_name}': {e}")
            
    return successful_nodes

def main():
    # 1. Download nodes
    print(f"Downloading nodes from {NODE_URL}...")
    try:
        response = requests.get(NODE_URL, timeout=10)
        response.raise_for_status() # Check for HTTP errors
        node_links = response.text.strip().split('\n')
        node_links = [link.strip() for link in node_links if link.strip()] # Filter empty lines
        print(f"Downloaded {len(node_links)} nodes.")
    except requests.exceptions.RequestException as e:
        print(f"Error downloading nodes: {e}")
        sys.exit(1)

    if not node_links:
        print("No nodes found in the downloaded file. Exiting.")
        sys.exit(0)

    # 2. Parse nodes
    parsed_nodes = []
    original_links_map = {} # Map to store proxy name to original link
    for i, link in enumerate(node_links):
        parsed = parse_node_link(link)
        if parsed:
            # Ensure name is unique, especially when link doesn't provide a clear name
            original_name_for_map = parsed["name"] # Use the originally parsed name as key
            unique_name_for_clash_config = original_name_for_map
            count = 1
            # Clash proxy names must be unique
            while unique_name_for_clash_config in [p["name"] for p in parsed_nodes]:
                unique_name_for_clash_config = f"{original_name_for_map}_{count}"
                count += 1
            
            parsed["name"] = unique_name_for_clash_config
            
            parsed_nodes.append(parsed)
            # original_links_map should store the unique name from Clash config to original link
            original_links_map[unique_name_for_clash_config] = link
    
    if not parsed_nodes:
        print("No valid nodes parsed. Exiting.")
        sys.exit(0)

    # 3. Generate Clash config
    generate_clash_config(parsed_nodes)

    # 4. Start Clash Core (handled by external script in GitHub Actions)
    # This script is only responsible for generating config and testing; Clash Core start/stop is handled by GH Actions workflow

    # 5. Test nodes
    successful_nodes = test_nodes(original_links_map)

    # 6. Save successful nodes
    os.makedirs(os.path.dirname(SUCCESS_NODES_PATH), exist_ok=True)
    with open(SUCCESS_NODES_PATH, "w", encoding="utf-8") as f:
        for node_link in successful_nodes:
            f.write(f"{node_link}\n")
    print(f"Successfully saved {len(successful_nodes)} working nodes to {SUCCESS_NODES_PATH}")

if __name__ == "__main__":
    main()
