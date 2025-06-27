import httpx
import yaml
import asyncio
import os
import subprocess
import time
import socket
import re
import json
import urllib.parse
import traceback
import base64
from typing import List, Dict, Any, Optional, Tuple

# Base URLs for fetching Clash configuration files or subscription links
CLASH_BASE_CONFIG_URLS: List[str] = [
    "https://raw.githubusercontent.com/qjlxg/NoMoreWalls/refs/heads/master/snippets/nodes_GB.yml",
    "https://raw.githubusercontent.com/0x1b-Dev/free-nodes/main/clash.yaml",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/sub_merge_yaml.yml",
    "https://raw.githubusercontent.com/qjlxg/aggregator/main/data/clash.yaml",
    "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.yaml"
]

# Constants for Clash.Meta API interaction
CLASH_API_PORT: int = 9090
CLASH_API_TIMEOUT: float = 10.0
CLASH_API_MAX_WAIT_TIME: int = 75
CLASH_API_WAIT_INTERVAL: int = 2
CLASH_TEST_URL: str = "http://www.google.com/generate_204"
CLASH_TEST_TIMEOUT: int = 5000 # milliseconds

def is_valid_reality_short_id(short_id: Optional[str]) -> bool:
    """
    Validates if a REALITY protocol shortId is valid (8-character hexadecimal string).

    Args:
        short_id: The shortId string to validate.

    Returns:
        True if the shortId is valid, False otherwise.
    """
    if not short_id or not isinstance(short_id, str):
        return False
    return bool(re.match(r"^[0-9a-fA-F]{8}$", short_id))

def validate_proxy(proxy: Dict[str, Any], index: int) -> bool:
    """
    Validates a proxy node configuration, specifically for REALITY protocol settings.

    Args:
        proxy: A dictionary representing the proxy node configuration.
        index: The index of the proxy in the list (for logging purposes).

    Returns:
        True if the proxy configuration is valid, False otherwise.
    """
    missing_fields: List[str] = []
    if not proxy.get("name"):
        missing_fields.append("name")
    if not proxy.get("server"):
        missing_fields.append("server")
    if not proxy.get("port"):
        missing_fields.append("port")
    
    if missing_fields:
        print(f"⚠️ Skipping invalid node (index {index}): Missing fields {', '.join(missing_fields)} - {proxy.get('name', 'Unknown Node')}")
        return False
    
    if proxy.get("type") == "vless":
        reality_opts = proxy.get("reality-opts")
        if reality_opts:
            if not isinstance(reality_opts, dict):
                print(f"⚠️ Skipping invalid REALITY node (index {index}): 'reality-opts' is not a dictionary - {proxy.get('name')} - reality-opts: {reality_opts}")
                return False
            short_id = reality_opts.get("shortId")
            if short_id is not None and not is_valid_reality_short_id(short_id):
                print(f"⚠️ Skipping invalid REALITY node (index {index}): Invalid shortId: {short_id} - {proxy.get('name')} - Full config: {json.dumps(proxy, ensure_ascii=False)}")
                return False
    return True

def to_plaintext_node(proxy: Dict[str, Any], delay: int) -> str:
    """
    Converts a Clash proxy configuration to a plaintext node link, including delay information.
    Supports Shadowsocks, VMess, and Hysteria2.

    Args:
        proxy: A dictionary representing the proxy node configuration.
        delay: The measured delay of the node in milliseconds.

    Returns:
        A string representing the plaintext node link, or an empty string if conversion fails or type is unsupported.
    """
    try:
        name = urllib.parse.quote(proxy.get("name", "unknown"))
        proxy_type = proxy.get("type")
        
        if proxy_type == "ss":
            # Shadowsocks: ss://method:password@server:port#name - delayms
            method = proxy.get("cipher")
            password = proxy.get("password")
            server = proxy.get("server")
            port = proxy.get("port")
            if method and password and server and port:
                user_info = base64.b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
                return f"ss://{user_info}@{server}:{port}#{name} - {delay}ms"
        
        elif proxy_type == "vmess":
            # VMess: vmess://base64-encoded-json#name - delayms
            vmess_config = {
                "v": "2",
                "ps": proxy.get("name"),
                "add": proxy.get("server"),
                "port": proxy.get("port"),
                "id": proxy.get("uuid"),
                "aid": proxy.get("alterId", 0),
                "net": proxy.get("network", "tcp"),
                "type": proxy.get("cipher", "auto"),
                "tls": "tls" if proxy.get("tls", False) else "",
                "host": proxy.get("servername", ""),
                "path": proxy.get("ws-opts", {}).get("path", "")
            }
            encoded = base64.b64encode(json.dumps(vmess_config).encode()).decode().rstrip("=")
            return f"vmess://{encoded}#{name} - {delay}ms"
            
        elif proxy_type == "hysteria2":
            # Hysteria2: hysteria2://password@server:port?sni=servername&insecure=0#name - delayms
            server = proxy.get("server")
            port = proxy.get("port")
            password = proxy.get("password")
            sni = proxy.get("sni", server)
            insecure = "1" if proxy.get("skip-cert-verify", False) else "0"
            if server and port and password:
                return f"hysteria2://{password}@{server}:{port}?sni={sni}&insecure={insecure}#{name} - {delay}ms"
        
        else:
            print(f"⚠️ Skipping unsupported node type for plaintext conversion: {proxy_type} - {proxy.get('name', 'Unknown Node')}")
            return ""
    except Exception as e:
        print(f"⚠️ Failed to convert to plaintext node: {proxy.get('name', 'Unknown Node')} - Error: {e}")
        return ""

def parse_v2ray_subscription(content: str) -> List[Dict[str, Any]]:
    """
    Parses V2Ray subscription links (e.g., vmess://, ss://, hysteria2://) and converts them
    into Clash-format proxy nodes.

    Args:
        content: The raw content of the V2Ray subscription.

    Returns:
        A list of dictionaries, where each dictionary represents a Clash-format proxy node.
    """
    proxies: List[Dict[str, Any]] = []
    lines = content.splitlines()
    for index, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        try:
            if line.startswith("vmess://"):
                decoded = base64.b64decode(line[8:]).decode('utf-8')
                vmess = json.loads(decoded)
                proxy = {
                    "name": vmess.get("ps", f"vmess-{index}"),
                    "type": "vmess",
                    "server": vmess.get("add"),
                    "port": int(vmess.get("port")),
                    "uuid": vmess.get("id"),
                    "alterId": int(vmess.get("aid", 0)),
                    "cipher": vmess.get("type", "auto"),
                    "tls": vmess.get("tls") == "tls",
                    "network": vmess.get("net", "tcp"),
                    "ws-opts": {"path": vmess.get("path", "")} if vmess.get("net") == "ws" else {}
                }
                proxies.append(proxy)
            elif line.startswith("ss://"):
                # SS links can have base64 encoded userinfo before @
                parts = line[5:].split('#')
                user_server_part = parts[0]
                name = urllib.parse.unquote(parts[-1]) if len(parts) > 1 else f"ss-{index}"

                # Check if user_server_part is base64 encoded (contains no colon before @)
                if '@' in user_server_part and ':' not in user_server_part.split('@')[0]:
                    decoded_user_server = base64.b64decode(user_server_part).decode('utf-8')
                    userinfo, server_port = decoded_user_server.split('@')
                else:
                    userinfo, server_port = user_server_part.split('@')

                method, password = userinfo.split(':')
                server, port = server_port.split(':')
                
                proxy = {
                    "name": name,
                    "type": "ss",
                    "server": server,
                    "port": int(port),
                    "cipher": method,
                    "password": password
                }
                proxies.append(proxy)
            elif line.startswith("hysteria2://"):
                decoded = urllib.parse.urlparse(line)
                name = urllib.parse.unquote(decoded.fragment) if decoded.fragment else f"hysteria2-{index}"
                query = urllib.parse.parse_qs(decoded.query)
                proxy = {
                    "name": name,
                    "type": "hysteria2",
                    "server": decoded.hostname,
                    "port": int(decoded.port or 443),
                    "password": decoded.username or query.get("password", [""])[0],
                    "sni": query.get("sni", [""])[0] or decoded.hostname,
                    "skip-cert-verify": query.get("insecure", ["0"])[0] == "1"
                }
                proxies.append(proxy)
            else:
                print(f"⚠️ Skipping unknown protocol node (index {index}): {line[:50]}...")
        except Exception as e:
            print(f"⚠️ Skipping invalid subscription node (index {index}): {line[:50]}... - Error: {e}")
            print(f"   Full traceback for debugging: {traceback.format_exc()}")
    return proxies

async def fetch_yaml_configs(urls: List[str]) -> List[Dict[str, Any]]:
    """
    Fetches YAML-formatted Clash configuration files or subscription links from a list of URLs
    and extracts proxy nodes. Handles direct YAML, base64-encoded YAML, and V2Ray subscriptions.

    Args:
        urls: A list of URLs to fetch configurations from.

    Returns:
        A list of dictionaries, where each dictionary represents a Clash-format proxy node.
    """
    all_proxies: List[Dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=30.0) as client:
        for url in urls:
            try:
                print(f"🔄 Fetching configuration from {url}...")
                response = await client.get(url)
                response.raise_for_status()
                response_text = response.text

                proxies: List[Dict[str, Any]] = []
                # Attempt to parse as YAML directly
                if response_text.strip().startswith(("proxies:", "---", "port:", "mixed-port:")):
                    try:
                        yaml_content = yaml.safe_load(response_text)
                        proxies = yaml_content.get("proxies", [])
                        print(f"   Successfully parsed as direct YAML.")
                    except yaml.YAMLError as e:
                        print(f"   Failed to parse as direct YAML: {e}. Attempting base64 decode or V2Ray parse.")
                else:
                    # Attempt base64 decode
                    try:
                        decoded_text = base64.b64decode(response_text).decode('utf-8', errors='ignore')
                        if decoded_text.strip().startswith(("proxies:", "---", "port:", "mixed-port:")):
                            try:
                                yaml_content = yaml.safe_load(decoded_text)
                                proxies = yaml_content.get("proxies", [])
                                print(f"   Successfully parsed as base64-decoded YAML.")
                            except yaml.YAMLError as e:
                                print(f"   Failed to parse base64-decoded content as YAML: {e}. Attempting V2Ray parse.")
                                proxies = parse_v2ray_subscription(decoded_text)
                        else:
                            proxies = parse_v2ray_subscription(decoded_text)
                            print(f"   Successfully parsed as base64-decoded V2Ray subscription.")
                    except (base64.binascii.Error, UnicodeDecodeError):
                        print(f"   Content is not base64 encoded. Attempting V2Ray parse directly.")
                        proxies = parse_v2ray_subscription(response_text)
                
                if not proxies:
                    print(f"⚠️ Warning: No proxy nodes found in {url}")
                    continue
                
                parsed_count = 0
                for index, proxy in enumerate(proxies):
                    if validate_proxy(proxy, index):
                        all_proxies.append(proxy)
                        parsed_count += 1
                print(f"✅ Successfully parsed {parsed_count} valid proxy nodes from {url}.")
            except httpx.RequestError as e:
                print(f"❌ Error: Failed to fetch configuration from {url}: {e}")
            except Exception as e:
                print(f"❌ An unknown error occurred while processing {url}: {e}")
                print(f"   Full traceback for debugging: {traceback.format_exc()}")
    return all_proxies

async def test_clash_meta_nodes(clash_core_path: str, config_path: str, all_proxies: List[Dict[str, Any]], api_port: int = CLASH_API_PORT, retries: int = 3) -> List[Dict[str, Any]]:
    """
    Starts the Clash.Meta core, loads the generated configuration, tests proxy node delays,
    and returns a list of successfully tested nodes with their delays.

    Args:
        clash_core_path: The path to the Clash.Meta executable.
        config_path: The path to the generated Clash configuration file.
        all_proxies: A list of all proxy configurations to be tested.
        api_port: The port for Clash.Meta's external controller API.
        retries: Number of attempts to start Clash.Meta and connect to its API.

    Returns:
        A list of dictionaries, each containing 'name', 'delay', and 'config' for tested nodes,
        sorted by delay.
    """
    tested_nodes_info: List[Dict[str, Any]] = []

    async def read_stream_and_print(stream: asyncio.StreamReader, name: str, log_file: str):
        """Helper to read from a subprocess stream and print to console and log file."""
        with open(log_file, "a", encoding="utf-8") as f:
            while True:
                line = await stream.readline()
                if not line:
                    break
                line_str = line.decode('utf-8', errors='ignore').strip()
                print(f"[{name}] {line_str}")
                f.write(f"[{name}] {line_str}\n")
            print(f"[{name}] Stream finished.")
            f.write(f"[{name}] Stream finished.\n")
    
    # Check if the API port is already in use before starting Clash.Meta
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('127.0.0.1', api_port))
        except OSError:
            print(f"❌ Error: Port {api_port} is already in use. Please choose a different port or ensure it's free.")
            return []
        finally:
            s.close() # Ensure socket is closed after check

    proxy_map = {proxy["name"]: proxy for proxy in all_proxies if "name" in proxy}
    
    for attempt in range(retries):
        clash_process: Optional[asyncio.subprocess.Process] = None
        stdout_task: Optional[asyncio.Task] = None
        stderr_task: Optional[asyncio.Task] = None
        print(f"\n🚀 Attempting to start Clash.Meta core (Attempt {attempt + 1}/{retries})...")
        try:
            if not os.path.isfile(clash_core_path) or not os.access(clash_core_path, os.X_OK):
                print(f"❌ Error: Clash.Meta executable not found or not executable: {clash_core_path}")
                return []
            
            clash_process = await asyncio.create_subprocess_exec(
                clash_core_path,
                "-f", config_path,
                "-d", "./data", # Data directory for Clash.Meta
                "-ext-ctl", f"0.0.0.0:{api_port}", # External controller for API
                "-ext-ui", "ui", # External UI directory (if available)
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            print(f"Clash.Meta process started, PID: {clash_process.pid}")

            # Start tasks to read stdout and stderr concurrently
            stdout_task = asyncio.create_task(read_stream_and_print(clash_process.stdout, "Clash_STDOUT", "data/clash_stdout.log"))
            stderr_task = asyncio.create_task(read_stream_and_print(clash_process.stderr, "Clash_STDERR", "data/clash_stderr.log"))

            api_url_base = f"http://127.0.0.1:{api_port}"
            proxies_api_url = f"{api_url_base}/proxies"
            
            print(f"Attempting to connect to Clash.Meta API ({api_url_base})...")
            async with httpx.AsyncClient(timeout=CLASH_API_TIMEOUT) as client:
                connected = False
                for i in range(int(CLASH_API_MAX_WAIT_TIME / CLASH_API_WAIT_INTERVAL)):
                    try:
                        response = await client.get(proxies_api_url, timeout=CLASH_API_WAIT_INTERVAL)
                        response.raise_for_status()
                        print(f"✅ Successfully connected to Clash.Meta API (took approximately {i * CLASH_API_WAIT_INTERVAL} seconds).")
                        connected = True
                        break
                    except httpx.RequestError:
                        if clash_process.returncode is not None:
                            print(f"⚠️ Clash.Meta process exited prematurely (Exit Code: {clash_process.returncode})")
                            break
                        print(f"⏳ Waiting for Clash.Meta API ({(i + 1) * CLASH_API_WAIT_INTERVAL}s/{CLASH_API_MAX_WAIT_TIME}s)...")
                        await asyncio.sleep(CLASH_API_WAIT_INTERVAL)

                if not connected:
                    print(f"❌ Failed to connect to Clash.Meta API after {CLASH_API_MAX_WAIT_TIME} seconds.")
                    continue # Try next attempt
                
                all_proxies_data = response.json()
                proxy_names: List[str] = []
                for proxy_name, details in all_proxies_data.get("proxies", {}).items():
                    # Filter out proxy groups and special types
                    if details.get("type") not in ["Fallback", "Selector", "URLTest", "LoadBalance", "Direct", "Reject"]:
                        proxy_names.append(proxy_name)
                
                print(f"Found {len(proxy_names)} testable proxy names from Clash.Meta API.")
                if not proxy_names:
                    print("🤷 No testable proxy nodes found in Clash.Meta configuration.")
                    return [] # No nodes to test, so return empty list

                print("\n🔬 Starting proxy node delay tests...")
                tasks: List[asyncio.Task] = []
                for name in proxy_names:
                    test_url = f"{proxies_api_url}/{urllib.parse.quote(name)}/delay?timeout={CLASH_TEST_TIMEOUT}&url={urllib.parse.quote(CLASH_TEST_URL)}"
                    tasks.append(client.get(test_url, timeout=CLASH_API_TIMEOUT))
                
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                for i, result in enumerate(results):
                    node_name = proxy_names[i]
                    if isinstance(result, httpx.Response):
                        try:
                            delay_data = result.json()
                            delay = delay_data.get("delay", -1)
                            if delay > 0:
                                print(f"✅ {node_name}: {delay}ms")
                                if node_name in proxy_map:
                                    tested_nodes_info.append({
                                        "name": node_name,
                                        "delay": delay,
                                        "config": proxy_map[node_name]
                                    })
                                else:
                                    print(f"⚠️ Warning: Node {node_name} not found in original proxy list (might be an internal Clash proxy).")
                            else:
                                print(f"💔 {node_name}: Test failed/timeout ({delay_data.get('message', 'Unknown error')})")
                        except json.JSONDecodeError:
                            print(f"💔 {node_name}: Response JSON parsing failed for delay test.")
                    else:
                        print(f"💔 {node_name}: Request error during delay test - {result}")
                
                tested_nodes_info.sort(key=lambda x: x["delay"])
                return tested_nodes_info # Successfully completed testing, return results
        
        except Exception as e:
            print(f"❌ An error occurred during node testing: {e}")
            print(traceback.format_exc())
        finally:
            if clash_process and clash_process.returncode is None:
                print("🛑 Stopping Clash.Meta process...")
                clash_process.terminate()
                try:
                    await asyncio.wait_for(clash_process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    print("⚠️ Clash.Meta process did not terminate gracefully, killing it.")
                    clash_process.kill()
            
            # Cancel stream reading tasks
            if stdout_task:
                stdout_task.cancel()
                try:
                    await stdout_task # Await to ensure cancellation is handled
                except asyncio.CancelledError:
                    pass
            if stderr_task:
                stderr_task.cancel()
                try:
                    await stderr_task # Await to ensure cancellation is handled
                except asyncio.CancelledError:
                    pass
    
    print(f"❌ Clash.Meta testing failed after {retries} attempts.")
    return tested_nodes_info # Return whatever was collected, even if attempts failed

async def main():
    """
    Main function to fetch Clash configurations, unify them, test nodes using Clash.Meta,
    and output results to files.
    """
    print("🚀 Starting Clash Node Optimization Process...")
    
    # Create data directory and clear previous log files
    os.makedirs("data", exist_ok=True)
    for log_file in ["data/clash_stdout.log", "data/clash_stderr.log", "data/all.txt"]:
        if os.path.exists(log_file):
            with open(log_file, "w", encoding="utf-8") as f:
                f.write("") # Clear file content
    
    print("\n--- Fetching YAML configurations from URLs ---")
    all_proxies: List[Dict[str, Any]] = await fetch_yaml_configs(CLASH_BASE_CONFIG_URLS)
    print(f"\n✅ Total {len(all_proxies)} proxy nodes parsed from all configurations.")
    
    if not all_proxies:
        print("🤷 No nodes found, cannot proceed with testing.")
        with open("data/all.txt", "w", encoding="utf-8") as f:
            f.write("No proxies found.\n")
        return
    
    # Filter out duplicate proxies based on key attributes
    unique_proxies_map: Dict[Tuple, Dict[str, Any]] = {}
    for proxy in all_proxies:
        # Create a unique key for each proxy based on its core attributes
        key = (
            proxy.get("type"),
            proxy.get("server"),
            proxy.get("port"),
            proxy.get("password", ""),
            proxy.get("cipher", ""),
            proxy.get("uuid", ""),
            proxy.get("tls", False),
            proxy.get("network", ""),
            proxy.get("ws-opts", {}).get("path", "") # Include WS path for uniqueness
        )
        if key not in unique_proxies_map:
            unique_proxies_map[key] = proxy
        else:
            print(f"  ➡️ Skipping duplicate node: {proxy.get('name', 'Unknown')} ({proxy.get('type')}, {proxy.get('server')}:{proxy.get('port')})")
    
    unique_proxies: List[Dict[str, Any]] = list(unique_proxies_map.values())
    print(f"✨ After filtering duplicates, {len(unique_proxies)} unique nodes remain.")
    
    # Ensure all proxy names are unique for Clash.Meta
    proxy_names_set: set = set()
    for proxy in unique_proxies:
        name = proxy.get("name")
        if name is None:
            # Assign a default name if missing
            proxy["name"] = f"unnamed-proxy-{len(proxy_names_set)}"
            name = proxy["name"]

        original_name = name
        counter = 1
        while name in proxy_names_set:
            name = f"{original_name}-{counter}"
            counter += 1
        if name != original_name:
            print(f"⚠️ Warning: Duplicate proxy name '{original_name}' found. Renamed to '{name}'.")
            proxy["name"] = name
        proxy_names_set.add(name)
    
    # Define a unified Clash configuration structure
    unified_clash_config: Dict[str, Any] = {
        "proxies": unique_proxies,
        "proxy-groups": [
            {
                "name": "Proxy All",
                "type": "select",
                "proxies": [p["name"] for p in unique_proxies if "name" in p]
            },
            {
                "name": "Auto Select (URLTest)",
                "type": "url-test",
                "proxies": [p["name"] for p in unique_proxies if "name" in p],
                "url": CLASH_TEST_URL,
                "interval": 300 # Test interval in seconds
            }
        ],
        "rules": [
            "MATCH,Proxy All" # All traffic goes through "Proxy All" group
        ],
        "dns": {
            "enable": True,
            "ipv6": False,
            "listen": "0.0.0.0:1053",
            "enhanced-mode": "fake-ip",
            "default-nameserver": [
                "114.114.114.114",
                "8.8.8.8"
            ],
            "nameserver": [
                "tls://dns.google/dns-query",
                "https://dns.alidns.com/dns-query"
            ]
        },
        "log-level": "info",
        "port": 7890, # HTTP proxy port
        "socks-port": 7891, # SOCKS5 proxy port
        "allow-lan": True, # Allow LAN connections
        "external-controller": f"0.0.0.0:{CLASH_API_PORT}", # External controller API port
        "external-ui": "ui" # Path to external UI assets
    }
    
    unified_config_path: str = "data/unified_clash_config.yaml"
    try:
        with open(unified_config_path, "w", encoding="utf-8") as f:
            yaml.dump(unified_clash_config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        
        # Optional: Verify the generated YAML content for common issues (like 'mode' field)
        with open(unified_config_path, "r", encoding="utf-8") as f:
            config_content_check = yaml.safe_load(f)
            if "mode" in config_content_check:
                print(f"⚠️ Warning: Generated config contains 'mode' field: {config_content_check['mode']}. This might be overridden by Clash.Meta defaults.")
            else:
                print(f"✅ Generated config validated: no 'mode' field found (good for default behavior).")

        print(f"📦 Unified Clash configuration saved to: {unified_config_path}")
    except Exception as e:
        print(f"❌ Error: Failed to generate unified Clash configuration: {e}")
        print(f"   Full traceback for debugging: {traceback.format_exc()}")
        return
    
    clash_core_path: Optional[str] = os.environ.get("CLASH_CORE_PATH")
    if not clash_core_path:
        print(f"❌ Error: Environment variable 'CLASH_CORE_PATH' is not set.")
        print("Please set it to the path of your Clash.Meta executable, e.g.:")
        print("export CLASH_CORE_PATH=/path/to/clash-meta")
        return
    
    print("\n--- Starting Clash.Meta for node delay testing ---")
    tested_nodes: List[Dict[str, Any]] = await test_clash_meta_nodes(clash_core_path, unified_config_path, unique_proxies)
    
    # Output tested nodes to a plaintext file
    with open("data/all.txt", "w", encoding="utf-8") as f:
        if tested_nodes:
            f.write("Tested Proxy Nodes (plaintext format, sorted by delay):\n")
            for node_info in tested_nodes:
                plaintext_node = to_plaintext_node(node_info["config"], node_info["delay"])
                if plaintext_node:
                    f.write(f"{plaintext_node}\n")
        else:
            f.write("No nodes passed the delay test.\n")
    print(f"📝 Test results (plaintext node format) written to data/all.txt")
    
    # Generate a Clash configuration file with only the tested nodes
    tested_config_path: str = "data/tested_clash_config.yaml"
    if tested_nodes:
        tested_proxies: List[Dict[str, Any]] = [node_info["config"] for node_info in tested_nodes]
        tested_clash_config: Dict[str, Any] = {
            "proxies": tested_proxies,
            "proxy-groups": [
                {
                    "name": "Tested Proxies",
                    "type": "select",
                    "proxies": [p["name"] for p in tested_proxies if "name" in p]
                },
                {
                    "name": "Auto Select (URLTest)",
                    "type": "url-test",
                    "proxies": [p["name"] for p in tested_proxies if "name" in p],
                    "url": CLASH_TEST_URL,
                    "interval": 300
                }
            ],
            "rules": [
                "MATCH,Tested Proxies"
            ],
            "dns": unified_clash_config["dns"], # Reuse DNS settings
            "log-level": unified_clash_config["log-level"],
            "port": unified_clash_config["port"],
            "socks-port": unified_clash_config["socks-port"],
            "allow-lan": unified_clash_config["allow-lan"],
            "external-controller": unified_clash_config["external-controller"],
            "external-ui": unified_clash_config["external-ui"]
        }
        try:
            with open(tested_config_path, "w", encoding="utf-8") as f:
                yaml.dump(tested_clash_config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
            print(f"📦 Tested Clash configuration saved to: {tested_config_path}")
            print(f"Total {len(tested_proxies)} proxy nodes passed the delay test.")
        except Exception as e:
            print(f"❌ Error: Failed to generate tested Clash configuration: {e}")
            print(f"   Full traceback for debugging: {traceback.format_exc()}")
    else:
        print("🤷 No nodes passed the delay test, skipping creation of 'tested_clash_config.yaml'.")
    
    print(f"\n✅ Optimization process completed.")
    print(f"Final unified YAML configuration available at: {unified_config_path}")
    if tested_nodes:
        print(f"Tested and filtered YAML configuration available at: {tested_config_path}")
    print(f"Plaintext list of all tested nodes (sorted by delay) at: data/all.txt")

if __name__ == "__main__":
    asyncio.run(main())
