import aiohttp
import asyncio
import os
import re
import base64
import yaml
import json
import time
from urllib.parse import quote, urlencode
from datetime import datetime, timezone

# Environment Variables
GITHUB_TOKEN = os.getenv("BOT")
TEST_ENABLED = os.getenv("TEST_NODES", "true").lower() == "true"
TEST_MAX_NODES = int(os.getenv("TEST_MAX_NODES", 50))
TEST_TIMEOUT = float(os.getenv("TEST_TIMEOUT", 5))

# File Paths
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
        debug_logs.append(f"Loaded {len(invalid_urls)} invalid URLs")
        debug_logs.append(f"Invalid URL list: {invalid_urls}")
    except FileNotFoundError:
        debug_logs.append(f"{invalid_urls_file} not found, creating a new file")
    return invalid_urls

async def test_node_async(node, timeout=TEST_TIMEOUT):
    server, port = parse_node(node)
    if not server or not port:
        debug_logs.append(f"Node {node[:50]}... invalid server or port")
        return False
    uuid_pattern = re.compile(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}')
    if node.startswith('vless://') and not uuid_pattern.search(node):
        debug_logs.append(f"Node {node[:50]}... invalid UUID")
        return False
    try:
        # Note: Testing proxy nodes by making a direct HTTP GET request to their server:port
        # is generally not how these protocols (SS, Hysteria2, Trojan, VLESS, VMess) work.
        # They are not standard HTTP servers. A successful HTTP 200, 403, or 404 might
        # indicate that *something* is listening on that port, but it doesn't confirm
        # the proxy functionality itself.
        # For a truly robust test, you would need to implement protocol-specific client
        # logic (e.g., trying to establish a proxy connection).
        # However, for a basic reachability check, this HTTP GET can sometimes give
        # an indication if a web server or a proxy with HTTP fallback is running.
        async with aiohttp.ClientSession() as session:
            url = f"http://{server}:{port}"
            async with session.get(url, timeout=timeout) as response:
                # 200: OK, server is responding.
                # 403/404: Server is responding, but denying access or resource not found.
                # These can still indicate the server is alive and reachable, even if not
                # serving a public web page.
                if response.status in [200, 404, 403]:
                    debug_logs.append(f"Node {server}:{port} test successful (HTTP {response.status})")
                    return True
                debug_logs.append(f"Node {server}:{port} test failed: HTTP {response.status}")
    except Exception as e:
        debug_logs.append(f"Node {server}:{port} test failed: {e}")
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
        debug_logs.append(f"Failed to parse node: {node[:50]}... ({e})")
    return None, None

headers = {
    "Accept": "application/vnd.github.v3+json",
    "User-Agent": "Mozilla/5.0 (compatible; NodeExtractor/1.0)"
}
if GITHUB_TOKEN:
    headers["Authorization"] = f"token {GITHUB_TOKEN}"
else:
    debug_logs.append("Warning: BOT environment variable not found")

async def check_rate_limit(session):
    try:
        async with session.get("https://api.github.com/rate_limit", headers=headers) as response:
            response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
            rate_limit = await response.json()
            debug_logs.append(f"Rate limit: {rate_limit['rate']['remaining']} remaining")
    except Exception as e:
        debug_logs.append(f"Failed to check rate limit: {e}")

protocol_pattern = re.compile(r'(ss|hysteria2|vless|vmess|trojan)://[^\s<>\'"]+', re.MULTILINE | re.IGNORECASE)
# Refined base64 pattern to be more strict and avoid matching random strings.
# It checks for typical base64 characters and padding, and requires a minimum length
# (e.g., 10 characters to avoid very short, meaningless matches).
base64_pattern = re.compile(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$', re.MULTILINE)


try:
    with open(input_file, "r", encoding="utf-8") as f:
        urls = [line.strip().split("|")[0] for line in f if line.strip()]
    invalid_urls = load_invalid_urls()
    urls = [url for url in urls if url not in invalid_urls]
    debug_logs.append(f"Read {len(urls)} valid URLs from {input_file}")
except FileNotFoundError:
    debug_logs.append(f"Error: {input_file} not found")
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
        debug_logs.append(f"YAML conversion failed: {proxy.get('name', 'unknown')} ({e})")
    return None

async def extract_nodes_from_url(session, url, index, total_urls):
    extracted_protocol_nodes = []
    extracted_yaml_nodes = []
    start_time = time.time()
    debug_logs.append(f"\nProcessing URL {index+1}/{total_urls}: {url}")

    try:
        raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        async with session.get(raw_url, headers=headers, timeout=15) as response:
            response.raise_for_status()
            content = await response.text()
            content = content[:1000000] # Limit content size to prevent excessive memory usage
            debug_logs.append(f"Successfully fetched content from {url}, length: {len(content)}")
            debug_logs.append(f"First 100 characters of content: {content[:100].replace('\n', ' ')}")

            protocol_matches = protocol_pattern.finditer(content)
            for match in protocol_matches:
                node = match.group(0).strip()
                # Basic validation for extracted protocol nodes
                if protocol_pattern.match(node) and len(node) > 10:
                    extracted_protocol_nodes.append(node)
                    url_node_map[node] = url
                    debug_logs.append(f"Extracted plaintext node: {node[:50]}...")

            base64_matches = base64_pattern.findall(content)
            debug_logs.append(f"Found {len(base64_matches)} potential Base64 strings")
            skip_params = ['encryption=', 'security=', 'sni=', 'type=', 'mode=', 'serviceName=', 'fp=', 'pbk=', 'sid=']
            for b64_str in base64_matches:
                # Skip strings that look like base64 but are actually URL parameters
                if any(param in b64_str.lower() for param in skip_params):
                    debug_logs.append(f"Skipping non-Base64 parameter: {b64_str[:20]}...")
                    continue
                try:
                    # Attempt to decode, then check if it contains a protocol pattern
                    decoded = base64.b64decode(b64_str, validate=True).decode('utf-8', errors='ignore')
                    if protocol_pattern.search(decoded):
                        node = decoded.strip()
                        if protocol_pattern.match(node) and len(node) > 10:
                            extracted_protocol_nodes.append(node)
                            url_node_map[node] = url
                            debug_logs.append(f"Extracted Base64 decoded node: {node[:50]}...")
                    # Also try to parse as JSON for VMess
                    try:
                        json_data = json.loads(decoded)
                        if isinstance(json_data, dict) and any(key in json_data for key in ['v', 'ps', 'add', 'port', 'id']):
                            node = f"vmess://{base64.b64encode(json.dumps(json_data).encode('utf-8')).decode('utf-8')}"
                            extracted_protocol_nodes.append(node)
                            url_node_map[node] = url
                            debug_logs.append(f"Extracted Base64 JSON node: {node[:50]}...")
                    except json.JSONDecodeError:
                        pass # Not a JSON, continue
                except (base64.binascii.Error, UnicodeDecodeError) as e:
                    debug_logs.append(f"Base64 decoding failed: {b64_str[:20]}... ({e})")
                    continue

            file_extension = os.path.splitext(url)[1].lower()
            debug_logs.append(f"Attempting to parse YAML/JSON: {url}, extension: {file_extension}")
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
                                                debug_logs.append(f"Extracted YAML protocol node: {protocol_node[:50]}...")
                                            extracted_yaml_nodes.append(proxy)
                                            debug_logs.append(f"Extracted YAML node: {yaml.dump([proxy], allow_unicode=True, sort_keys=False)[:50]}...")
                                elif isinstance(proxies, dict): # Handle single proxy object at top level
                                    if any(k in proxies for k in ['server', 'port', 'type', 'cipher', 'password', 'uuid']):
                                        protocol_node = yaml_to_protocol(proxies)
                                        if protocol_node:
                                            extracted_protocol_nodes.append(protocol_node)
                                            url_node_map[protocol_node] = url
                                            debug_logs.append(f"Extracted YAML protocol node: {protocol_node[:50]}...")
                                        extracted_yaml_nodes.append(proxies)
                                        debug_logs.append(f"Extracted YAML node: {yaml.dump([proxies], allow_unicode=True, sort_keys=False)[:50]}...")
                    debug_logs.append(f"YAML data type: {type(yaml_data)}")
                except yaml.YAMLError as e:
                    debug_logs.append(f"YAML parsing failed: {url} ({e})")
                
                # Try JSON parsing if YAML failed or if it's a JSON file
                if file_extension in ['.json'] or (not extracted_protocol_nodes and not extracted_yaml_nodes): # Only try JSON if no YAML nodes were found or it's explicitly JSON
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
                                                debug_logs.append(f"Extracted JSON protocol node: {protocol_node[:50]}...")
                                            extracted_yaml_nodes.append(proxy) # Store as YAML-like dict for consistency
                                            debug_logs.append(f"Extracted JSON node: {json.dumps([proxy], ensure_ascii=False)[:50]}...")
                        debug_logs.append(f"JSON data type: {type(json_data)}")
                    except json.JSONDecodeError as e:
                        debug_logs.append(f"JSON parsing failed: {url} ({e})")

    except Exception as e:
        debug_logs.append(f"Failed to fetch content for {url}: {e}")
        debug_logs.append(f"URL {url} extraction failed, its validity will be handled during the testing phase.")

    elapsed = time.time() - start_time
    debug_logs.append(f"URL {index+1} processing completed, took {elapsed:.2f} seconds")
    return extracted_protocol_nodes, extracted_yaml_nodes

async def test_and_save_nodes():
    debug_logs.append("\nPhase 2: Starting to test extracted nodes...")

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
                    debug_logs.append(f"Warning: Incorrect format in temporary file: {line.strip()}")
        debug_logs.append(f"Loaded {len(temp_protocol_nodes)} nodes to test")
    except FileNotFoundError:
        debug_logs.append(f"Error: {temp_nodes_file} not found, skipping node testing.")
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
        debug_logs.append(f"Node test {i+1}/{len(nodes_to_test)} completed")

    if invalid_urls_to_add:
        current_invalid_urls = load_invalid_urls() # Reload to get the latest state
        new_invalid_urls = invalid_urls_to_add - current_invalid_urls
        if new_invalid_urls:
            with open(invalid_urls_file, "a", encoding="utf-8") as f:
                for url in new_invalid_urls:
                    # Corrected: Use datetime.timezone.utc for timezone object
                    f.write(f"{url}|{datetime.now(datetime.timezone.utc).isoformat()}\n")
            debug_logs.append(f"Recorded {len(new_invalid_urls)} new invalid URLs")
        else:
            debug_logs.append("No new invalid URLs to record.")
    else:
        debug_logs.append("No invalid URLs to record due to node test failures.")

    with open(protocol_output_file, "w", encoding="utf-8") as f:
        for node in valid_protocol_nodes:
            f.write(f"{node}\n")
    debug_logs.append(f"Saved {len(valid_protocol_nodes)} valid protocol nodes to {protocol_output_file}")
    print(f"Extracted and tested {len(valid_protocol_nodes)} valid protocol nodes, saved to {protocol_output_file}")

async def main():
    async with aiohttp.ClientSession() as session:
        await check_rate_limit(session)
        # Limiting to 50 URLs for debugging as per your comment, remove for full run
        urls_set = sorted(list(set(urls)))[:50]
        total_urls = len(urls_set)
        tasks = []

        debug_logs.append("Phase 1: Starting node extraction from all URLs...")
        for i, url in enumerate(urls_set):
            tasks.append(extract_nodes_from_url(session, url, i, total_urls))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, result in enumerate(results):
            if isinstance(result, tuple):
                p_nodes, y_nodes = result
                protocol_nodes.extend(p_nodes)
                yaml_nodes.extend(y_nodes)
            else:
                debug_logs.append(f"Error during URL {i+1} extraction: {result}")

        protocol_nodes_set = list(dict.fromkeys(protocol_nodes))
        # Convert YAML nodes to a string representation for deduplication, then back to dict
        yaml_nodes_set = list({yaml.dump(node, allow_unicode=True, sort_keys=False): node for node in yaml_nodes}.values())

        debug_logs.append(f"Extracted {len(protocol_nodes_set)} raw protocol nodes (pending test)")
        debug_logs.append(f"Extracted {len(yaml_nodes_set)} raw YAML nodes")

        with open(temp_nodes_file, "w", encoding="utf-8") as f:
            for node in protocol_nodes_set:
                f.write(f"{node}|{url_node_map.get(node, 'unknown')}\n")
        debug_logs.append(f"Saved {len(protocol_nodes_set)} untested protocol nodes to {temp_nodes_file}")
        print(f"Extracted {len(protocol_nodes_set)} raw protocol nodes, saved to {temp_nodes_file} (pending test)")

        with open(yaml_output_file, "w", encoding="utf-8") as f:
            if yaml_nodes_set:
                yaml.dump({"proxies": yaml_nodes_set}, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
            else:
                f.write("# No YAML nodes found\n")
        debug_logs.append(f"Saved {len(yaml_nodes_set)} YAML nodes to {yaml_output_file}")
        print(f"Extracted {len(yaml_nodes_set)} YAML nodes, saved to {yaml_output_file}")

        await test_and_save_nodes()

        with open(debug_log_file, "w", encoding="utf-8") as f:
            f.write("\n".join(debug_logs))
        print(f"Debug logs saved to {debug_log_file}")

if __name__ == "__main__":
    asyncio.run(main())
