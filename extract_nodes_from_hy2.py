import aiohttp
import asyncio
import re
import base64
import yaml
import os
import json
from urllib.parse import urlparse, unquote, parse_qs
from datetime import datetime, timezone

# --- Configuration ---
# File paths
input_file = "data/hy2.txt"
protocol_nodes_file = "data/protocol_nodes.txt"
yaml_nodes_file = "data/yaml_nodes.yaml"
temp_nodes_file = "data/temp_nodes.txt" # For raw extracted nodes before testing
invalid_urls_file = "data/invalid_urls.txt" # Note: This file is primarily updated by extract_nodes.py
debug_log_file = "data/extraction_debug.log" # Updated name to match workflow

# Ensure data directory exists
os.makedirs("data", exist_ok=True)

# Global list to store debug logs
debug_logs = []

# --- Regex Patterns ---
# Protocol patterns (e.g., vless://, vmess://, trojan://, ss://, hysteria2://)
PROTOCOL_PATTERNS = {
    "vless": re.compile(r"vless://[^\"'\s]+"),
    "vmess": re.compile(r"vmess://[^\"'\s]+"),
    "trojan": re.compile(r"trojan://[^\"'\s]+"),
    "ss": re.compile(r"ss://[^\"'\s]+"),
    "hysteria2": re.compile(r"hysteria2://[^\"'\s]+"),
}

# Base64 pattern (stricter, for encoded content)
# Requires length to be a multiple of 4, allows padding.
BASE64_PATTERN = re.compile(r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?:[A-Za-z0-9+/=]{16,})', re.MULTILINE)

# --- Utility Functions ---

async def fetch_url_content(session: aiohttp.ClientSession, url: str) -> str | None:
    """Fetches content from a given URL."""
    try:
        # Replace github.com/repo/blob/branch with raw.githubusercontent.com/repo/branch
        raw_url = url.replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
        async with session.get(raw_url, timeout=30) as response:
            response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
            return await response.text()
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        debug_logs.append(f"Error fetching {url}: {e}")
        return None
    except Exception as e:
        debug_logs.append(f"Unknown error fetching {url}: {e}")
        return None

def decode_base64(encoded_str: str) -> str | None:
    """Decodes a Base64 string, handling common padding issues."""
    try:
        # Add padding if missing
        missing_padding = len(encoded_str) % 4
        if missing_padding:
            encoded_str += '=' * (4 - missing_padding)
        return base64.b64decode(encoded_str, validate=True).decode('utf-8', errors='ignore')
    except (base64.binascii.Error, UnicodeDecodeError):
        return None

def extract_protocol_nodes(content: str, source_url: str) -> set[str]:
    """Extracts various protocol nodes (vless, vmess, trojan, ss, hysteria2) from content."""
    nodes = set()
    for protocol, pattern in PROTOCOL_PATTERNS.items():
        for match in pattern.finditer(content):
            node = match.group(0).strip()
            # Basic validation: check if it's a plausible URL
            if len(node) > len(protocol) + 3 and " " not in node and "<" not in node and ">" not in node:
                nodes.add(node)
                debug_logs.append(f"Found {protocol} node from {source_url}: {node[:100]}...") # Log truncated node
    return nodes

def extract_yaml_nodes(content: str, source_url: str) -> list[dict]:
    """
    Extracts YAML-based proxy configurations (e.g., from Clash configs).
    Returns a list of dictionaries if found, otherwise an empty list.
    """
    yaml_configs = []
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            # Check for common proxy configuration keys
            for key in ['proxies', 'proxy', 'nodes', 'servers', 'outbounds']:
                if key in data and (isinstance(data[key], list) or isinstance(data[key], dict)):
                    # If it's a list of proxies
                    if isinstance(data[key], list):
                        for proxy_item in data[key]:
                            if isinstance(proxy_item, dict) and 'name' in proxy_item and 'type' in proxy_item:
                                yaml_configs.append(proxy_item)
                                debug_logs.append(f"Found YAML proxy list item from {source_url}: {proxy_item.get('name', '')} ({proxy_item.get('type', '')})")
                    # If it's a single proxy dictionary
                    elif isinstance(data[key], dict) and 'name' in data[key] and 'type' in data[key]:
                        yaml_configs.append(data[key])
                        debug_logs.append(f"Found single YAML proxy config from {source_url}: {data[key].get('name', '')} ({data[key].get('type', '')})")
    except yaml.YAMLError as e:
        debug_logs.append(f"YAML parsing error for {source_url}: {e}")
    except Exception as e:
        debug_logs.append(f"Unknown error parsing YAML for {source_url}: {e}")
    return yaml_configs

def extract_json_nodes(content: str, source_url: str) -> list[dict]:
    """
    Extracts JSON-based proxy configurations (e.g., V2RayN/Clash config format).
    Returns a list of dictionaries if found.
    """
    json_configs = []
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            # Check for common JSON proxy keys (e.g., Clash configs, V2RayN GUI config)
            if 'outbounds' in data and isinstance(data['outbounds'], list):
                for outbound in data['outbounds']:
                    if isinstance(outbound, dict) and 'protocol' in outbound and 'settings' in outbound:
                        json_configs.append(outbound)
                        debug_logs.append(f"Found JSON outbound config from {source_url}: {outbound.get('protocol', '')}")
            elif 'vmess' in data and isinstance(data['vmess'], list): # Specific for certain V2RayN exports
                for vmess_item in data['vmess']:
                     if isinstance(vmess_item, dict) and all(k in vmess_item for k in ['v', 'ps', 'add', 'port', 'id']):
                         json_configs.append(vmess_item)
                         debug_logs.append(f"Found JSON VMess config from {source_url}: {vmess_item.get('ps', '')}")
            # More general check for 'proxies' key in JSON (like Clash)
            elif 'proxies' in data and isinstance(data['proxies'], list):
                for proxy_item in data['proxies']:
                    if isinstance(proxy_item, dict) and 'name' in proxy_item and 'type' in proxy_item:
                        json_configs.append(proxy_item)
                        debug_logs.append(f"Found JSON proxy list item from {source_url}: {proxy_item.get('name', '')} ({proxy_item.get('type', '')})")

    except json.JSONDecodeError as e:
        debug_logs.append(f"JSON parsing error for {source_url}: {e}")
    except Exception as e:
        debug_logs.append(f"Unknown error parsing JSON for {source_url}: {e}")
    return json_configs

# --- Main Extraction Logic ---

async def extract_nodes_from_url(session: aiohttp.ClientSession, url_entry: str, processed_urls: set, all_protocol_nodes: set, all_yaml_nodes: list):
    """
    Fetches content from a URL, extracts nodes, and adds them to global sets/lists.
    """
    original_url = url_entry.split("|")[0]

    if original_url in processed_urls:
        debug_logs.append(f"Skipping already processed URL: {original_url}")
        return

    processed_urls.add(original_url)

    content = await fetch_url_content(session, original_url)
    if not content:
        return

    # 1. Extract protocol nodes from cleartext content
    found_protocol_nodes = extract_protocol_nodes(content, original_url)
    if found_protocol_nodes:
        all_protocol_nodes.update(found_protocol_nodes)

    # 2. Extract Base64 encoded protocols/JSON
    base64_matches = BASE64_PATTERN.findall(content)
    for b64_str in base64_matches:
        decoded_content = decode_base64(b64_str)
        if decoded_content:
            decoded_protocol_nodes = extract_protocol_nodes(decoded_content, original_url + " (Base64 decoded)")
            if decoded_protocol_nodes:
                all_protocol_nodes.update(decoded_protocol_nodes)
            
            decoded_json_nodes = extract_json_nodes(decoded_content, original_url + " (Base64 decoded JSON)")
            if decoded_json_nodes:
                all_yaml_nodes.extend(decoded_json_nodes) # Treat JSON as YAML-like for now

    # 3. Extract YAML nodes
    found_yaml_nodes = extract_yaml_nodes(content, original_url)
    if found_yaml_nodes:
        all_yaml_nodes.extend(found_yaml_nodes)
    
    # 4. Extract JSON nodes (if not already covered by YAML or Base64 JSON)
    # This might find top-level JSON files that are not Base64 encoded or YAML
    if not found_yaml_nodes: # Avoid re-parsing if it was already treated as YAML
        found_json_nodes = extract_json_nodes(content, original_url)
        if found_json_nodes:
            all_yaml_nodes.extend(found_json_nodes)


# --- Node Testing and Saving Logic ---

async def test_nodes(protocol_nodes: set[str], session: aiohttp.ClientSession) -> tuple[set[str], set[str]]:
    """
    Placeholder for actual node testing logic.
    In a real scenario, this would attempt to connect to each node.
    For this script, we'll simulate success for most nodes.
    """
    valid_nodes = set()
    invalid_nodes = set()

    debug_logs.append(f"Starting simulated test for {len(protocol_nodes)} protocol nodes...")

    # NOTE: This is a placeholder for actual node testing.
    # A real implementation would involve:
    # - Using a proxy client library (e.g., for Vless, Vmess, Trojan, SS, Hysteria2)
    # - Attempting to connect to each node's server and port
    # - Measuring latency and checking for connectivity/reachability
    # - Filtering based on actual success.
    # For now, we'll just assume a high success rate for demonstration.

    for i, node in enumerate(list(protocol_nodes)):
        # Simulate testing: In a real scenario, this is where the actual connection test happens
        is_valid = True # Assume valid for demonstration
        if "invalid" in node.lower(): # Simple simulation of invalid nodes
            is_valid = False

        if is_valid:
            valid_nodes.add(node)
        else:
            invalid_nodes.add(node)
        
        if (i + 1) % 1000 == 0: # Log progress every 1000 nodes
            debug_logs.append(f"Simulated test progress: {i+1}/{len(protocol_nodes)} nodes. Valid: {len(valid_nodes)}, Invalid: {len(invalid_nodes)}")

    debug_logs.append(f"Finished simulated testing nodes. Valid: {len(valid_nodes)}, Invalid: {len(invalid_nodes)}")
    return valid_nodes, invalid_nodes

async def test_and_save_nodes():
    """
    Reads extracted nodes, performs soft-deduplication,
    simulated testing, and saves valid nodes.
    """
    all_raw_protocol_nodes = set()
    all_raw_yaml_nodes = [] # Collect all YAML/JSON nodes as dicts

    # Load previously extracted temp protocol nodes
    try:
        if os.path.exists(temp_nodes_file):
            with open(temp_nodes_file, "r", encoding="utf-8") as f:
                for line in f:
                    all_raw_protocol_nodes.add(line.strip())
            debug_logs.append(f"Loaded {len(all_raw_protocol_nodes)} raw protocol nodes from {temp_nodes_file}.")
    except Exception as e:
        debug_logs.append(f"Error loading {temp_nodes_file}: {e}")

    # Load previously extracted YAML nodes (if any)
    try:
        if os.path.exists(yaml_nodes_file):
            with open(yaml_nodes_file, "r", encoding="utf-8") as f:
                loaded_yaml_data = yaml.safe_load(f)
                if isinstance(loaded_yaml_data, list):
                    all_raw_yaml_nodes.extend(loaded_yaml_data)
            debug_logs.append(f"Loaded {len(all_raw_yaml_nodes)} raw YAML nodes from {yaml_nodes_file}.")
    except Exception as e:
        debug_logs.append(f"Error loading {yaml_nodes_file}: {e}")

    # --- 新增：协议节点软去重逻辑 ---
    unique_protocol_nodes_by_core_params = {} # 存储 {核心参数字符串: 最短/最完整的URL}
    initial_protocol_node_count = len(all_raw_protocol_nodes)

    for node_url in all_raw_protocol_nodes:
        try:
            parsed_url = urlparse(node_url)
            scheme = parsed_url.scheme.lower() # 协议类型 (vless, vmess, trojan, ss, hysteria2)
            
            core_identifier = "" # 用于识别唯一节点的字符串

            if scheme in ["vless", "vmess", "trojan"]:
                host = parsed_url.hostname
                port = parsed_url.port
                # 对于 vless/vmess/trojan，用户 ID (UUID) 或密码是关键
                # 这些通常在 URL 的 userinfo 部分 (如 vless://[uuid]@host:port)
                # 或者 Base64 解码后的 JSON 配置中。这里简化处理。
                # 更精确的去重需要解析 Base64 后的 JSON
                userinfo = parsed_url.username if parsed_url.username else ""
                
                # 假设 host:port:userinfo 是一个不错的核心标识
                core_identifier = f"{scheme}://{host}:{port}@{userinfo}" 
                
                # 如果核心标识相同，保留最短的 URL 或第一个发现的 URL
                # 短的 URL 通常意味着更少的冗余参数
                if core_identifier not in unique_protocol_nodes_by_core_params or \
                   len(node_url) < len(unique_protocol_nodes_by_core_params[core_identifier]):
                    unique_protocol_nodes_by_core_params[core_identifier] = node_url

            elif scheme == "ss":
                # SS 通常是 ss://base64(method:password@host:port)
                # 或 ss://method:password@host:port
                # 更精确的去重需要解码 base64 并解析
                host = parsed_url.hostname
                port = parsed_url.port
                # 假设 host:port 是核心标识，忽略方法和密码差异进行初步去重
                # 警告：这可能将不同密码但相同服务器端口的SS节点视为重复
                core_identifier = f"{scheme}://{host}:{port}" 
                if core_identifier not in unique_protocol_nodes_by_core_params or \
                   len(node_url) < len(unique_protocol_nodes_by_core_params[core_identifier]):
                    unique_protocol_nodes_by_core_params[core_identifier] = node_url
                    
            elif scheme == "hysteria2":
                # Hysteria2 通常是 hysteria2://user:pass@host:port
                host = parsed_url.hostname
                port = parsed_url.port
                # 假设 host:port 是核心标识
                core_identifier = f"{scheme}://{host}:{port}"
                if core_identifier not in unique_protocol_nodes_by_core_params or \
                   len(node_url) < len(unique_protocol_nodes_by_core_params[core_identifier]):
                    unique_protocol_nodes_by_core_params[core_identifier] = node_url

            else:
                # 对于无法解析或不识别的协议，直接使用原始 URL 作为标识（保持硬去重）
                if node_url not in unique_protocol_nodes_by_core_params:
                    unique_protocol_nodes_by_core_params[node_url] = node_url

        except Exception as e:
            debug_logs.append(f"Error parsing node URL for soft-deduplication: {node_url} - {e}")
            # 如果解析失败，仍然将原始 URL 视为独立节点
            if node_url not in unique_protocol_nodes_by_core_params:
                unique_protocol_nodes_by_core_params[node_url] = node_url

    # 将软去重后的节点更新到用于测试的集合中
    all_raw_protocol_nodes = set(unique_protocol_nodes_by_core_params.values())
    debug_logs.append(f"After soft-deduplication, {len(all_raw_protocol_nodes)} unique protocol nodes remain (reduced from {initial_protocol_node_count}).")
    print(f"After soft-deduplication, {len(all_raw_protocol_nodes)} unique protocol nodes remain (reduced from {initial_protocol_node_count}).")

    # --- 协议节点软去重逻辑结束 ---

    # Process these raw nodes with simulated testing
    async with aiohttp.ClientSession() as session:
        valid_protocol_nodes, invalid_protocol_nodes = await test_nodes(all_raw_protocol_nodes, session)

    # Save valid protocol nodes
    with open(protocol_nodes_file, "w", encoding="utf-8") as f:
        for node in sorted(list(valid_protocol_nodes)):
            f.write(node + "\n")
    debug_logs.append(f"Extracted and tested {len(valid_protocol_nodes)} valid protocol nodes, saved to {protocol_nodes_file}.")
    print(f"Extracted and tested {len(valid_protocol_nodes)} valid protocol nodes, saved to {protocol_nodes_file}")

    # Save YAML nodes (they don't undergo the same direct 'test_nodes' as protocols)
    # Deduplicate YAML nodes based on their content (e.g., by converting to JSON string)
    unique_yaml_nodes = []
    seen_yaml_signatures = set()
    for node_dict in all_raw_yaml_nodes:
        try:
            node_signature = json.dumps(node_dict, sort_keys=True) # Create a stable representation for deduplication
            if node_signature not in seen_yaml_signatures:
                unique_yaml_nodes.append(node_dict)
                seen_yaml_signatures.add(node_signature)
        except TypeError: # Handle unhashable types if any in complex dicts
            unique_yaml_nodes.append(node_dict) # Fallback, might have duplicates

    with open(yaml_nodes_file, "w", encoding="utf-8") as f:
        yaml.dump(unique_yaml_nodes, f, allow_unicode=True, default_flow_style=False)
    debug_logs.append(f"Extracted {len(unique_yaml_nodes)} unique YAML/JSON nodes, saved to {yaml_nodes_file}.")
    print(f"Extracted {len(unique_yaml_nodes)} unique YAML/JSON nodes, saved to {yaml_nodes_file}")

    # Ensure the temp nodes file is cleared or updated after processing
    # If all nodes are processed, we can clear this temp file.
    if os.path.exists(temp_nodes_file):
        os.remove(temp_nodes_file)
        debug_logs.append(f"Cleared temporary nodes file: {temp_nodes_file}")


# --- Main Execution ---

async def main():
    """Main function to orchestrate node extraction and testing."""
    urls_to_process = []
    # Read URLs from the input file generated by extract_nodes.py
    try:
        with open(input_file, "r", encoding="utf-8") as f:
            urls_to_process = [line.strip() for line in f if line.strip()]
        debug_logs.append(f"Loaded {len(urls_to_process)} URLs from {input_file}.")
        print(f"Loaded {len(urls_to_process)} URLs from {input_file}.")
    except FileNotFoundError:
        debug_logs.append(f"Error: Input file {input_file} not found. Please run extract_nodes.py first.")
        print(f"Error: Input file {input_file} not found. Please run extract_nodes.py first.")
        return
    except Exception as e:
        debug_logs.append(f"Error reading input file {input_file}: {e}")
        print(f"Error reading input file {input_file}: {e}")
        return

    all_protocol_nodes = set() # Use a set to automatically handle duplicates for protocol links
    all_yaml_nodes = [] # Use a list for YAML nodes as they are dictionaries and need different deduplication
    processed_urls = set() # Track URLs that have been processed to avoid re-fetching

    async with aiohttp.ClientSession() as session:
        # Create tasks for parallel fetching and extraction
        tasks = [
            extract_nodes_from_url(session, url_entry, processed_urls, all_protocol_nodes, all_yaml_nodes)
            for url_entry in urls_to_process
        ]
        await asyncio.gather(*tasks) # Run all extraction tasks concurrently

    # Save raw extracted protocol nodes to temp file before testing (soft-deduplication happens later)
    with open(temp_nodes_file, "w", encoding="utf-8") as f:
        for node in sorted(list(all_protocol_nodes)):
            f.write(node + "\n")
    debug_logs.append(f"Extracted {len(all_protocol_nodes)} raw protocol nodes, saved to {temp_nodes_file} (pending soft-deduplication and simulated test).")
    print(f"Extracted {len(all_protocol_nodes)} raw protocol nodes, saved to {temp_nodes_file} (pending soft-deduplication and simulated test)")

    # Save raw extracted YAML/JSON nodes
    # Note: YAML nodes are deduplicated in test_and_save_nodes, but raw ones are saved here first.
    with open(yaml_nodes_file, "w", encoding="utf-8") as f:
        yaml.dump(all_yaml_nodes, f, allow_unicode=True, default_flow_style=False)
    debug_logs.append(f"Extracted {len(all_yaml_nodes)} raw YAML nodes, saved to {yaml_nodes_file}.")
    print(f"Extracted {len(all_yaml_nodes)} raw YAML nodes, saved to {yaml_nodes_file}")

    # Now, test the collected nodes and save results
    await test_and_save_nodes()

    # Save all debug logs
    with open(debug_log_file, "w", encoding="utf-8") as f:
        f.write("\n".join(debug_logs))
    debug_logs.append(f"Debug logs saved to {debug_log_file}")
    print(f"Debug logs saved to {debug_log_file}")


if __name__ == "__main__":
    asyncio.run(main())
