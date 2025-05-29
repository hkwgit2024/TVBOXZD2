import aiohttp
import asyncio
import base64
import json
import logging
import os
import re
import yaml
import requests
from datetime import datetime
import pytz
from urllib.parse import urlparse

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)
handler = logging.FileHandler('data/extract.log')
handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
logger.addHandler(handler)

# Shanghai timezone
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

# Data directory
DATA_DIR = 'data'
os.makedirs(DATA_DIR, exist_ok=True)

# Global storage for results
unique_nodes = set()
url_node_counts = {}
# Use a dictionary to store invalid URLs with their timestamp and reason
invalid_urls_from_extract = {}


def load_invalid_urls_from_file():
    """Loads invalid URLs previously saved by search.py or extract.py."""
    invalid = {}
    filepath = os.path.join(DATA_DIR, 'invalid_urls.txt')
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split(' | ', 2) # Split into at most 3 parts
                    if len(parts) == 3:
                        timestamp_str, url, reason = parts
                        # We only care about the URL for quick lookup
                        invalid[url] = {'timestamp': timestamp_str, 'reason': reason}
        except Exception as e:
            logger.error(f"Error loading invalid_urls.txt: {e}")
    return invalid

def save_invalid_urls(all_invalid_urls):
    """Saves all currently known invalid URLs to file."""
    filepath = os.path.join(DATA_DIR, 'invalid_urls.txt')
    try:
        with open(filepath, 'w', encoding='utf-8') as f:
            for url, info in all_invalid_urls.items():
                f.write(f"{info['timestamp']} | {url} | {info['reason']}\n")
        logger.info(f"Saved {len(all_invalid_urls)} invalid URLs to {filepath}")
    except Exception as e:
        logger.error(f"Error saving invalid_urls.txt: {e}")

async def test_node_connection(session, node, timeout=15):
    """Tests the connectivity of a node.
    For subscription links (HTTP/HTTPS), performs a HEAD request.
    For proxy protocols (trojan, vmess, etc.), assumes they are valid at this stage.
    """
    if node.startswith(('trojan://', 'vmess://', 'ss://', 'hy2://', 'vless://')):
        # For direct proxy protocols, we assume validity after extraction.
        # True connectivity testing for these would require a proxy client,
        # which is beyond the scope of a simple HTTP HEAD request.
        return True

    # For HTTP/HTTPS links (likely subscription URLs), test connectivity
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
    }
    for attempt in range(3):
        try:
            async with session.head(node, headers=headers, timeout=timeout, allow_redirects=True) as response:
                if response.status == 200:
                    return True
                logger.debug(f"Node {node} returned status: {response.status} (Attempt {attempt + 1}/3)")
        except aiohttp.ClientError as e:
            logger.debug(f"Testing node {node} failed (Attempt {attempt + 1}/3): {e}")
        except Exception as e:
            logger.warning(f"Unexpected error testing node {node}: {e}")
        await asyncio.sleep(2) # Wait before retrying
    return False

def recursive_decode_base64(text):
    """Recursively decodes Base64 encoded content."""
    try:
        # Check if the text is potentially Base64. A simple check, not foolproof.
        # Base64 strings length should be a multiple of 4, or padded with '='
        if not text or len(text) % 4 != 0 or not re.match(r'^[a-zA-Z0-9+/=]+$', text):
            return text # Not a valid base64 string, return as is

        decoded_bytes = base64.b64decode(text, validate=True)
        decoded_str = decoded_bytes.decode('utf-8')
        # Recursively try to decode if the decoded string itself looks like base64
        return recursive_decode_base64(decoded_str)
    except (base64.binascii.Error, UnicodeDecodeError):
        return text # Not valid base64 or decoding error, return original text
    except Exception as e:
        logger.debug(f"Error during recursive Base64 decode: {e}")
        return text

def parse_file_content(content):
    """Parses file content to extract nodes."""
    nodes = []

    # Direct extraction of node links (e.g., from subscription files)
    # Added hy2 and considered standard HTTP/HTTPS for subscription links
    node_patterns = [
        r'(trojan://[^\s]+)',
        r'(vmess://[^\s]+)',
        r'(ss://[^\s]+)',
        r'(hy2://[^\s]+)',
        r'(vless://[^\s]+)',
        r'(https?://[^\s]+)' # Potential subscription links
    ]

    for pattern in node_patterns:
        matches = re.findall(pattern, content)
        nodes.extend(matches)

    # Base64 decoding
    # This should be applied to the *entire content* if it's a single Base64 encoded subscription
    decoded_content_from_base64 = recursive_decode_base64(content.strip())
    if decoded_content_from_base64 != content.strip():
        # If successfully decoded, re-parse the decoded content
        nodes.extend(parse_file_content(decoded_content_from_base64))
    else:
        # If not fully decoded, try decoding line by line for files with mixed content
        for line in content.splitlines():
            decoded_line = recursive_decode_base64(line.strip())
            if decoded_line != line.strip():
                # If a line was decoded, parse it for nodes
                nodes.extend(parse_file_content(decoded_line))


    # Parse YAML content for Clash/Sing-Box proxies
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            # Clash format
            if 'proxies' in data and isinstance(data['proxies'], list):
                for item in data['proxies']:
                    if isinstance(item, dict):
                        node_type = item.get('type', '').lower()
                        # Only handle known proxy types that can be converted to standard links
                        if node_type in ['trojan', 'vmess', 'ss', 'vless', 'shadowsocks', 'shadowsocksr', 'hysteria2']:
                            # This part is complex due to various proxy configurations.
                            # For simplicity, we'll try to reconstruct basic links.
                            # A full implementation would need to handle all fields.
                            try:
                                if node_type == 'vmess':
                                    # vmess link generation is complex, needs full config
                                    nodes.append(f"vmess://{base64.b64encode(json.dumps(item).encode()).decode()}")
                                elif node_type in ['ss', 'shadowsocks']:
                                    cipher = item.get('cipher')
                                    password = item.get('password')
                                    server = item.get('server')
                                    port = item.get('port')
                                    if all([cipher, password, server, port]):
                                        encoded_info = base64.b64encode(f"{cipher}:{password}@{server}:{port}".encode()).decode()
                                        name = item.get('name', 'ss_node')
                                        nodes.append(f"ss://{encoded_info}#{name}")
                                elif node_type == 'trojan':
                                    password = item.get('password')
                                    server = item.get('server')
                                    port = item.get('port')
                                    sni = item.get('sni', '')
                                    if all([password, server, port]):
                                        nodes.append(f"trojan://{password}@{server}:{port}?sni={sni}")
                                elif node_type == 'vless':
                                    uuid = item.get('uuid')
                                    server = item.get('server')
                                    port = item.get('port')
                                    tls = 'tls' if item.get('tls') else ''
                                    if all([uuid, server, port]):
                                        nodes.append(f"vless://{uuid}@{server}:{port}?security={tls}")
                                elif node_type in ['hy2', 'hysteria2']:
                                    # Hysteria2 specific parsing (example, might need more fields)
                                    server = item.get('server')
                                    port = item.get('port')
                                    password = item.get('password')
                                    if all([server, port, password]):
                                        nodes.append(f"hy2://{password}@{server}:{port}")

                            except Exception as e:
                                logger.debug(f"Failed to generate {node_type} link from YAML: {e}")

            # Sing-Box format (outbounds)
            if 'outbounds' in data and isinstance(data['outbounds'], list):
                for item in data['outbounds']:
                    if isinstance(item, dict):
                        protocol = item.get('protocol', '').lower()
                        # Similar logic as above for different protocols
                        if protocol in ['trojan', 'vmess', 'shadowsocks', 'vless', 'hysteria2']:
                             try:
                                 # This parsing would be highly specific to Sing-Box's outbound structure.
                                 # You'd need to extract fields like `server`, `port`, `uuid`, `password`, `security` etc.
                                 # and construct the appropriate URL.
                                 # For demonstration, let's just log if found
                                 logger.debug(f"Found Sing-Box outbound of type: {protocol}")
                                 # Example: For vmess in sing-box, `uuid` is in `uuid`, `server` in `server`, `port` in `port`
                                 # You would build the vmess:// link similar to the Clash example.
                             except Exception as e:
                                 logger.debug(f"Failed to process Sing-Box {protocol} outbound: {e}")

    except yaml.YAMLError as e:
        logger.debug(f"YAML parsing failed (not necessarily an error, might be plain text): {e}")
    except Exception as e:
        logger.debug(f"Error during YAML parsing: {e}")

    # Parse JSON content for v2ray/Sing-Box configurations
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            # V2Ray/Xray config (often 'outbounds' key)
            if 'outbounds' in data and isinstance(data['outbounds'], list):
                for outbound in data['outbounds']:
                    if isinstance(outbound, dict):
                        protocol = outbound.get('protocol', '').lower()
                        if protocol == 'vmess':
                            # Vmess JSON structure for a single node
                            settings = outbound.get('settings', {})
                            vnext = settings.get('vnext', [])
                            if vnext:
                                server_obj = vnext[0].get('users', [])
                                if server_obj:
                                    # Extract relevant fields to construct vmess:// link
                                    # This is a simplified example; actual V2Ray config can be complex.
                                    user_info = server_obj[0] # Assuming first user
                                    address = vnext[0].get('address')
                                    port = vnext[0].get('port')
                                    if address and port and user_info.get('id'):
                                        # Construct a minimal vmess link JSON payload
                                        vmess_config = {
                                            "v": "2",
                                            "ps": user_info.get('remarks', 'vmess_node'),
                                            "add": address,
                                            "port": port,
                                            "id": user_info.get('id'),
                                            "aid": user_info.get('alterId', 0),
                                            "net": outbound.get('streamSettings', {}).get('network', 'tcp'),
                                            "type": "", # e.g., "none" for tcp
                                            "host": outbound.get('streamSettings', {}).get('wsSettings', {}).get('headers', {}).get('Host', ''),
                                            "path": outbound.get('streamSettings', {}).get('wsSettings', {}).get('path', ''),
                                            "tls": "tls" if outbound.get('streamSettings', {}).get('security') == 'tls' else ''
                                        }
                                        encoded_vmess = base64.b64encode(json.dumps(vmess_config).encode('utf-8')).decode('utf-8')
                                        nodes.append(f"vmess://{encoded_vmess}")
            # Other JSON formats might exist, e.g., an array of direct node links
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, str) and item.startswith(('trojan://', 'vmess://', 'ss://', 'hy2://', 'vless://')):
                        nodes.append(item)

    except json.JSONDecodeError as e:
        logger.debug(f"JSON parsing failed (not necessarily an error, might be plain text): {e}")
    except Exception as e:
        logger.debug(f"Error during JSON parsing: {e}")

    return list(set(nodes)) # Return unique nodes found within this content

async def fetch_file(session, url, retries=3):
    """Fetches file content from a URL."""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
        "Accept-Encoding": "gzip, deflate, br"
    }
    for attempt in range(retries):
        try:
            async with session.get(url, headers=headers, timeout=20, allow_redirects=True) as response:
                if response.status == 200:
                    content = await response.text()
                    logger.info(f"Successfully fetched file from {url}")
                    return content
                else:
                    reason = f'Status code {response.status}'
                    invalid_urls_from_extract[url] = {
                        'timestamp': datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S %Z'),
                        'reason': reason
                    }
                    logger.warning(f"Failed to fetch {url}, status: {response.status} (Attempt {attempt + 1}/{retries})")
        except aiohttp.ClientError as e:
            reason = f'Connection error: {e}'
            invalid_urls_from_extract[url] = {
                'timestamp': datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S %Z'),
                'reason': reason
            }
            logger.warning(f"Connection error fetching {url}: {e} (Attempt {attempt + 1}/{retries})")
        except asyncio.TimeoutError:
            reason = 'Timeout during fetch'
            invalid_urls_from_extract[url] = {
                'timestamp': datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S %Z'),
                'reason': reason
            }
            logger.warning(f"Timeout fetching {url} (Attempt {attempt + 1}/{retries})")
        except Exception as e:
            reason = f'Unexpected error: {e}'
            invalid_urls_from_extract[url] = {
                'timestamp': datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S %Z'),
                'reason': reason
            }
            logger.error(f"Unexpected error fetching {url}: {e} (Attempt {attempt + 1}/{retries})")
        await asyncio.sleep(2) # Wait before retrying

    # Fallback to synchronous requests (for stubborn URLs or specific network issues)
    logger.info(f"Async request failed for {url}, attempting synchronous fallback.")
    try:
        response = requests.get(url, headers=headers, timeout=20)
        if response.status_code == 200:
            content = response.text
            logger.info(f"Synchronous request successfully fetched file from {url}")
            return content
        else:
            reason = f'Sync status code {response.status_code}'
            invalid_urls_from_extract[url] = {
                'timestamp': datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S %Z'),
                'reason': reason
            }
            logger.warning(f"Synchronous fetch {url} failed, status: {response.status_code}")
    except requests.exceptions.RequestException as e:
        reason = f'Sync request error: {e}'
        invalid_urls_from_extract[url] = {
            'timestamp': datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S %Z'),
            'reason': reason
        }
        logger.warning(f"Synchronous fetch {url} failed: {e}")
    return None

async def process_url(url, session, known_invalid_urls):
    """Processes a single URL, fetches content, extracts nodes, and tests them."""
    if url in known_invalid_urls:
        logger.info(f"Skipping previously invalidated URL: {url} (Reason: {known_invalid_urls[url]['reason']})")
        return 0, False # Return 0 nodes and indicate it was skipped

    content = await fetch_file(session, url)
    if not content:
        # fetch_file already logs and adds to invalid_urls_from_extract if it fails
        return 0, False # Return 0 nodes and indicate failure

    nodes = parse_file_content(content)
    valid_nodes_for_url = 0
    if not nodes:
        invalid_urls_from_extract[url] = {'timestamp': datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S %Z'), 'reason': 'No nodes found in content'}
        logger.info(f"URL {url} contains no detectable nodes.")
        return 0, False

    # Test extracted nodes concurrently
    node_tasks = [test_node_connection(session, node) for node in nodes]
    connection_results = await asyncio.gather(*node_tasks)

    for i, node in enumerate(nodes):
        if connection_results[i]:
            unique_nodes.add(node)
            valid_nodes_for_url += 1
            logger.debug(f"Added valid node: {node}")
        else:
            logger.debug(f"Node {node} failed connection test.")

    url_node_counts[url] = valid_nodes_for_url

    if valid_nodes_for_url == 0 and url not in invalid_urls_from_extract:
        # If no nodes were found or all failed, and it wasn't marked invalid by fetch_file
        invalid_urls_from_extract[url] = {'timestamp': datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S %Z'), 'reason': 'No valid nodes after testing'}
        logger.info(f"URL {url} yielded no valid nodes after testing.")
        return 0, False

    return len(nodes), True # Return total extracted nodes (before testing) and success status

async def main():
    """Main function to orchestrate URL processing and node extraction."""
    # 1. Load URLs to process
    urls_to_process = []
    try:
        with open(os.path.join(DATA_DIR, 'url.txt'), 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split(' | ')
                if len(parts) >= 2:
                    urls_to_process.append(parts[1])
        logger.info(f"Loaded {len(urls_to_process)} URLs from url.txt")
    except FileNotFoundError:
        logger.error("url.txt not found. Please ensure search.py has run successfully.")
        return

    # 2. Load existing invalid URLs
    # This ensures we don't re-process URLs that were already known to be bad
    global_invalid_urls = load_invalid_urls_from_file()
    initial_invalid_count = len(global_invalid_urls)
    logger.info(f"Loaded {initial_invalid_count} invalid URLs from previous runs.")


    total_nodes_extracted = 0
    processed_urls_count = 0
    async with aiohttp.ClientSession() as session:
        tasks = []
        for url in urls_to_process:
            tasks.append(process_url(url, session, global_invalid_urls))
            # Batch processing to manage concurrency and rate limiting
            if len(tasks) >= 20: # Process 20 URLs concurrently
                results = await asyncio.gather(*tasks)
                for nodes_extracted, success in results:
                    total_nodes_extracted += nodes_extracted
                    if success: # Only count as processed if it wasn't skipped
                        processed_urls_count += 1
                tasks = [] # Reset tasks for next batch
                await asyncio.sleep(2) # Short delay between batches

        # Process any remaining tasks
        if tasks:
            results = await asyncio.gather(*tasks)
            for nodes_extracted, success in results:
                total_nodes_extracted += nodes_extracted
                if success:
                    processed_urls_count += 1

    logger.info(f"Finished processing. Total URLs processed: {processed_urls_count}, Total nodes extracted (before testing): {total_nodes_extracted}")

    # 3. Consolidate and save invalid URLs
    # Merge newly found invalid URLs with previously known ones
    for url, info in invalid_urls_from_extract.items():
        global_invalid_urls[url] = info
    save_invalid_urls(global_invalid_urls)
    logger.info(f"Total invalid URLs after this run: {len(global_invalid_urls)}")

    # 4. Save unique valid nodes
    if unique_nodes:
        # Sort nodes for consistent output
        sorted_nodes = sorted(list(unique_nodes))
        with open(os.path.join(DATA_DIR, 'hy2.txt'), 'w', encoding='utf-8') as f:
            for node in sorted_nodes:
                f.write(f"{node}\n")
        logger.info(f"Saved {len(unique_nodes)} unique valid nodes to hy2.txt")
    else:
        logger.info("No unique valid nodes were extracted.")

    # 5. Final statistics
    logger.info("--- Extraction Summary ---")
    logger.info(f"Total URLs processed from url.txt: {len(urls_to_process)}")
    logger.info(f"URLs skipped (already invalid): {len([u for u in urls_to_process if u in global_invalid_urls and u not in invalid_urls_from_extract])}")
    logger.info(f"URLs yielding valid nodes: {len([url for url, count in url_node_counts.items() if count > 0])}")
    for url, count in url_node_counts.items():
        if count > 0:
            logger.info(f"  - {url}: {count} nodes")
    logger.info(f"URLs identified as invalid during extraction: {len(invalid_urls_from_extract)}")


if __name__ == "__main__":
    asyncio.run(main())
