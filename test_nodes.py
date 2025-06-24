import httpx
import asyncio
import json
import os
import logging
import re
import time
import aiodns
import aiofiles
import psutil
import socket
import ssl
from urllib.parse import urlparse, unquote, parse_qs
from concurrent.futures import ThreadPoolExecutor

# --- Configuration ---
SS_TXT_URL = "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt"
DATA_DIR = "data"
HISTORY_FILE = os.path.join(DATA_DIR, "history_results.json")
DNS_CACHE_FILE = os.path.join(DATA_DIR, "dns_cache.json")
SUCCESSFUL_NODES_OUTPUT_FILE = os.path.join(DATA_DIR, "sub.txt")
TEST_TIMEOUT_SECONDS = float(os.getenv("TEST_TIMEOUT", 2)) # Default 2 seconds
BATCH_SIZE = 100 # Process nodes in batches to reduce scheduling overhead
DNS_CACHE_EXPIRATION = 2678400 # 31 days
HISTORY_EXPIRATION = 604800 # History records 7 days

# Dynamically set maximum concurrency
def get_optimal_concurrency():
    cpu_count = psutil.cpu_count()
    memory = psutil.virtual_memory()
    available_memory = memory.available / (1024 ** 2) # MB
    base_concurrency = cpu_count * 50
    if available_memory < 1000: # Adjust if memory is low
        base_concurrency = cpu_count * 20
    return min(base_concurrency, 200) # Cap at 200 to prevent excessive resource usage

MAX_CONCURRENT_TASKS = get_optimal_concurrency()

# --- Logging Configuration ---
# Set log level via environment variable, defaults to INFO
LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
logging.basicConfig(level=getattr(logging, LOG_LEVEL, logging.INFO),
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Pre-compiled Regular Expressions ---
PROTOCOL_RE = re.compile(r"^(vless|vmess|trojan|ss|hy2|hysteria2):\/\/[^\s]+$", re.IGNORECASE)
HOST_PORT_RE = re.compile(r"(?:@|:)(\d{1,5})(?:\?|$|#)")
NODE_LINK_RE = re.compile(r"^(vless|vmess|trojan|ss|hy2|hysteria2):\/\/(.*)")
HOST_PORT_FULL_RE = re.compile(r"^(?:\[([0-9a-fA-F:]+)\]|([0-9]{1,3}(?:\.[0-9]{1,3}){3})|([a-zA-Z0-9.-]+)):([0-9]+)$")
IP_RE = re.compile(r"^(?:\[[0-9a-fA-F:]+\]|[0-9]{1,3}(?:\.[0-9]{1,3}){3})$")

# --- Data Structures ---
class NodeTestResult:
    def __init__(self, node_info, status, delay_ms=-1, error_message=""):
        self.node_info = node_info
        self.status = status
        self.delay_ms = delay_ms
        self.error_message = error_message

# --- Global Variables ---
history_results = {}
dns_cache = {}

# --- Helper Functions ---
def normalize_link(link):
    """Normalizes the node link by stripping minor parameters for consistent history keys."""
    try:
        parsed = urlparse(link)
        # We want to keep the scheme, netloc (host:port), and path. Query params and fragments are discarded.
        # This creates a more stable key for history lookup, as minor parameter changes
        # don't create new entries.
        base_link = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        return base_link.rstrip('/') # Remove trailing slash if present
    except Exception as e:
        logger.warning(f"Failed to normalize link '{link}': {e}")
        return link # Return original link if normalization fails

async def bulk_dns_lookup(hostnames):
    """Performs bulk DNS lookups, prioritizing cached results."""
    resolver = aiodns.DNSResolver(nameservers=["8.8.8.8", "1.1.1.1"])
    results = {}
    current_time = int(time.time())
    cache_hits = 0

    to_resolve = []
    for hostname in hostnames:
        if hostname in dns_cache and current_time - dns_cache[hostname]["timestamp"] < DNS_CACHE_EXPIRATION:
            results[hostname] = dns_cache[hostname]["ip"]
            cache_hits += 1
        else:
            to_resolve.append(hostname)

    if to_resolve:
        # Create tasks for all hostnames to be resolved
        tasks = [resolver.query(hostname, 'A') for hostname in to_resolve]
        responses = await asyncio.gather(*tasks, return_exceptions=True) # Gather results concurrently

        for hostname, response in zip(to_resolve, responses):
            if isinstance(response, Exception):
                try:
                    # Attempt IPv6 if IPv4 fails
                    response = await resolver.query(hostname, 'AAAA')
                    if response:
                        ip = response[0].host
                        results[hostname] = ip
                        dns_cache[hostname] = {"ip": ip, "timestamp": current_time}
                        logger.debug(f"Resolved {hostname} to IPv6: {ip}")
                except Exception as e:
                    logger.debug(f"DNS resolution failed for {hostname}: {e}")
                continue # Skip to next hostname if resolution failed
            if response:
                ip = response[0].host
                results[hostname] = ip
                dns_cache[hostname] = {"ip": ip, "timestamp": current_time}
                logger.debug(f"Resolved {hostname} to IPv4: {ip}")

    logger.info(f"DNS lookup summary: {len(hostnames)} total, {cache_hits} cache hits ({cache_hits/len(hostnames)*100:.2f}%), {len(results)} successfully resolved.")
    return results

async def load_history():
    """Asynchronously loads historical test results."""
    global history_results
    if os.path.exists(HISTORY_FILE):
        try:
            async with aiofiles.open(HISTORY_FILE, "r", encoding="utf-8") as f:
                content = await f.read()
                if content: # Ensure file is not empty
                    history_results = json.loads(content)
                else:
                    logger.warning("History file is empty, initializing an empty history.")
                    history_results = {}
            logger.info(f"History results loaded: {len(history_results)} records.")
        except json.JSONDecodeError as e:
            logger.warning(f"History results file corrupted or invalid JSON, re-initializing: {e}")
            history_results = {}
        except Exception as e:
            logger.error(f"Error loading history file: {e}")
            history_results = {}
    else:
        logger.info("History results file not found, will create a new one.")

async def save_history():
    """Asynchronously saves historical test results, cleaning expired records."""
    current_time = int(time.time())
    # Filter out expired records based on HISTORY_EXPIRATION
    cleaned_history = {
        node_id: data for node_id, data in history_results.items()
        if current_time - data.get("timestamp", 0) < HISTORY_EXPIRATION
    }
    os.makedirs(DATA_DIR, exist_ok=True)
    async with aiofiles.open(HISTORY_FILE, "w", encoding="utf-8") as f:
        await f.write(json.dumps(cleaned_history, indent=2, ensure_ascii=False))
    logger.info(f"History results saved: {len(cleaned_history)} records after cleaning.")

async def load_dns_cache():
    """Asynchronously loads the DNS cache."""
    global dns_cache
    if os.path.exists(DNS_CACHE_FILE):
        try:
            async with aiofiles.open(DNS_CACHE_FILE, "r", encoding="utf-8") as f:
                content = await f.read()
                if content: # Ensure file is not empty
                    dns_cache = json.loads(content)
                else:
                    logger.warning("DNS cache file is empty, initializing an empty cache.")
                    dns_cache = {}
            logger.info(f"DNS cache loaded: {len(dns_cache)} records.")
        except json.JSONDecodeError as e:
            logger.warning(f"DNS cache file corrupted or invalid JSON, re-initializing: {e}")
            dns_cache = {}
        except Exception as e:
            logger.error(f"Error loading DNS cache file: {e}")
            dns_cache = {}
    else:
        logger.info("DNS cache file not found, will create a new one.")

async def save_dns_cache():
    """Asynchronously saves the DNS cache, cleaning expired records."""
    current_time = int(time.time())
    # Filter out expired records based on DNS_CACHE_EXPIRATION
    cleaned_cache = {
        host: data for host, data in dns_cache.items()
        if current_time - data.get("timestamp", 0) < DNS_CACHE_EXPIRATION
    }
    os.makedirs(DATA_DIR, exist_ok=True)
    async with aiofiles.open(DNS_CACHE_FILE, "w", encoding="utf-8") as f:
        await f.write(json.dumps(cleaned_cache, indent=2, ensure_ascii=False))
    logger.info(f"DNS cache saved and expired records cleaned: {len(cleaned_cache)} records.")

async def fetch_ss_txt(url):
    """Fetches the node list from the given URL."""
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=15) as client: # Increased timeout slightly
            response = await client.get(url)
            response.raise_for_status()
            return response.text
    except httpx.RequestError as e:
        logger.error(f"Failed to fetch node list from {url}: {e}")
        return None
    except Exception as e:
        logger.error(f"An unknown error occurred while fetching node list from {url}: {e}")
        return None

def prefilter_links(links):
    """Prefilters invalid node links based on basic format and presence of host/port."""
    valid_links = []
    for link in links:
        link = link.strip()
        if not link:
            continue
        if not PROTOCOL_RE.match(link):
            logger.debug(f"Filtering invalid link (protocol mismatch): {link}")
            continue
        if not HOST_PORT_RE.search(link):
            logger.debug(f"Filtering invalid link (missing port): {link}")
            continue
        valid_links.append(link)
    logger.info(f"Pre-filtering complete: {len(links)} original links, {len(valid_links)} retained.")
    return valid_links

def parse_node_info(link):
    """Parses node information from a given link."""
    node_info = {'original_link': link}
    try:
        link = link.strip()
        if not link:
            return None

        match = NODE_LINK_RE.match(link)
        if not match:
            logger.debug(f"Unrecognized protocol for link: {link}")
            return None

        protocol = match.group(1).lower()
        remaining_part = match.group(2)
        node_info['protocol'] = protocol

        if '#' in remaining_part:
            remaining_part, remarks = remaining_part.rsplit('#', 1)
            node_info['remarks'] = unquote(remarks)
        else:
            node_info['remarks'] = f"{protocol.upper()} Node"

        if protocol in ['vless', 'vmess', 'trojan', 'ss']:
            # For these protocols, the format is usually <user_info>@<host>:<port>?<query>#<remarks>
            if '@' in remaining_part:
                user_info_part, host_port_part = remaining_part.split('@', 1)
            else:
                user_info_part = "" # For SS, it might just be <base64_encoded_info>
                host_port_part = remaining_part

            if '?' in host_port_part:
                host_port_str, query_str = host_port_part.split('?', 1)
                query_params = parse_qs(query_str)
            else:
                host_port_str = host_port_part
                query_params = {}

            host_match = HOST_PORT_FULL_RE.match(host_port_str)
            if host_match:
                node_info['server'] = host_match.group(1) or host_match.group(2) or host_match.group(3)
                node_info['port'] = int(host_match.group(4))
                if not (1 <= node_info['port'] <= 65535):
                    logger.debug(f"Invalid port number (range 1-65535): {node_info['port']} in {link}")
                    return None
            else:
                logger.debug(f"Could not parse host:port from {host_port_str} in {link}")
                return None

            for key, values in query_params.items():
                node_info[key] = values[0] # Take the first value for each key

        elif protocol in ['hy2', 'hysteria2']:
            # Hysteria2 format: hy2://<host>:<port>?<query>#<remarks>
            parts = remaining_part.split('?', 1)
            host_port_str = parts[0]
            query_params = parse_qs(parts[1]) if len(parts) > 1 else {}

            host_match = HOST_PORT_FULL_RE.match(host_port_str)
            if host_match:
                node_info['server'] = host_match.group(1) or host_match.group(2) or host_match.group(3)
                node_info['port'] = int(host_match.group(4))
                if not (1 <= node_info['port'] <= 65535):
                    logger.debug(f"Invalid port number (range 1-65535): {node_info['port']} in {link}")
                    return None
            else:
                logger.debug(f"Could not parse hy2 host:port from {host_port_str} in {link}")
                return None
            for key, values in query_params.items():
                node_info[key] = values[0]

        else:
            logger.warning(f"Unsupported protocol type: {protocol} for link {link}")
            return None

        # Determine if the server is a domain or an IP address
        if not IP_RE.match(node_info['server']):
            node_info['is_domain'] = True
        else:
            node_info['is_domain'] = False
            node_info['resolved_ip'] = node_info['server'] # If it's an IP, it's already resolved

        return node_info

    except Exception as e:
        logger.error(f"Error parsing node link '{link}': {e}", exc_info=False) # exc_info=False to avoid full traceback for every parsing error
        return None

async def check_node(node_info):
    """Tests node connectivity."""
    node_id = normalize_link(node_info['original_link']) # Use normalized link for history key
    current_time = time.time()

    # Check history cache for recent successful/failed results
    if node_id in history_results:
        record = history_results[node_id]
        if record['status'] == 'Successful' and current_time - record['timestamp'] < 300: # Re-check successful every 5 min
            logger.debug(f"Using cached successful result for {node_info['remarks']}")
            return NodeTestResult(node_info, 'Successful', record['delay_ms'])
        elif record['status'] == 'Failed' and current_time - record['timestamp'] < HISTORY_EXPIRATION: # Don't re-check failed if recent
            logger.debug(f"Skipping recently failed node: {node_info['remarks']}")
            return NodeTestResult(node_info, 'Failed', -1, record['error_message'])

    protocol = node_info.get('protocol')
    remarks = node_info.get('remarks', 'N/A')
    server = node_info.get('server')
    port = node_info.get('port')
    target_host = node_info.get('resolved_ip') # Use the pre-resolved IP

    if not all([server, port, target_host]):
        return NodeTestResult(node_info, "Failed", -1, "Incomplete info or DNS resolution failed")

    test_start_time = time.monotonic()
    error_message = ""
    sock = None
    wrapped_socket = None

    try:
        # Hysteria2 uses UDP
        if protocol in ['hy2', 'hysteria2']:
            try:
                # UDP check: just try to send a small packet and see if it goes through
                # This is a very basic check; a real Hysteria2 client would do more.
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(TEST_TIMEOUT_SECONDS)
                sock.connect((target_host, port))
                sock.sendall(b'ping')
                # No response expected for basic UDP reachability, just check if send succeeded
                logger.debug(f"UDP port {target_host}:{port} appears reachable.")
                test_end_time = time.monotonic()
                delay = (test_end_time - test_start_time) * 1000
                return NodeTestResult(node_info, "Successful", delay)
            except socket.timeout:
                error_message = "UDP Connection Timeout"
            except ConnectionRefusedError:
                error_message = "UDP Connection Refused"
            except Exception as e:
                error_message = f"UDP Test Error: {e}"
            finally:
                if sock:
                    sock.close()
            return NodeTestResult(node_info, "Failed", -1, error_message)

        # For other protocols (VLESS, VMESS, Trojan, SS) assume TCP
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(TEST_TIMEOUT_SECONDS)
            await asyncio.get_event_loop().run_in_executor(
                None, sock.connect, (target_host, port)
            )

            # Handle TLS handshake if 'security' is 'tls' (common for VLESS/Trojan)
            if node_info.get('security') == 'tls':
                context = ssl.create_default_context()
                context.check_hostname = False # We're just checking connectivity, not certificate validity
                context.verify_mode = ssl.CERT_NONE # Disable certificate verification for reachability check
                sni_hostname = node_info.get('sni') or node_info.get('host') or node_info['server']
                wrapped_socket = context.wrap_socket(sock, server_hostname=sni_hostname)
                await asyncio.get_event_loop().run_in_executor(
                    None, wrapped_socket.do_handshake
                )
            test_end_time = time.monotonic()
            delay = (test_end_time - test_start_time) * 1000
            logger.info(f"Tested {remarks} ({target_host}:{port}) - Status: Successful, Delay: {delay:.2f}ms")
            return NodeTestResult(node_info, "Successful", delay)

        except socket.timeout:
            error_message = "TCP Connection Timeout"
        except ConnectionRefusedError:
            error_message = "TCP Connection Refused"
        except ssl.SSLError as e:
            error_message = f"TLS Handshake Error: {e}"
        except Exception as e:
            error_message = f"Unexpected error during TCP/TLS test: {e}"
        finally:
            if wrapped_socket:
                wrapped_socket.close()
            if sock:
                sock.close()

    except Exception as e: # Catch any high-level errors during the test process
        error_message = f"Critical error during node check: {e}"
    finally: # Ensure sockets are closed even if an unexpected error occurs above
        if wrapped_socket:
            wrapped_socket.close()
        if sock:
            sock.close()

    logger.warning(f"Tested {remarks} ({target_host}:{port}) - Status: Failed, Delay: -1ms, Error: {error_message}")
    return NodeTestResult(node_info, "Failed", -1, error_message)

async def test_nodes_in_batches(nodes, batch_size=BATCH_SIZE):
    """Tests nodes in batches with a concurrency limit."""
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_TASKS)
    async def test_node_with_semaphore(node):
        async with semaphore:
            return await check_node(node)

    all_results = []
    # Create all tasks upfront
    tasks = [test_node_with_semaphore(node) for node in nodes]

    # Gather results in batches to provide progress feedback
    for i in range(0, len(tasks), batch_size):
        batch_tasks = tasks[i:i + batch_size]
        batch_results = await asyncio.gather(*batch_tasks)
        all_results.extend(batch_results)
        logger.info(f"Completed batch {i // batch_size + 1}/{len(tasks) // batch_size + 1}. Processed {len(all_results)}/{len(nodes)} nodes so far.")

    return all_results

def generate_summary(test_results):
    """Generates a summary of the test results."""
    successful_nodes = [r for r in test_results if r.status == "Successful"]
    success_count = len(successful_nodes)
    total_count = len(test_results)
    success_rate = (success_count / total_count * 100) if total_count else 0
    avg_delay = sum(r.delay_ms for r in successful_nodes) / success_count if success_count else -1
    logger.info(f"Test Summary: {success_count}/{total_count} successful ({success_rate:.2f}%), Average Delay: {avg_delay:.2f}ms")

async def main():
    """Main function to orchestrate the node testing process."""
    start_time = time.time()
    os.makedirs(DATA_DIR, exist_ok=True) # Ensure data directory exists

    await load_history()
    await load_dns_cache()

    ss_txt_content = await fetch_ss_txt(SS_TXT_URL)
    if not ss_txt_content:
        logger.error("Failed to fetch node list or list is empty, exiting.")
        # Ensure sub.txt is written even if no nodes are found
        async with aiofiles.open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
            await f.write("# No valid nodes found or tested.\n")
        return

    links = ss_txt_content.strip().split('\n')
    filtered_links = prefilter_links(links)
    if not filtered_links:
        logger.warning("No valid links after pre-filtering, exiting.")
        async with aiofiles.open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
            await f.write("# No valid nodes found or tested.\n")
        return

    # Use ThreadPoolExecutor for CPU-bound parsing tasks
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor() as executor:
        parsed_nodes = await loop.run_in_executor(
            executor,
            lambda: [parse_node_info(link) for link in filtered_links if parse_node_info(link)]
        )
    # Filter out None values from parsing failures
    parsed_nodes = [node for node in parsed_nodes if node is not None]
    total_parsed_nodes = len(parsed_nodes)
    logger.info(f"Total parsed nodes: {total_parsed_nodes}")

    if not parsed_nodes:
        logger.warning("No valid nodes parsed, exiting.")
        async with aiofiles.open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
            await f.write("# No valid nodes found.\n")
        return

    # Filter nodes based on history: prioritize recently successful, skip recently failed
    current_time = time.time()
    failed_nodes_normalized_links = {
        normalize_link(node_id) for node_id, data in history_results.items()
        if data['status'] == 'Failed' and current_time - data['timestamp'] < HISTORY_EXPIRATION
    }
    successful_nodes_normalized_links = {
        normalize_link(node_id) for node_id, data in history_results.items()
        if data['status'] == 'Successful' and current_time - data['timestamp'] < HISTORY_EXPIRATION
    }

    # Separate nodes into those to prioritize (recent success) and others
    priority_nodes = []
    other_nodes = []
    for node in parsed_nodes:
        normalized_link = normalize_link(node['original_link'])
        if normalized_link in successful_nodes_normalized_links:
            priority_nodes.append(node)
        elif normalized_link not in failed_nodes_normalized_links:
            other_nodes.append(node)
        else:
            # Node is a recently failed one, mark it in history (if not already there)
            if normalized_link not in history_results: # Should ideally be in history if in failed_nodes_normalized_links
                history_results[normalized_link] = {
                    "status": "Failed",
                    "error_message": "Skipped due to recent failure history",
                    "timestamp": int(time.time())
                }
            logger.debug(f"Skipping {node.get('remarks')} due to recent failure history.")

    # Combine lists, prioritizing successful ones
    nodes_to_test = priority_nodes + other_nodes
    logger.info(f"Nodes prepared for testing: {len(nodes_to_test)}/{total_parsed_nodes} (prioritizing {len(priority_nodes)} previously successful nodes).")

    # Pre-resolve domains and update node info
    logger.info("Starting bulk DNS resolution for domains...")
    domains_to_resolve = {node['server'] for node in nodes_to_test if node.get('is_domain')}
    resolved_ips = await bulk_dns_lookup(domains_to_resolve)
    logger.info("Bulk DNS resolution complete.")

    # Update resolved_ip for domain nodes and filter out those that failed DNS resolution
    nodes_for_testing = []
    for node in nodes_to_test:
        if node.get('is_domain'):
            if node['server'] in resolved_ips:
                node['resolved_ip'] = resolved_ips[node['server']]
                nodes_for_testing.append(node)
            else:
                # If DNS failed, mark this node as failed in history
                normalized_link = normalize_link(node['original_link'])
                history_results[normalized_link] = {
                    "status": "Failed",
                    "error_message": "DNS resolution failed",
                    "timestamp": int(time.time())
                }
                logger.debug(f"Skipping {node.get('remarks')} because DNS resolution failed.")
        else:
            nodes_for_testing.append(node) # Already has 'resolved_ip' if it's an IP

    logger.info(f"Initiating connectivity tests for {len(nodes_for_testing)} nodes.")
    test_results = await test_nodes_in_batches(nodes_for_testing) # Corrected: pass the whole list for batch processing

    # Save results to history
    successful_links_for_output = []
    for result in test_results:
        node_id = normalize_link(result.node_info['original_link'])
        if result.status == "Successful":
            successful_links_for_output.append(result.node_info['original_link'])
            history_results[node_id] = {
                "status": "Successful",
                "delay_ms": result.delay_ms,
                "timestamp": int(time.time())
            }
        else:
            history_results[node_id] = {
                "status": "Failed",
                "error_message": result.error_message,
                "timestamp": int(time.time())
            }

    # Generate summary
    generate_summary(test_results)
    successful_nodes_count = len(successful_links_for_output)
    failed_nodes_count = len(test_results) - successful_nodes_count
    logger.info(f"Testing complete. Successful nodes: {successful_nodes_count}, Failed nodes: {failed_nodes_count}.")

    # Write to sub.txt
    async with aiofiles.open(SUCCESSFUL_NODES_OUTPUT_FILE, "w", encoding="utf-8") as f:
        if successful_links_for_output:
            await f.write("\n".join(successful_links_for_output) + "\n")
            logger.info(f"Wrote {len(successful_links_for_output)} nodes to {SUCCESSFUL_NODES_OUTPUT_FILE}.")
        else:
            await f.write("# No valid nodes found.\n")
            logger.info(f"No successful nodes found, wrote empty message to {SUCCESSFUL_NODES_OUTPUT_FILE}.")

    await save_history()
    await save_dns_cache()
    logger.info(f"Total script execution time: {time.time() - start_time:.2f} seconds.")

if __name__ == "__main__":
    asyncio.run(main())
