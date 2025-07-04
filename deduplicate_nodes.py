import requests
import os
import re
import datetime
import urllib.parse
import logging
import base64
import json
import socket
import platform
import subprocess
from urllib.parse import parse_qs
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type
import argparse
import concurrent.futures # Import the concurrent module for parallel processing

# Configure logging
def setup_logging(debug: bool):
    """
    Configures the logging level based on debug mode.
    If debug is True, logs at DEBUG level; otherwise, logs at INFO level.
    """
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('node_deduplication.log', encoding='utf-8'),
            logging.StreamHandler()
        ]
    )

class NodeStandardizer:
    """Node standardizer, responsible for parsing and standardizing node URLs of different protocols."""
    
    @staticmethod
    def clean_node_url(node_url: str) -> str:
        """
        Cleans the node URL, removing invisible characters, extra spaces, and handling encoding issues.
        """
        if not node_url:
            return ""
        # Remove control characters, spaces, tabs, newlines, etc.
        node_url = re.sub(r'[\x00-\x1F\x7F\x80-\x9F\s]+', '', node_url).strip().rstrip('/')
        # Attempt to decode possible double URL encoding multiple times
        for _ in range(3):
            try:
                decoded = urllib.parse.unquote(node_url, errors='ignore')
                if decoded == node_url:
                    break
                node_url = decoded
            except Exception:
                break
        return node_url

    @staticmethod
    def standardize_node_minimal(node_url: str, debug: bool = False) -> tuple[str | None, str, str | None, str | None, int | None]:
        """
        Standardizes the node URL, extracting core information for deduplication,
        and retaining the original node, hostname/IP, and port.
        Returns (standardized node string, protocol type, original node, hostname/IP, port).
        """
        if not node_url:
            return None, "unknown", None, None, None

        node_url_cleaned = NodeStandardizer.clean_node_url(node_url)
        match = re.match(r"^(?P<protocol>hysteria2|vmess|trojan|ss|ssr|vless)://(?P<data>.*)", 
                         node_url_cleaned, re.IGNORECASE)
        if not match:
            if debug:
                logging.debug(f"Unsupported protocol or malformed format: {node_url}")
            return None, "unknown", None, None, None

        protocol = match.group("protocol").lower()
        data_part = match.group("data")
        host = None
        port = None

        try:
            core_data = data_part.split('?', 1)[0].split('#', 1)[0]
            core_data_standardized = urllib.parse.unquote_plus(core_data).strip()

            if protocol == "vmess":
                result, host, port = NodeStandardizer._standardize_vmess(core_data_standardized, data_part)
            elif protocol == "vless":
                result, host, port = NodeStandardizer._standardize_vless(core_data_standardized, data_part)
            elif protocol in ("trojan", "hysteria2"):
                result, host, port = NodeStandardizer._standardize_trojan_hysteria2(protocol, core_data_standardized)
            elif protocol == "ss":
                result, host, port = NodeStandardizer._standardize_ss(core_data_standardized)
            elif protocol == "ssr":
                result, host, port = NodeStandardizer._standardize_ssr(core_data_standardized)
            else:
                result = None

            if result and debug:
                logging.debug(f"Deduplication key: {result} (Original: {node_url})")
            return result, protocol, node_url, host, port

        except Exception as e:
            logging.error(f"Error standardizing node {node_url}: {e}")
            return None, "unknown", None, None, None

    @staticmethod
    def _standardize_vmess(core_data: str, full_data: str) -> tuple[str | None, str | None, int | None]:
        """Handles vmess protocol."""
        parts = core_data.split('@', 1)
        if len(parts) != 2:
            return None, None, None
        uuid, address_port = parts
        address = None
        port = None
        try:
            # Attempt base64 decoding
            decoded = json.loads(base64.b64decode(uuid + '=' * (-len(uuid) % 4)).decode('utf-8', errors='ignore'))
            uuid = decoded.get('id', '').lower()
            address = decoded.get('add', '').lower()
            port = int(decoded.get('port', 0))
            if NodeStandardizer.is_valid_port(str(port)):
                return f"vmess://{uuid}@{address}:{port}", address, port
            return None, None, None
        except (base64.binascii.Error, json.JSONDecodeError, UnicodeDecodeError):
            # Fallback: try direct parsing
            address_parts = address_port.rsplit(':', 1)
            if len(address_parts) == 2 and NodeStandardizer.is_valid_port(address_parts[1]):
                address = address_parts[0].lower()
                port = int(address_parts[1])
                return f"vmess://{uuid.lower()}@{address_port.lower()}", address, port
            return None, None, None

    @staticmethod
    def _standardize_vless(core_data: str, full_data: str) -> tuple[str | None, str | None, int | None]:
        """Handles vless protocol."""
        parts = core_data.split('@', 1)
        if len(parts) != 2:
            return None, None, None
        uuid, address_port = parts
        address_parts = address_port.rsplit(':', 1)
        if len(address_parts) == 2 and NodeStandardizer.is_valid_port(address_parts[1]):
            address = address_parts[0].lower()
            port = int(address_parts[1])
            query = full_data.split('?', 1)[1].split('#', 1)[0] if '?' in full_data else ''
            params = parse_qs(query)
            encryption = params.get('encryption', ['none'])[0].lower()
            transport = params.get('type', ['tcp'])[0].lower()
            security = params.get('security', ['none'])[0].lower()
            flow = params.get('flow', [''])[0].lower()
            sni = params.get('sni', [''])[0].lower()
            fp = params.get('fp', [''])[0].lower()
            return f"vless://{uuid.lower()}@{address_port.lower()}?encryption={encryption}&type={transport}&security={security}&flow={flow}&sni={sni}&fp={fp}", address, port
        return None, None, None

    @staticmethod
    def _standardize_trojan_hysteria2(protocol: str, core_data: str) -> tuple[str | None, str | None, int | None]:
        """Handles trojan and hysteria2 protocols."""
        parts = core_data.split('@', 1)
        if len(parts) != 2:
            return None, None, None
        password, address_port = parts
        address_parts = address_port.rsplit(':', 1)
        if len(address_parts) == 2 and NodeStandardizer.is_valid_port(address_parts[1]):
            address = address_parts[0].lower()
            port = int(address_parts[1])
            return f"{protocol}://{urllib.parse.quote(password, safe='')}@{address_port.lower()}", address, port
        return None, None, None

    @staticmethod
    def _standardize_ss(core_data: str) -> tuple[str | None, str | None, int | None]:
        """Handles ss protocol."""
        if '@' not in core_data or ':' not in core_data.split('@')[0]:
            return None, None, None
        try:
            auth_info, server_info = core_data.split('@', 1)
            method, password = auth_info.split(':', 1)
            host, port_str = server_info.rsplit(':', 1)
            if NodeStandardizer.is_valid_port(port_str):
                port = int(port_str)
                return f"ss://{method.lower()}:{urllib.parse.quote(password, safe='')}@{host.lower()}:{port}", host.lower(), port
            return None, None, None
        except ValueError:
            logging.debug(f"Could not parse SS core format: {core_data}")
            return None, None, None

    @staticmethod
    def _standardize_ssr(core_data: str) -> tuple[str | None, str | None, int | None]:
        """Handles ssr protocol."""
        parts = core_data.split(':')
        if len(parts) < 6:
            return None, None, None
        try:
            host, port_str, proto, method, obfs, password = parts[:6]
            password = urllib.parse.unquote_plus(password)
            if NodeStandardizer.is_valid_port(port_str):
                port = int(port_str)
                return f"ssr://{host.lower()}:{port}:{proto.lower()}:{method.lower()}:{obfs.lower()}:{urllib.parse.quote(password, safe='')}", host.lower(), port
            return None, None, None
        except ValueError:
            logging.debug(f"Could not parse SSR core format: {core_data}")
            return None, None, None

    @staticmethod
    def is_valid_port(port: str) -> bool:
        """Validates if the port number is valid."""
        try:
            return 0 < int(port) <= 65535
        except ValueError:
            return False

class NodeConnectivityChecker:
    """Node connectivity checker, supporting both ICMP Ping and TCP port check."""
    
    @staticmethod
    def check_icmp_ping(host: str, count: int = 1, timeout: int = 1) -> tuple[bool, str]:
        """
        Pings the given hostname or IP address using ICMP.
        
        Args:
            host (str): The hostname or IP address to ping.
            count (int): Number of pings to send.
            timeout (int): Timeout for each ping request in seconds.
            
        Returns:
            tuple[bool, str]: Returns (True, IP address) if at least one ping is successful,
            otherwise returns (False, IP address or error message).
        """
        ip_address = None
        try:
            ip_address = socket.gethostbyname(host)
        except socket.gaierror:
            logging.info(f"ICMP Ping {host} - Hostname could not be resolved.") 
            return False, host # Return original host if resolution fails

        param = '-n' if platform.system().lower() == 'windows' else '-c'
        timeout_param = '-w' if platform.system().lower() == 'windows' else '-W' 

        try:
            # For Windows, timeout parameter unit is milliseconds, so multiply by 1000
            actual_timeout = timeout * 1000 if platform.system().lower() == 'windows' else timeout
            command = ['ping', param, str(count), timeout_param, str(actual_timeout), ip_address]
            
            process = subprocess.run(command, capture_output=True, text=True, timeout=timeout * count + 2) 
            
            if process.returncode == 0:
                logging.info(f"ICMP Ping {host} ({ip_address}) successful.") 
                return True, ip_address
            else:
                logging.info(f"ICMP Ping {host} ({ip_address}) failed. Error code: {process.returncode}, Output: {process.stdout.strip()} {process.stderr.strip()}")
                return False, ip_address
        except subprocess.TimeoutExpired:
            logging.info(f"ICMP Ping {host} ({ip_address}) timed out.")
            return False, ip_address
        except Exception as e:
            logging.error(f"Error during ICMP Ping for {host} ({ip_address}): {e}")
            return False, ip_address

    @staticmethod
    def check_tcp_port(host: str, port: int, timeout: int = 1) -> tuple[bool, str]:
        """
        Checks TCP port connectivity for the given host and port.
        
        Args:
            host (str): The hostname or IP address to connect to.
            port (int): The TCP port to check.
            timeout (int): Timeout for the connection attempt in seconds.
            
        Returns:
            tuple[bool, str]: Returns (True, IP address) if connection is successful,
            otherwise returns (False, IP address or error message).
        """
        ip_address = None
        try:
            ip_address = socket.gethostbyname(host)
        except socket.gaierror:
            logging.info(f"TCP Check {host}:{port} - Hostname could not be resolved.")
            return False, host # Return original host if resolution fails

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip_address, port)) # connect_ex returns 0 on success, error code otherwise
            sock.close()
            
            if result == 0:
                logging.info(f"TCP Check {host}:{port} ({ip_address}) successful.")
                return True, ip_address
            else:
                logging.info(f"TCP Check {host}:{port} ({ip_address}) failed. Error code: {result}.")
                return False, ip_address
        except socket.timeout:
            logging.info(f"TCP Check {host}:{port} ({ip_address}) timed out.")
            return False, ip_address
        except Exception as e:
            logging.error(f"Error during TCP Check for {host}:{port} ({ip_address}): {e}")
            return False, ip_address

@retry(stop=stop_after_attempt(3), wait=wait_fixed(2), 
        retry=retry_if_exception_type(requests.exceptions.RequestException))
def fetch_url(url: str) -> requests.Response:
    """Fetches URL with retry mechanism."""
    with requests.Session() as session:
        response = session.get(url, timeout=20, stream=True)
        response.raise_for_status()
        return response

def write_protocol_outputs(nodes: dict, output_dir: str) -> dict:
    """
    Writes deduplicated nodes by protocol to separate files and to a single file.
    Returns the count of nodes for each file.
    """
    os.makedirs(output_dir, exist_ok=True)
    protocol_counts = {}
    all_nodes = []

    # Write by protocol
    for protocol, node_list in nodes.items():
        if node_list:
            output_file = os.path.join(output_dir, f"{protocol}.txt")
            sorted_nodes = sorted(node_list)
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write('\n'.join(sorted_nodes) + '\n') 
            protocol_counts[output_file] = len(sorted_nodes)
            logging.info(f"Written protocol file: {output_file} ({len(sorted_nodes)} nodes)")
            all_nodes.extend(sorted_nodes)

    # Write to a single file
    output_all_file = os.path.join(output_dir, 'all.txt')
    with open(output_all_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(all_nodes)) + '\n')
    protocol_counts[output_all_file] = len(all_nodes)
    logging.info(f"Written single file: {output_all_file} ({len(all_nodes)} nodes)")

    return protocol_counts

def download_and_deduplicate_nodes(args):
    """
    Downloads node data from GitHub Raw link, standardizes and deduplicates,
    saves by protocol, and performs connectivity tests.
    """
    setup_logging(args.debug)
    node_url = args.node_url
    output_dir = args.output_dir
    
    unique_nodes = {}  # Stores original nodes by protocol {protocol: [node1, node2, ...]}
    unique_keys = set()  # Set of deduplication keys
    
    # Stores (original node, hostname/IP, port) tuples for connectivity check
    nodes_for_connectivity_check = [] 
    
    stats = {
        'download_count': 0,
        'total_nodes_processed': 0,
        'failed_to_standardize_count': 0,
        'invalid_format_count': 0,
        'duplicate_count': 0,
        'protocol_counts': {},
        'output_file_counts': {},
        'check_success_count': 0,
        'check_fail_count': 0,
    }
    
    logging.info("--- Starting node download and deduplication ---")
    start_time = datetime.datetime.now()

    try:
        logging.info(f"Downloading: {node_url}")
        response = fetch_url(node_url)
        stats['download_count'] += 1
        
        for line in response.iter_lines(decode_unicode=True):
            node = line.strip()
            if not node:
                continue
            
            stats['total_nodes_processed'] += 1
            minimal_node, protocol, original_node, host, port = NodeStandardizer.standardize_node_minimal(node, args.debug)
            
            if minimal_node and original_node:
                if minimal_node in unique_keys:
                    stats['duplicate_count'] += 1
                    if args.debug:
                        logging.debug(f"Duplicate node found: {minimal_node}")
                else:
                    unique_keys.add(minimal_node)
                    unique_nodes.setdefault(protocol, []).append(original_node)
                    stats['protocol_counts'][protocol] = stats['protocol_counts'].get(protocol, 0) + 1
                    if host and port: # If hostname/IP and port are successfully extracted, add to the check list
                        nodes_for_connectivity_check.append((original_node, host, port))
                    else:
                        if args.debug:
                            logging.debug(f"Skipping connectivity check for node (missing host/port): {original_node}")
            else:
                stats['failed_to_standardize_count'] += 1
                if args.debug:
                    logging.warning(f"Failed to standardize node: {node}")

    except requests.exceptions.RequestException as e:
        logging.error(f"Download failed {node_url}: {e}")
        stats['invalid_format_count'] += 1
    except Exception as e:
        logging.error(f"Unknown error processing {node_url}: {e}")
        stats['invalid_format_count'] += 1

    # Write protocol-specific and single output files
    stats['output_file_counts'] = write_protocol_outputs(unique_nodes, output_dir)

    # Perform node connectivity tests (parallel processing)
    logging.info(f"\n--- Starting node connectivity test (method: {args.check_method}, parallel) ---")
    check_successful_nodes = []
    check_failed_nodes = []
    
    # Set maximum concurrent workers and connection timeout
    MAX_WORKERS = args.max_check_workers 
    CONNECT_TIMEOUT = args.connect_timeout
    total_checks = len(nodes_for_connectivity_check)
    
    # Choose the connectivity check method
    check_function = None
    if args.check_method == 'ping':
        check_function = NodeConnectivityChecker.check_icmp_ping
    elif args.check_method == 'tcp':
        check_function = NodeConnectivityChecker.check_tcp_port
    else:
        logging.error(f"Invalid check method: {args.check_method}. Skipping connectivity tests.")
        check_function = None # Ensure no function is called

    if check_function:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # Submit all connectivity check tasks
            future_to_node = {}
            for original_node, host, port in nodes_for_connectivity_check:
                if args.check_method == 'ping':
                    future_to_node[executor.submit(check_function, host, timeout=CONNECT_TIMEOUT)] = original_node
                elif args.check_method == 'tcp':
                    future_to_node[executor.submit(check_function, host, port, timeout=CONNECT_TIMEOUT)] = original_node
            
            check_count = 0
            for future in concurrent.futures.as_completed(future_to_node):
                original_node = future_to_node[future]
                check_count += 1
                try:
                    is_success, checked_target = future.result()
                    if is_success:
                        check_successful_nodes.append(original_node)
                        stats['check_success_count'] += 1
                    else:
                        check_failed_nodes.append(original_node)
                        stats['check_fail_count'] += 1
                except Exception as exc:
                    logging.error(f"Exception occurred during connectivity check for node {original_node}: {exc}")
                    check_failed_nodes.append(original_node) # Treat nodes with exceptions as failed
                    stats['check_fail_count'] += 1
                
                # Output progress every 1000 nodes or when all are processed
                if check_count % 1000 == 0 or check_count == total_checks:
                    logging.info(f"Processed {check_count}/{total_checks} connectivity check tasks.")
    else:
        logging.warning("No valid connectivity check method selected. Connectivity tests skipped.")

    # Write connectivity check result files
    os.makedirs(output_dir, exist_ok=True)
    check_success_file = os.path.join(output_dir, 'connectivity_successful_nodes.txt')
    with open(check_success_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(check_successful_nodes)) + '\n')
    logging.info(f"Written successful nodes file: {check_success_file} ({len(check_successful_nodes)} nodes)")

    check_fail_file = os.path.join(output_dir, 'connectivity_failed_nodes.txt')
    with open(check_fail_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(sorted(check_failed_nodes)) + '\n')
    protocol_counts[check_fail_file] = len(check_failed_nodes) # Add to output file counts
    logging.info(f"Written failed nodes file: {check_fail_file} ({len(check_failed_nodes)} nodes)")


    end_time = datetime.datetime.now()
    duration = end_time - start_time

    # Output run summary
    logging.info("\n==================== Run Summary ====================")
    logging.info(f"Number of successfully downloaded links: {stats['download_count']}")
    logging.info(f"Total nodes processed: {stats['total_nodes_processed']}")
    logging.info(f"Duplicate nodes count: {stats['duplicate_count']}")
    logging.info(f"Nodes failed to standardize: {stats['failed_to_standardize_count']}")
    logging.info(f"Nodes with invalid format: {stats['invalid_format_count']}")
    logging.info(f"Total valid deduplicated nodes: {sum(stats['protocol_counts'].values())}")
    logging.info("Protocol distribution:")
    for protocol, count in sorted(stats['protocol_counts'].items()):
        logging.info(f"  {protocol}: {count}")
    logging.info("Output files:")
    # Update output_file_counts to include connectivity check result files
    stats['output_file_counts'][check_success_file] = len(check_successful_nodes)
    stats['output_file_counts'][check_fail_file] = len(check_failed_nodes)
    for output_file, count in sorted(stats['output_file_counts'].items()):
        logging.info(f"  {output_file}: {count} nodes")
    logging.info(f"Number of successful checks: {stats['check_success_count']}")
    logging.info(f"Number of failed checks: {stats['check_fail_count']}")
    logging.info(f"Total duration: {duration.total_seconds():.2f} seconds")
    logging.info("==============================================")

def parse_args():
    """Parses command-line arguments."""
    parser = argparse.ArgumentParser(description='Download, deduplicate, and check proxy nodes connectivity.')
    parser.add_argument('--node-url', 
                        default="https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/nodes.txt", 
                        help='URL for the node file')
    parser.add_argument('--output-dir', default='data', help='Output directory')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--max-check-workers', type=int, default=100, # Default max concurrent workers changed to 100
                        help='Maximum number of concurrent workers for connectivity checks.')
    parser.add_argument('--connect-timeout', type=int, default=1, # Renamed to connect-timeout, default 1 second
                        help='Timeout for each connectivity check attempt in seconds.')
    parser.add_argument('--check-method', type=str, default='tcp', choices=['tcp', 'ping'], # New parameter for check method
                        help='Method to use for connectivity checks: "tcp" (default) or "ping".')
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    download_and_deduplicate_nodes(args)
