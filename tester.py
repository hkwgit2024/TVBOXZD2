import requests
import re
import yaml
import subprocess
import os
import time
import sys
import json
import base64
from urllib.parse import urlparse, unquote, parse_qs


# URL to download the raw node list
NODE_LIST_URL = "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
# URL for Mihomo (Clash.Meta) binary (Linux AMD64 latest stable version)
# It's recommended to periodically check the MetaCubeX/mihomo releases page for the latest stable version:
# https://github.com/MetaCubeX/mihomo/releases
MIHOMO_DOWNLOAD_URL = "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.11/mihomo-linux-amd64-v1.19.11.gz"
MIHOMO_BIN_NAME = "mihomo"
CONFIG_FILE = "config.yaml"
OUTPUT_DIR = "data"
OUTPUT_FILE = os.path.join(OUTPUT_DIR, "all.txt")
CLASH_PORT = 7890 # Port for Clash.Meta local proxy
TEST_URL = "http://www.google.com" # URL to test connectivity

def download_file(url, destination):
    """Downloads a file from a URL to a specified destination with progress."""
    print(f"Downloading {url} to {destination}...")
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        total_size = int(response.headers.get('content-length', 0))
        downloaded_size = 0

        with open(destination, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
                downloaded_size += len(chunk)
                if total_size > 0:
                    progress = (downloaded_size / total_size) * 100
                    # Print progress on the same line
                    print(f"\rDownloading: {downloaded_size / (1024*1024):.2f}MB / {total_size / (1024*1024):.2f}MB ({progress:.1f}%)", end='')
                else:
                    print(f"\rDownloading: {downloaded_size / (1024*1024):.2f}MB", end='')
        print("\nDownload complete.") # New line after progress
        return True
    except requests.exceptions.RequestException as e:
        print(f"\nError downloading {url}: {e}") # New line before error
        return False

def setup_mihomo():
    """Downloads, extracts, and sets up the Mihomo binary."""
    print("Checking Mihomo binary setup...")
    if not os.path.exists(MIHOMO_BIN_NAME):
        archive_name = os.path.basename(MIHOMO_DOWNLOAD_URL)
        if not download_file(MIHOMO_DOWNLOAD_URL, archive_name):
            sys.exit("Failed to download Mihomo binary.")

        print(f"Extracting {archive_name}...")
        try:
            if archive_name.endswith('.gz'):
                # Redirect gunzip output to sys.stdout for visibility
                subprocess.run(["gunzip", "-f", archive_name], check=True, stdout=sys.stdout, stderr=sys.stderr)
                extracted_name = archive_name.replace(".gz", "")

                # Try to find the extracted file and rename it
                found_extracted = False
                for p_name in [extracted_name, "mihomo", "clash", "clash-linux-amd64"]:
                    if os.path.exists(p_name) and not os.path.isdir(p_name):
                        os.rename(p_name, MIHOMO_BIN_NAME)
                        found_extracted = True
                        break
                if not found_extracted:
                    print(f"Error: Could not find the extracted Mihomo binary in common names after gunzip. Please verify the archive content.")
                    sys.exit("Failed to find extracted Mihomo binary.")
            else:
                print(f"Error: Unsupported archive format: {archive_name}. Expected .gz")
                sys.exit("Unsupported Mihomo archive format.")
        except subprocess.CalledProcessError as e:
            print(f"Error during extraction: {e}")
            sys.exit("Mihomo extraction failed.")
        except Exception as e:
            print(f"An unexpected error occurred during Mihomo setup: {e}")
            sys.exit("Mihomo setup failed.")

    os.chmod(MIHOMO_BIN_NAME, 0o755)
    print(f"{MIHOMO_BIN_NAME} is set up and executable.")

def download_and_parse_nodes(url):
    """Downloads node configurations and parses them."""
    print(f"Downloading node list from {url}...")
    try:
        response = requests.get(url)
        response.raise_for_status()
        content = response.text
    except requests.exceptions.RequestException as e:
        print(f"Error downloading node list: {e}")
        return []

    protocols = ["hysteria2://", "vmess://", "trojan://", "ss://", "ssr://", "vless://"]
    nodes = set()
    for line in content.splitlines():
        line = line.strip()
        for protocol in protocols:
            if line.startswith(protocol):
                nodes.add(line)
                break
    print(f"Found {len(nodes)} unique nodes.")
    return list(nodes)

def create_clash_config(node_url):
    """Creates a basic Clash.Meta config for a single node."""
    proxy_name = f"proxy-{hash(node_url) % 100000}" # Simple unique name for the proxy
    config = {
        "port": CLASH_PORT,
        "mode": "direct",
        "log-level": "info", # Changed from 'silent' to 'info' for more debugging logs
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "proxies": [],
        "proxy-groups": [
            {
                "name": "select",
                "type": "select",
                "proxies": [proxy_name]
            }
        ],
        "rules": [
            "MATCH,select"
        ]
    }

    # Simplified parsing for various protocols into Clash.Meta YAML format
    if node_url.startswith("vmess://"):
        try:
            vmess_b64 = node_url[len("vmess://"):]
            decoded_vmess = json.loads(base64.b64decode(vmess_b64).decode('utf-8'))
            config["proxies"].append({
                "name": proxy_name,
                "type": "vmess",
                "server": decoded_vmess.get("add"),
                "port": int(decoded_vmess.get("port")),
                "uuid": decoded_vmess.get("id"),
                "alterId": int(decoded_vmess.get("aid", 0)),
                "cipher": decoded_vmess.get("scy", "auto"),
                "network": decoded_vmess.get("net", "tcp"),
                "tls": decoded_vmess.get("tls", "") == "tls",
                "skip-cert-verify": decoded_vmess.get("v", "") == "1" or decoded_vmess.get("allowInsecure", False), # 'v' for v2rayN and 'allowInsecure' for Clash
                "ws-opts": {
                    "path": decoded_vmess.get("path", "/"),
                    "headers": {"Host": decoded_vmess.get("host", decoded_vmess.get("add"))}
                } if decoded_vmess.get("net") == "ws" else {}
            })
        except Exception as e:
            print(f"Error parsing vmess node {node_url}: {e}")
            return None
    elif node_url.startswith("ss://"):
        try:
            # SS links are complex. This is a very basic attempt.
            # Real-world SS parsing needs a dedicated library (e.g., handling plugin, method, password encoding)
            parsed_url = urlparse(node_url)
            method_password = parsed_url.username
            server = parsed_url.hostname
            port = parsed_url.port
            # Decode method_password if it's base64 encoded
            if method_password:
                try:
                    method_password = base64.b64decode(method_password + '=' * (-len(method_password) % 4)).decode('utf-8')
                except:
                    pass # Not base64, use directly

            if ':' in method_password:
                method, password = method_password.split(':', 1)
            else:
                method = "auto" # Fallback, might not be correct
                password = method_password

            config["proxies"].append({
                "name": proxy_name,
                "type": "ss",
                "server": server,
                "port": port,
                "cipher": method,
                "password": password,
                # Add plugin, udp-over-tcp, etc. if needed after parsing
            })
        except Exception as e:
            print(f"Error parsing ss node {node_url}: {e}")
            return None
    elif node_url.startswith("trojan://"):
        try:
            parsed_url = urlparse(node_url)
            password = parsed_url.username
            server = parsed_url.hostname
            port = parsed_url.port
            config["proxies"].append({
                "name": proxy_name,
                "type": "trojan",
                "server": server,
                "port": port,
                "password": password,
                "tls": True,
                "skip-cert-verify": True # Often needed for self-signed or custom certs
            })
        except Exception as e:
            print(f"Error parsing trojan node {node_url}: {e}")
            return None
    elif node_url.startswith("vless://"):
        try:
            parsed_url = urlparse(node_url)
            uuid = parsed_url.username
            server = parsed_url.hostname
            port = parsed_url.port
            params = parse_qs(parsed_url.query)

            network = params.get('type', ['tcp'])[0]
            tls_enabled = params.get('security', [''])[0] == 'tls'
            ws_path = params.get('path', ['/'])[0]
            ws_headers_host = params.get('host', [server])[0]
            flow = params.get('flow', [None])[0]

            vless_proxy = {
                "name": proxy_name,
                "type": "vless",
                "server": server,
                "port": port,
                "uuid": uuid,
                "network": network,
                "tls": tls_enabled,
                "udp": True # Common for VLESS
            }
            if flow:
                vless_proxy["flow"] = flow

            if network == "ws":
                vless_proxy["ws-opts"] = {
                    "path": ws_path,
                    "headers": {"Host": ws_headers_host}
                }
            config["proxies"].append(vless_proxy)
        except Exception as e:
            print(f"Error parsing vless node {node_url}: {e}")
            return None
    elif node_url.startswith("hysteria2://"):
        try:
            parsed_url = urlparse(node_url)
            server = parsed_url.hostname
            port = parsed_url.port
            password = parsed_url.username
            params = parse_qs(parsed_url.query)

            obfs = params.get('obfs', [None])[0]
            obfs_password = params.get('obfs-password', [None])[0]
            alpn = params.get('alpn', [None])[0]

            hysteria2_proxy = {
                "name": proxy_name,
                "type": "hysteria2",
                "server": server,
                "port": port,
                "password": password,
                "tls": True,
                "skip-cert-verify": params.get('insecure', ['0'])[0] == '1' # 'insecure' parameter for skip-cert-verify
            }
            if obfs:
                hysteria2_proxy["obfs"] = obfs
            if obfs_password:
                hysteria2_proxy["obfs-password"] = obfs_password
            if alpn:
                hysteria2_proxy["alpn"] = alpn # Clash.Meta supports ALPN in Hysteria2

            config["proxies"].append(hysteria2_proxy)
        except Exception as e:
            print(f"Error parsing hysteria2 node {node_url}: {e}")
            return None
    elif node_url.startswith("ssr://"):
        print(f"Warning: SSR node parsing is complex and not fully implemented in this script: {node_url}")
        return None
    else:
        print(f"Warning: Unsupported or unparsed protocol for Clash.Meta: {node_url}")
        return None

    if not config["proxies"]:
        print(f"No proxy configured for {node_url} after parsing attempt.")
        return None

    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        print(f"Generated Clash.Meta config for {node_url} at {CONFIG_FILE}")
        return True
    except Exception as e:
        print(f"Error writing Clash.Meta config for {node_url}: {e}")
        return None


def test_node_connectivity(node_url):
    """
    Tests the connectivity of a single node using Clash.Meta.
    Returns True if connected, False otherwise.
    """
    print(f"\n--- Testing node: {node_url} ---")
    if not create_clash_config(node_url):
        print(f"Skipping {node_url} due to parsing error or unsupported protocol.")
        return False

    mihomo_process = None
    try:
        # Start Mihomo in the background, redirecting output for visibility
        print(f"Starting {MIHOMO_BIN_NAME} with config {CONFIG_FILE} on port {CLASH_PORT}...")
        mihomo_process = subprocess.Popen(
            [f"./{MIHOMO_BIN_NAME}", "-f", CONFIG_FILE],
            stdout=sys.stdout, # Redirect stdout to console for live logs
            stderr=sys.stderr, # Redirect stderr to console for live errors
            text=True,
            bufsize=1 # Line-buffered output
        )
        print(f"{MIHOMO_BIN_NAME} process started (PID: {mihomo_process.pid}). Giving it time to initialize...")
        time.sleep(3) # Give Mihomo a bit more time to start up

        # Test connectivity using curl through the local proxy
        curl_command = [
            "curl",
            "--socks5-hostname", f"127.0.0.1:{CLASH_PORT}",
            TEST_URL,
            "--max-time", "15", # Increased timeout for potentially slow proxies
            "--silent", "--output", "/dev/null",
            "--fail"
        ]
        print(f"Running curl command: {' '.join(curl_command)}")
        curl_result = subprocess.run(curl_command, capture_output=True, text=True) # Capture curl output for debugging

        if curl_result.returncode == 0:
            print(f"Node {node_url} is CONNECTED.")
            return True
        else:
            print(f"Node {node_url} FAILED to connect (curl exit code: {curl_result.returncode}).")
            print(f"Curl stdout:\n{curl_result.stdout}")
            print(f"Curl stderr:\n{curl_result.stderr}")
            return False
    except FileNotFoundError:
        print(f"Error: {MIHOMO_BIN_NAME} not found. Ensure it's in the current directory and executable.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"Subprocess error during testing {node_url}: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred during testing {node_url}: {e}")
        return False
    finally:
        if mihomo_process and mihomo_process.poll() is None:
            print(f"Terminating {MIHOMO_BIN_NAME} process (PID: {mihomo_process.pid})...")
            mihomo_process.terminate()
            try:
                mihomo_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                mihomo_process.kill()
                print(f"Force killed {MIHOMO_BIN_NAME} process for {node_url}.")
        else:
            print(f"{MIHOMO_BIN_NAME} process was not running or already terminated.")
        
        # Clean up config file
        if os.path.exists(CONFIG_FILE):
            os.remove(CONFIG_FILE)
            print(f"Cleaned up {CONFIG_FILE}.")

if __name__ == "__main__":
    print("Starting proxy node processing script.")

    # Setup Mihomo binary
    setup_mihomo()

    # Create output directory if it doesn't exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"Output directory '{OUTPUT_DIR}' ensured to exist.")

    all_nodes = download_and_parse_nodes(NODE_LIST_URL)
    working_nodes = []

    for i, node in enumerate(all_nodes):
        print(f"\n--- Processing node {i+1}/{len(all_nodes)} ---")
        if test_node_connectivity(node):
            working_nodes.append(node)
        print("-" * 40) # Separator for readability

    print(f"\n--- Script execution complete ---")
    print(f"Total nodes processed: {len(all_nodes)}")
    print(f"Total working nodes found: {len(working_nodes)}")

    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for node in working_nodes:
            f.write(node + "\n")
    print(f"Working nodes saved to {OUTPUT_FILE}")
