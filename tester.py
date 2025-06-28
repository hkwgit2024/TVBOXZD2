import requests
import re
import yaml
import subprocess
import os
import time
import sys

# URL to download the raw node list
NODE_LIST_URL = "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
# URL for Mihomo (Clash.Meta) binary (Linux AMD64 latest stable version, replace if a newer version is available)
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
    """Downloads a file from a URL to a specified destination."""
    print(f"Downloading {url} to {destination}...")
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        with open(destination, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        print("Download complete.")
        return True
    except requests.exceptions.RequestException as e:
        print(f"Error downloading {url}: {e}")
        return False

def setup_mihomo():
    """Downloads, extracts, and sets up the Mihomo binary."""
    if not os.path.exists(MIHOMO_BIN_NAME):
        archive_name = os.path.basename(MIHOMO_DOWNLOAD_URL)
        if not download_file(MIHOMO_DOWNLOAD_URL, archive_name):
            sys.exit("Failed to download Mihomo binary.")

        print(f"Extracting {archive_name}...")
        if archive_name.endswith('.gz'):
            subprocess.run(["gunzip", "-f", archive_name], check=True)
            extracted_name = archive_name.replace(".gz", "")
            # Mihomo binary inside the .gz might not have the same name as the extracted file,
            # it's often 'mihomo-linux-amd64-vX.Y.Z' or just 'mihomo'.
            # We'll rename the extracted file to MIHOMO_BIN_NAME for consistency.
            # Assuming the gunzip extracts to a file without extension like 'mihomo-linux-amd64-v1.19.11'
            # We need to find the extracted file name.
            # A more robust way is to check the common extracted names for mihomo.
            # For now, let's assume gunzip extracts to a file named like 'mihomo-linux-amd64-v1.19.11'
            # and we rename it to 'mihomo'.
            # Alternatively, gunzip extracts to current directory.
            # Let's check for common extracted names after gunzip.
            possible_extracted_names = [
                extracted_name, # e.g. mihomo-linux-amd64-v1.19.11
                "mihomo", # if the archive contains just 'mihomo'
                "clash", # if it's named 'clash'
                "clash-linux-amd64" # another common naming
            ]
            found_extracted = False
            for p_name in possible_extracted_names:
                if os.path.exists(p_name) and not os.path.isdir(p_name):
                    os.rename(p_name, MIHOMO_BIN_NAME)
                    found_extracted = True
                    break
            if not found_extracted:
                print(f"Could not find the extracted Mihomo binary. Please check common naming conventions for {archive_name}.")
                sys.exit("Failed to find extracted Mihomo binary.")
        else:
            print(f"Unsupported archive format: {archive_name}")
            sys.exit("Unsupported Mihomo archive format.")

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
    proxy_name = f"proxy-{hash(node_url) % 100000}" # Simple unique name
    config = {
        "port": CLASH_PORT,
        "mode": "direct", # We're using direct to force curl to use the proxy
        "log-level": "silent",
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

    # Clash.Meta uses the 'external-controller' to provide a RESTful API
    # to interact with it, which can be useful for more advanced testing.
    # For basic connectivity, we'll just run it as a proxy.
    # To parse various proxy links (vmess, trojan, etc.) and convert them to Clash format,
    # a dedicated library or a complex parsing logic would be needed.
    # For simplicity, this example assumes the node_url can be directly placed
    # if Clash.Meta supports it or needs a conversion.
    # A full implementation would need to parse each protocol string (e.g., vmess://, ss://)
    # and convert it into Clash's YAML format for proxies.
    # This is a significant task, so for this example, I will assume a simplified direct parsing
    # for specific protocols or outline the need for conversion.

    # Example: Simple handling for vmess. Real parsing is complex.
    # This is a placeholder for a proper node parsing function.
    # A robust solution would use a library like 'py_surge' or 'clash-config-parser' if available.
    if node_url.startswith("vmess://"):
        try:
            # Decode base64 part of vmess
            vmess_b64 = node_url[len("vmess://"):]
            decoded_vmess = json.loads(base64.b64decode(vmess_b64).decode('utf-8'))
            config["proxies"].append({
                "name": proxy_name,
                "type": "vmess",
                "server": decoded_vmess.get("add"),
                "port": decoded_vmess.get("port"),
                "uuid": decoded_vmess.get("id"),
                "alterId": decoded_vmess.get("aid", 0),
                "cipher": decoded_vmess.get("scy", "auto"),
                "network": decoded_vmess.get("net", "tcp"),
                "tls": decoded_vmess.get("tls", "") == "tls",
                "ws-opts": {
                    "path": decoded_vmess.get("path", "/"),
                    "headers": {"Host": decoded_vmess.get("host", decoded_vmess.get("add"))}
                } if decoded_vmess.get("net") == "ws" else {}
            })
        except Exception as e:
            print(f"Error parsing vmess node {node_url}: {e}")
            return None # Indicate parsing failure
    elif node_url.startswith("ss://"):
        # This is highly simplified. SS links can have many variations.
        try:
            from urllib.parse import urlparse, unquote
            parsed_url = urlparse(node_url)
            # SS usually has base64 encoded parts or direct credentials
            # This requires careful parsing of the URI structure based on SS AHEAD, SIP002, etc.
            # A full implementation would need a dedicated SS parser.
            # For this example, let's assume a direct proxy type with minimal info if not fully parsed.
            parts = parsed_url.netloc.split('@')
            if len(parts) == 2:
                method_password_b64 = parts[0]
                server_port = parts[1]
                method, password = base64.b64decode(method_password_b64).decode('utf-8').split(':', 1)
                server, port = server_port.split(':', 1)
                config["proxies"].append({
                    "name": proxy_name,
                    "type": "ss",
                    "server": server,
                    "port": int(port),
                    "cipher": method,
                    "password": password
                })
            else:
                raise ValueError("Unsupported SS format")
        except Exception as e:
            print(f"Error parsing ss node {node_url}: {e}")
            return None
    elif node_url.startswith("trojan://"):
        try:
            from urllib.parse import urlparse
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
        # VLESS parsing is complex and requires specific details from the URI.
        # This is a highly simplified placeholder.
        try:
            from urllib.parse import urlparse, parse_qs
            parsed_url = urlparse(node_url)
            uuid = parsed_url.username
            server = parsed_url.hostname
            port = parsed_url.port
            params = parse_qs(parsed_url.query)

            network = params.get('type', ['tcp'])[0]
            tls_enabled = params.get('security', [''])[0] == 'tls'
            ws_path = params.get('path', ['/'])[0]
            ws_headers_host = params.get('host', [server])[0]

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
            from urllib.parse import urlparse, parse_qs
            parsed_url = urlparse(node_url)
            server = parsed_url.hostname
            port = parsed_url.port
            password = parsed_url.username
            params = parse_qs(parsed_url.query)

            # Hysteria2 specific options
            obfs = params.get('obfs', [None])[0]
            obfs_password = params.get('obfs-password', [None])[0]
            # Other Hysteria2 parameters like 'alpn', 'ca', 'up', 'down', 'fastopen' would go here

            hysteria2_proxy = {
                "name": proxy_name,
                "type": "hysteria2",
                "server": server,
                "port": port,
                "password": password,
                "obfs": obfs,
                "obfs-password": obfs_password,
                "tls": True,
                "skip-cert-verify": True # Often needed for Hysteria2 if using self-signed
            }
            config["proxies"].append(hysteria2_proxy)
        except Exception as e:
            print(f"Error parsing hysteria2 node {node_url}: {e}")
            return None
    elif node_url.startswith("ssr://"):
        # SSR links are complex due to base64 encoding and specific parameters.
        # This would require a full SSR parser.
        # For simplicity, we skip full parsing here, as it's beyond a quick example.
        print(f"SSR node parsing is complex and not fully implemented: {node_url}")
        return None
    else:
        print(f"Unsupported or unparsed protocol for Clash.Meta: {node_url}")
        return None # Indicate unsupported protocol

    if not config["proxies"]: # If no proxy was added due to parsing issues
        return None

    with open(CONFIG_FILE, 'w') as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False)
    return True


def test_node_connectivity(node_url):
    """
    Tests the connectivity of a single node using Clash.Meta.
    Returns True if connected, False otherwise.
    """
    print(f"Testing node: {node_url}")
    if not create_clash_config(node_url):
        print(f"Skipping {node_url} due to parsing error or unsupported protocol.")
        return False

    mihomo_process = None
    try:
        # Start Mihomo in the background
        mihomo_process = subprocess.Popen(
            [f"./{MIHOMO_BIN_NAME}", "-f", CONFIG_FILE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True # Decode stdout/stderr as text
        )
        print(f"Started {MIHOMO_BIN_NAME} for {node_url}")
        time.sleep(2) # Give Mihomo time to start

        # Test connectivity using curl through the local proxy
        # Use --socks5-hostname for SOCKS5 proxy, which supports hostname resolution at the proxy.
        # Or --proxy for HTTP/SOCKS5 if Clash is configured for both.
        # Clash.Meta by default opens an HTTP and SOCKS5 proxy on the defined port.
        curl_command = [
            "curl",
            "--socks5-hostname", f"127.0.0.1:{CLASH_PORT}",
            TEST_URL,
            "--max-time", "10", # Timeout after 10 seconds
            "--silent", "--output", "/dev/null", # Don't print output, just check exit code
            "--fail" # Fail silently on HTTP errors
        ]
        print(f"Running curl command: {' '.join(curl_command)}")
        curl_result = subprocess.run(curl_command)

        if curl_result.returncode == 0:
            print(f"Node {node_url} is CONNECTED.")
            return True
        else:
            print(f"Node {node_url} FAILED to connect (curl exit code: {curl_result.returncode}).")
            # You can uncomment to see clash logs if needed for debugging
            # stdout, stderr = mihomo_process.communicate(timeout=1)
            # print(f"Mihomo stdout:\n{stdout}")
            # print(f"Mihomo stderr:\n{stderr}")
            return False
    except FileNotFoundError:
        print(f"Error: {MIHOMO_BIN_NAME} not found. Ensure it's in the current directory and executable.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"Subprocess error: {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred during testing: {e}")
        return False
    finally:
        if mihomo_process and mihomo_process.poll() is None: # If process is still running
            print(f"Terminating {MIHOMO_BIN_NAME} process for {node_url}...")
            mihomo_process.terminate()
            try:
                mihomo_process.wait(timeout=5) # Wait for process to terminate
            except subprocess.TimeoutExpired:
                mihomo_process.kill() # Force kill if it doesn't terminate
                print(f"Force killed {MIHOMO_BIN_NAME} process for {node_url}.")
        # Clean up config file
        if os.path.exists(CONFIG_FILE):
            os.remove(CONFIG_FILE)

if __name__ == "__main__":
    import base64
    import json # Import json for vmess parsing

    # Setup Mihomo binary
    setup_mihomo()

    # Create output directory if it doesn't exist
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    all_nodes = download_and_parse_nodes(NODE_LIST_URL)
    working_nodes = []

    for node in all_nodes:
        if test_node_connectivity(node):
            working_nodes.append(node)
        print("-" * 30) # Separator for readability

    print(f"\nTotal working nodes found: {len(working_nodes)}")

    with open(OUTPUT_FILE, 'w') as f:
        for node in working_nodes:
            f.write(node + "\n")
    print(f"Working nodes saved to {OUTPUT_FILE}")
