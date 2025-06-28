import asyncio
import base64
import json
import logging
import subprocess
import sys
import time
from contextlib import asynccontextmanager # Changed to asynccontextmanager
from pathlib import Path
from urllib.parse import urlparse, parse_qs
import requests
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)

# Constants
NODE_LIST_URL = "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
MIHOMO_DOWNLOAD_URL = "https://github.com/MetaCubeX/mihomo/releases/download/v1.20.0/mihomo-linux-amd64-v1.20.0.gz"
MIHOMO_BIN_NAME = "mihomo"
CONFIG_FILE = Path("config.yaml")
OUTPUT_DIR = Path("data")
OUTPUT_FILE = OUTPUT_DIR / "all.txt"
CLASH_PORT = 7890 # Port for Clash.Meta local proxy
TEST_URL = "http://www.google.com" # URL to test connectivity
CONCURRENT_TESTS = 10 # Number of concurrent nodes to test

def validate_url(url):
    """Validates if the URL is well-formed."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def download_file(url, destination):
    """Downloads a file from a URL to a specified destination with progress."""
    if not validate_url(url):
        logger.error(f"Invalid URL: {url}")
        return False

    logger.info(f"Downloading {url} to {destination}...")
    try:
        with requests.get(url, stream=True, timeout=30) as response:
            response.raise_for_status()
            total_size = int(response.headers.get('content-length', 0))
            downloaded_size = 0

            with destination.open('wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                    downloaded_size += len(chunk)
                    # Update progress on the same line.
                    # Using sys.stdout.write for in-place update as logger.info adds newline.
                    if total_size > 0:
                        progress = (downloaded_size / total_size) * 100
                        sys.stdout.write(
                            f"\rDownloading: {downloaded_size / (1024*1024):.2f}MB / "
                            f"{total_size / (1024*1024):.2f}MB ({progress:.1f}%)"
                        )
                    else:
                        sys.stdout.write(f"\rDownloading: {downloaded_size / (1024*1024):.2f}MB")
                    sys.stdout.flush() # Ensure output is written immediately
            sys.stdout.write("\n") # New line after progress
            logger.info("Download complete.")
            return True
    except requests.RequestException as e:
        logger.error(f"Error downloading {url}: {e}")
        return False

def setup_mihomo():
    """Downloads, extracts, and sets up the Mihomo binary."""
    logger.info("Checking Mihomo binary setup...")
    bin_path = Path(MIHOMO_BIN_NAME)
    if bin_path.exists():
        logger.info(f"{MIHOMO_BIN_NAME} already exists.")
        bin_path.chmod(0o755)
        return

    archive_name = Path(MIHOMO_DOWNLOAD_URL).name
    if not download_file(MIHOMO_DOWNLOAD_URL, archive_name):
        logger.error("Failed to download Mihomo binary.")
        sys.exit(1)

    logger.info(f"Extracting {archive_name}...")
    try:
        # gunzip writes to stdout by default if no output file specified, which is fine for logging.
        subprocess.run(["gunzip", "-f", archive_name], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        extracted_name = archive_name.with_suffix('') # Remove .gz suffix

        found_extracted = False
        for p_name in [extracted_name.name, MIHOMO_BIN_NAME, "clash", "clash-linux-amd64"]:
            p_path = Path(p_name)
            if p_path.exists() and not p_path.is_dir():
                p_path.rename(MIHOMO_BIN_NAME)
                logger.info(f"Renamed {p_name} to {MIHOMO_BIN_NAME}")
                found_extracted = True
                break
        
        if not found_extracted:
            logger.error("Could not find extracted Mihomo binary in common names. Please check archive content.")
            sys.exit(1)

        bin_path.chmod(0o755)
        logger.info(f"{MIHOMO_BIN_NAME} is set up and executable.")
    except subprocess.CalledProcessError as e:
        logger.error(f"Error during extraction: {e.output.decode()}")
        sys.exit(1)
    except Exception as e:
        logger.error(f"An unexpected error occurred during Mihomo setup: {e}")
        sys.exit(1)

def download_and_parse_nodes(url):
    """Downloads and parses node configurations."""
    if not validate_url(url):
        logger.error(f"Invalid node list URL: {url}")
        return []

    logger.info(f"Downloading node list from {url}")
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        content = response.text
    except requests.RequestException as e:
        logger.error(f"Error downloading node list: {e}")
        return []

    protocols = ["hysteria2://", "vmess://", "trojan://", "ss://", "ssr://", "vless://"]
    nodes = set()
    for line in content.splitlines():
        line = line.strip()
        if any(line.startswith(p) for p in protocols):
            nodes.add(line)
    logger.info(f"Found {len(nodes)} unique nodes.")
    return list(nodes)

def parse_vmess(node_url):
    """Parses vmess node configuration."""
    try:
        vmess_b64 = node_url[len("vmess://"):]
        # Add padding if necessary
        vmess_b64 = vmess_b64 + '=' * (-len(vmess_b64) % 4)
        decoded_vmess = json.loads(base64.b64decode(vmess_b64).decode('utf-8'))
        return {
            "type": "vmess",
            "server": decoded_vmess.get("add"),
            "port": int(decoded_vmess.get("port")),
            "uuid": decoded_vmess.get("id"),
            "alterId": int(decoded_vmess.get("aid", 0)),
            "cipher": decoded_vmess.get("scy", "auto"),
            "network": decoded_vmess.get("net", "tcp"),
            "tls": decoded_vmess.get("tls", "") == "tls",
            "skip-cert-verify": decoded_vmess.get("v", "") == "1" or decoded_vmess.get("allowInsecure", False),
            "ws-opts": {
                "path": decoded_vmess.get("path", "/"),
                "headers": {"Host": decoded_vmess.get("host", decoded_vmess.get("add"))}
            } if decoded_vmess.get("net") == "ws" else {},
            "grpc-opts": {
                "serviceName": decoded_vmess.get("path", ""),
                "grpcMode": "gun" # Assuming gun mode for vmess grpc
            } if decoded_vmess.get("net") == "grpc" else {}
        }
    except (json.JSONDecodeError, base64.binascii.Error, ValueError) as e:
        logger.error(f"Error parsing vmess node {node_url}: {e}")
        return None

def parse_ss(node_url):
    """Parses shadowsocks node configuration."""
    try:
        parsed_url = urlparse(node_url)
        method_password_encoded = parsed_url.username
        if not method_password_encoded:
            logger.error(f"Invalid shadowsocks node format (missing method/password): {node_url}")
            return None

        method_password = ""
        try:
            # SS links can be base64 encoded or plain. Try decoding first.
            method_password = base64.b64decode(method_password_encoded + '=' * (-len(method_password_encoded) % 4)).decode('utf-8')
        except (base64.binascii.Error, UnicodeDecodeError):
            method_password = method_password_encoded # Not base64, use raw

        method, password = "auto", method_password # Default if no ':'
        if ':' in method_password:
            method, password = method_password.split(':', 1)

        # Handle params from fragment or query part if present (like plugin)
        params = parse_qs(parsed_url.query)
        if not params and parsed_url.fragment: # Some SS put plugin info in fragment
            params = parse_qs(parsed_url.fragment)

        plugin = params.get('plugin', [''])[0]
        plugin_opts = params.get('plugin_opts', [''])[0]

        ss_proxy = {
            "type": "ss",
            "server": parsed_url.hostname,
            "port": parsed_url.port,
            "cipher": method,
            "password": password,
        }
        if plugin:
            ss_proxy["plugin"] = plugin
            if plugin_opts:
                ss_proxy["plugin-opts"] = plugin_opts

        return ss_proxy
    except (ValueError, AttributeError) as e:
        logger.error(f"Error parsing ss node {node_url}: {e}")
        return None

def parse_trojan(node_url):
    """Parses trojan node configuration."""
    try:
        parsed_url = urlparse(node_url)
        params = parse_qs(parsed_url.query)
        return {
            "type": "trojan",
            "server": parsed_url.hostname,
            "port": parsed_url.port,
            "password": parsed_url.username,
            "tls": True,
            "sni": params.get('sni', [parsed_url.hostname])[0],
            "skip-cert-verify": params.get('allowInsecure', ['0'])[0] == '1' # Clash Meta uses allowInsecure for skip-cert-verify
        }
    except (ValueError, AttributeError) as e:
        logger.error(f"Error parsing trojan node {node_url}: {e}")
        return None

def parse_vless(node_url):
    """Parses vless node configuration."""
    try:
        parsed_url = urlparse(node_url)
        params = parse_qs(parsed_url.query)
        network = params.get('type', ['tcp'])[0]
        tls_enabled = params.get('security', [''])[0] == 'tls'
        ws_path = params.get('path', ['/'])[0]
        ws_headers_host = params.get('host', [parsed_url.hostname])[0]
        flow = params.get('flow', [None])[0]
        sni = params.get('sni', [parsed_url.hostname])[0]
        skip_cert_verify = params.get('allowInsecure', ['0'])[0] == '1'

        vless_proxy = {
            "type": "vless",
            "server": parsed_url.hostname,
            "port": parsed_url.port,
            "uuid": parsed_url.username,
            "network": network,
            "tls": tls_enabled,
            "sni": sni,
            "skip-cert-verify": skip_cert_verify,
            "udp": True # VLESS usually supports UDP
        }
        if flow:
            vless_proxy["flow"] = flow

        if network == "ws":
            vless_proxy["ws-opts"] = {
                "path": ws_path,
                "headers": {"Host": ws_headers_host}
            }
        elif network == "grpc":
            grpc_mode = params.get('grpcMode', ['gun'])[0] # Default to gun
            service_name = params.get('serviceName', [''])[0]
            vless_proxy["grpc-opts"] = {
                "grpcMode": grpc_mode,
                "serviceName": service_name
            }
        return vless_proxy
    except (ValueError, AttributeError) as e:
        logger.error(f"Error parsing vless node {node_url}: {e}")
        return None

def parse_hysteria2(node_url):
    """Parses hysteria2 node configuration."""
    try:
        parsed_url = urlparse(node_url)
        params = parse_qs(parsed_url.query)
        return {
            "type": "hysteria2",
            "server": parsed_url.hostname,
            "port": parsed_url.port,
            "password": parsed_url.username,
            "tls": True,
            "skip-cert-verify": params.get('insecure', ['0'])[0] == '1', # 'insecure' parameter for skip-cert-verify
            "obfs": params.get('obfs', [None])[0],
            "obfs-password": params.get('obfs-password', [None])[0],
            "alpn": params.get('alpn', [None])[0],
            "sni": params.get('sni', [parsed_url.hostname])[0]
        }
    except (ValueError, AttributeError) as e:
        logger.error(f"Error parsing hysteria2 node {node_url}: {e}")
        return None

def create_clash_config(node_url):
    """Creates a basic Clash.Meta config for a single node."""
    proxy_name = f"proxy-{hash(node_url) % 100000}"
    config = {
        "port": CLASH_PORT,
        "mode": "direct",
        "log-level": "debug", # Changed to "debug" for more detailed logs
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "proxies": [],
        "proxy-groups": [{"name": "select", "type": "select", "proxies": [proxy_name]}],
        "rules": ["MATCH,select"]
    }

    parsers = {
        "vmess://": parse_vmess,
        "ss://": parse_ss,
        "trojan://": parse_trojan,
        "vless://": parse_vless,
        "hysteria2://": parse_hysteria2
    }

    for protocol, parser in parsers.items():
        if node_url.startswith(protocol):
            proxy = parser(node_url)
            if proxy:
                proxy["name"] = proxy_name
                config["proxies"].append(proxy)
            break
    else:
        logger.warning(f"Unsupported protocol for node: {node_url}")
        return False

    if not config["proxies"]:
        logger.error(f"No proxy configured for {node_url}")
        return False

    try:
        with CONFIG_FILE.open('w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        logger.info(f"Generated Clash.Meta config for {node_url} at {CONFIG_FILE}")
        return True
    except (OSError, yaml.YAMLError) as e:
        logger.error(f"Error writing Clash.Meta config for {node_url}: {e}")
        return False

@asynccontextmanager
async def mihomo_process(config_file):
    """Context manager for running and cleaning up Mihomo process."""
    process = None
    try:
        logger.info(f"Starting {MIHOMO_BIN_NAME} with config {config_file} on port {CLASH_PORT}...")
        process = subprocess.Popen(
            [f"./{MIHOMO_BIN_NAME}", "-f", str(config_file)],
            stdout=sys.stdout,
            stderr=sys.stderr, # Fixed syntax error here
            text=True,
            bufsize=1
        )
        logger.info(f"{MIHOMO_BIN_NAME} process started (PID: {process.pid}). Giving it time to initialize...")
        await asyncio.sleep(5) # Increased sleep time for initialization
        yield process
    finally:
        if process and process.poll() is None:
            logger.info(f"Terminating {MIHOMO_BIN_NAME} process (PID: {process.pid})...")
            process.terminate()
            try:
                await asyncio.wait_for(asyncio.to_thread(process.wait), timeout=5) # Use to_thread for blocking call
                logger.info(f"{MIHOMO_BIN_NAME} process terminated (PID: {process.pid})")
            except asyncio.TimeoutError:
                process.kill()
                logger.warning(f"Force killed {MIHOMO_BIN_NAME} process (PID: {process.pid})")
        else:
            logger.info(f"{MIHOMO_BIN_NAME} process was not running or already terminated.")
        
        if config_file.exists():
            config_file.unlink()
            logger.info(f"Cleaned up {config_file}.")

async def test_node_connectivity(node_url):
    """Tests the connectivity of a single node using Clash.Meta."""
    logger.info(f"\n--- Testing node: {node_url} ---")
    if not create_clash_config(node_url):
        logger.warning(f"Skipping {node_url} due to parsing error or unsupported protocol.")
        return False

    try:
        async with mihomo_process(CONFIG_FILE):
            curl_command = [
                "curl",
                "--socks5-hostname", f"127.0.0.1:{CLASH_PORT}",
                TEST_URL,
                "--max-time", "15",
                "--silent", "--output", "/dev/null",
                "--fail"
            ]
            logger.info(f"Running curl command: {' '.join(curl_command)}")
            # Run curl in a separate thread to avoid blocking the event loop
            result = await asyncio.to_thread(subprocess.run, curl_command, capture_output=True, text=True)

            if result.returncode == 0:
                logger.info(f"Node {node_url} is CONNECTED.")
                return True
            logger.warning(f"Node {node_url} FAILED to connect (curl exit code: {result.returncode}).")
            logger.debug(f"Curl stdout:\n{result.stdout}")
            logger.debug(f"Curl stderr:\n{result.stderr}")
            return False
    except FileNotFoundError:
        logger.error(f"Error: {MIHOMO_BIN_NAME} not found. Ensure it's in the current directory and executable.")
        # Do not sys.exit here, allow other tests to run
        return False 
    except subprocess.SubprocessError as e:
        logger.error(f"Subprocess error during testing {node_url}: {e}")
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred during testing {node_url}: {e}")
        return False

async def main():
    """Main function to process proxy nodes."""
    logger.info("Starting proxy node processing script.")
    setup_mihomo()
    OUTPUT_DIR.mkdir(exist_ok=True)
    logger.info(f"Output directory '{OUTPUT_DIR}' ensured to exist.")

    all_nodes = download_and_parse_nodes(NODE_LIST_URL)
    working_nodes = []

    # Use a semaphore to limit concurrent tasks
    semaphore = asyncio.Semaphore(CONCURRENT_TESTS)

    async def bounded_test(node_url):
        async with semaphore:
            return await test_node_connectivity(node_url)

    tasks = [bounded_test(node) for node in all_nodes]
    
    # Process tasks as they complete
    for i, future in enumerate(asyncio.as_completed(tasks)):
        node = all_nodes[tasks.index(future)] # Find original node from future
        logger.info(f"\n--- Result for node {i+1}/{len(all_nodes)} ---")
        if await future:
            working_nodes.append(node)
        logger.info("-" * 40)

    logger.info(f"\n--- Script execution complete ---")
    logger.info(f"Total nodes processed: {len(all_nodes)}")
    logger.info(f"Total working nodes found: {len(working_nodes)}")

    with OUTPUT_FILE.open('w', encoding='utf-8') as f:
        for node in working_nodes:
            f.write(node + "\n")
    logger.info(f"Working nodes saved to {OUTPUT_FILE}")

if __name__ == "__main__":
    asyncio.run(main())
