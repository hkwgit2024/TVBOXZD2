import asyncio
import base64
import json
import logging
import subprocess
import sys
import time
from contextlib import asynccontextmanager
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
NODE_LIST_URL = "snippet.host/oouyda/raw"
MIHOMO_DOWNLOAD_URL = "https://github.com/MetaCubeX/mihomo/releases/download/v1.19.11/mihomo-linux-amd64-v1.19.11.gz"
MIHOMO_BIN_NAME = "mihomo"
OUTPUT_DIR = Path("data")
OUTPUT_FILE = OUTPUT_DIR / "all.txt"
CLASH_BASE_PORT = 7890
TEST_URL = "http://www.google.com"
CONCURRENT_TESTS = 10
CURL_TIMEOUT = 12  # Adjusted timeout for better reliability

def validate_url(url):
    """Validates if the URL is well-formed."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError as e:
        logger.error(f"URL validation failed for {url}: {e}")
        return False

def download_file(url, destination):
    """Downloads a file with progress tracking."""
    if not validate_url(url):
        return False

    logger.info(f"Downloading {url} to {destination}")
    try:
        with requests.get(url, stream=True, timeout=30) as response:
            response.raise_for_status()
            total_size = int(response.headers.get('content-length', 0))
            downloaded_size = 0
            with destination.open('wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded_size += len(chunk)
                        if total_size > 0:
                            progress = (downloaded_size / total_size) * 100
                            sys.stdout.write(f"\rProgress: {downloaded_size / (1024*1024):.2f}MB / "
                                             f"{total_size / (1024*1024):.2f}MB ({progress:.1f}%)")
                        else:
                            sys.stdout.write(f"\rDownloaded: {downloaded_size / (1024*1024):.2f}MB")
                        sys.stdout.flush()
            sys.stdout.write("\n")
        logger.info("Download completed successfully")
        return True
    except requests.RequestException as e:
        logger.error(f"Download failed for {url}: {e}")
        return False

def setup_mihomo():
    """Sets up the Mihomo binary."""
    bin_path = Path(MIHOMO_BIN_NAME)
    if bin_path.exists():
        bin_path.chmod(0o755)
        logger.info(f"{MIHOMO_BIN_NAME} already exists and is executable")
        return True

    archive_path = Path(MIHOMO_DOWNLOAD_URL).name
    if not download_file(MIHOMO_DOWNLOAD_URL, archive_path):
        logger.error("Mihomo binary download failed")
        return False

    try:
        subprocess.run(["gunzip", "-f", str(archive_path)], check=True)
        extracted_path = archive_path.with_suffix('')
        if extracted_path.exists():
            extracted_path.rename(MIHOMO_BIN_NAME)
            bin_path.chmod(0o755)
            logger.info(f"Setup {MIHOMO_BIN_NAME} successfully")
            return True
        logger.error("Extracted Mihomo binary not found")
        return False
    except subprocess.CalledProcessError as e:
        logger.error(f"Extraction failed: {e}")
        return False

def download_and_parse_nodes(url):
    """Downloads and parses node configurations."""
    if not validate_url(url):
        return []

    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        nodes = {line.strip() for line in response.text.splitlines()
                 if any(line.startswith(p) for p in ["hysteria2://", "vmess://", "trojan://", "ss://", "ssr://", "vless://"])}
        logger.info(f"Parsed {len(nodes)} unique nodes")
        return list(nodes)
    except requests.RequestException as e:
        logger.error(f"Node list download failed: {e}")
        return []

def parse_node(node_url):
    """Parses a node URL based on its protocol."""
    def add_base64_padding(b64_str):
        """Ensures proper Base64 padding."""
        return b64_str + '=' * (-len(b64_str) % 4)

    parsers = {
        "vmess://": lambda url: {
            "type": "vmess",
            "server": (decoded := json.loads(base64.b64decode(add_base64_padding(url[len("vmess://"):])).decode('utf-8'))).get("add"),
            "port": int(decoded.get("port")),
            "uuid": decoded.get("id"),
            "alterId": int(decoded.get("aid", 0)),
            "cipher": decoded.get("scy", "auto"),
            "network": decoded.get("net", "tcp"),
            "tls": decoded.get("tls", "") == "tls",
            "skip-cert-verify": decoded.get("v", "") == "1" or decoded.get("allowInsecure", False),
            "ws-opts": {"path": decoded.get("path", "/"), "headers": {"Host": decoded.get("host", decoded.get("add"))}}
            if decoded.get("net") == "ws" else {},
            "grpc-opts": {"serviceName": decoded.get("path", ""), "grpcMode": "gun"}
            if decoded.get("net") == "grpc" else {}
        },
        "ss://": lambda url: {
            "type": "ss",
            "server": (parsed := urlparse(url)).hostname,
            "port": parsed.port,
            "cipher": (mp := base64.b64decode(add_base64_padding(parsed.username)).decode('utf-8').split(':', 1))[0] if ':' in mp else "auto",
            "password": mp[1] if ':' in mp else mp,
            **({"plugin": p[0], "plugin-opts": po[0]} if (p := parse_qs(parsed.query).get('plugin', ['']))[0] and (po := parse_qs(parsed.query).get('plugin_opts', ['']))[0] else {})
        },
        "trojan://": lambda url: {
            "type": "trojan",
            "server": (parsed := urlparse(url)).hostname,
            "port": parsed.port,
            "password": parsed.username,
            "tls": True,
            "sni": parse_qs(parsed.query).get('sni', [parsed.hostname])[0],
            "skip-cert-verify": parse_qs(parsed.query).get('allowInsecure', ['0'])[0] == '1'
        },
        "vless://": lambda url: {
            "type": "vless",
            "server": (parsed := urlparse(url)).hostname,
            "port": parsed.port,
            "uuid": parsed.username,
            "network": (params := parse_qs(parsed.query)).get('type', ['tcp'])[0],
            "tls": params.get('security', [''])[0] == 'tls',
            "sni": params.get('sni', [parsed.hostname])[0],
            "skip-cert-verify": params.get('allowInsecure', ['0'])[0] == '1',
            "udp": True,
            **({"ws-opts": {"path": params.get('path', ['/'])[0], "headers": {"Host": params.get('host', [parsed.hostname])[0]}}
                if params.get('type', [''])[0] == "ws" else
                {"grpc-opts": {"grpcMode": params.get('grpcMode', ['gun'])[0], "serviceName": params.get('serviceName', [''])[0]}}
                if params.get('type', [''])[0] == "grpc" else {}})
        },
        "hysteria2://": lambda url: {
            "type": "hysteria2",
            "server": (parsed := urlparse(url)).hostname,
            "port": parsed.port,
            "password": parsed.username,
            "tls": True,
            "skip-cert-verify": parse_qs(parsed.query).get('insecure', ['0'])[0] == '1',
            "obfs": parse_qs(parsed.query).get('obfs', [None])[0],
            "obfs-password": parse_qs(parsed.query).get('obfs-password', [None])[0],
            "alpn": parse_qs(parsed.query).get('alpn', [None])[0],
            "sni": parse_qs(parsed.query).get('sni', [parsed.hostname])[0]
        }
    }

    for protocol, parser in parsers.items():
        if node_url.startswith(protocol):
            try:
                return parser(node_url)
            except (json.JSONDecodeError, base64.binascii.Error, ValueError, AttributeError) as e:
                logger.error(f"Failed to parse {protocol} node {node_url}: {e}")
                return None
    logger.warning(f"Unsupported protocol for node: {node_url}")
    return None

def create_clash_config(node_url, port):
    """Creates a Clash.Meta config for a single node."""
    proxy = parse_node(node_url)
    if not proxy:
        return None

    proxy_name = f"proxy-{hash(node_url) % 100000}"
    config = {
        "port": port,
        "mode": "direct",
        "log-level": "debug",
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "proxies": [{**proxy, "name": proxy_name}],
        "proxy-groups": [{"name": "select", "type": "select", "proxies": [proxy_name]}],
        "rules": ["MATCH,select"]
    }

    try:
        temp_config_file = Path(f"config_{port}.yaml")
        with temp_config_file.open('w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        logger.info(f"Generated config for {node_url} at {temp_config_file}")
        return temp_config_file
    except (OSError, yaml.YAMLError) as e:
        logger.error(f"Failed to write config for {node_url}: {e}")
        return None

@asynccontextmanager
async def mihomo_process(config_file, port):
    """Manages Mihomo process lifecycle."""
    process = None
    try:
        process = subprocess.Popen(
            [f"./{MIHOMO_BIN_NAME}", "-f", str(config_file)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        await asyncio.sleep(1.5)
        yield process
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                await asyncio.wait_for(asyncio.to_thread(process.wait), timeout=3)
            except asyncio.TimeoutError:
                process.kill()
                logger.warning(f"Force killed Mihomo process (PID: {process.pid})")
        if config_file.exists():
            config_file.unlink()

async def test_node_connectivity(node_url, port):
    """Tests connectivity for a single node."""
    temp_config_file = create_clash_config(node_url, port)
    if not temp_config_file:
        return None

    async with mihomo_process(temp_config_file, port):
        try:
            result = await asyncio.to_thread(subprocess.run,
                ["curl", "--socks5-hostname", f"127.0.0.1:{port}", TEST_URL, "--max-time", str(CURL_TIMEOUT), "--silent", "--output", "/dev/null", "--fail"],
                capture_output=True, text=True)
            if result.returncode == 0:
                logger.info(f"Node {node_url} is CONNECTED")
                return node_url
            logger.warning(f"Node {node_url} failed (exit code: {result.returncode})")
            logger.debug(f"Curl output: {result.stderr}")
            return None
        except subprocess.SubprocessError as e:
            logger.error(f"Subprocess error testing {node_url}: {e}")
            return None

async def main():
    """Main function to process and test proxy nodes."""
    if not setup_mihomo():
        sys.exit(1)

    OUTPUT_DIR.mkdir(exist_ok=True)
    nodes = download_and_parse_nodes(NODE_LIST_URL)
    if not nodes:
        logger.error("No nodes to process")
        sys.exit(1)

    ports = list(range(CLASH_BASE_PORT, CLASH_BASE_PORT + CONCURRENT_TESTS))
    port_lock = asyncio.Lock()
    semaphore = asyncio.Semaphore(CONCURRENT_TESTS)

    async def test_with_port(node_url):
        async with semaphore:
            async with port_lock:
                if not ports:
                    logger.error("No available ports")
                    return None
                port = ports.pop(0)
            try:
                return await test_node_connectivity(node_url, port)
            finally:
                async with port_lock:
                    ports.append(port)

    working_nodes = [node for node in await asyncio.gather(*(test_with_port(node) for node in nodes)) if node]

    # Cleanup any remaining temporary config files
    for port in range(CLASH_BASE_PORT, CLASH_BASE_PORT + CONCURRENT_TESTS):
        temp_config = Path(f"config_{port}.yaml")
        if temp_config.exists():
            temp_config.unlink()
            logger.info(f"Cleaned up {temp_config}")

    with OUTPUT_FILE.open('w', encoding='utf-8') as f:
        f.write('\n'.join(working_nodes))
    logger.info(f"Saved {len(working_nodes)} working nodes to {OUTPUT_FILE}")

if __name__ == "__main__":
    asyncio.run(main())
