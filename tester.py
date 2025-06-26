import asyncio
import json
import logging
import random
import shutil
import socket
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
import base64
import urllib.parse
import aiohttp
import binascii
import os
import yaml
import re
import sys

# Ensure Python version is 3.7 or higher
if sys.version_info < (3, 7):
    raise RuntimeError("This script requires Python 3.7 or higher")

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
OUTPUT_FILE_PATH = "data/all.txt"
CLASH_PATH = os.getenv("CLASH_CORE_PATH", "./clash")
TEST_URLS = [
    "https://www.google.com",
    "https://www.youtube.com",
    "https://www.cloudflare.com",
]
BATCH_SIZE = 1000
MAX_CONCURRENT = 10
TIMEOUT = 3
# MAX_RETRIES = 2
CLASH_BASE_CONFIG_URLS = [
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/data/clash.yaml",
    "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/data/520.yaml",
]

# Global variable
GLOBAL_CLASH_CONFIG_TEMPLATE: Optional[Dict[str, Any]] = None

async def fetch_clash_base_config(url: str) -> Optional[Dict[str, Any]]:
    """Fetch and parse Clash configuration from a URL."""
    async with aiohttp.ClientSession() as session:
        try:
            logger.info(f"Fetching Clash config from {url}...")
            async with session.get(url, timeout=10) as response:
                response.raise_for_status()
                content = await response.text()
                logger.info(f"Successfully fetched config from {url}")
                return yaml.safe_load(content)
        except aiohttp.ClientError as e:
            logger.error(f"Failed to fetch Clash config from {url}: {e}")
            return None
        except yaml.YAMLError as e:
            logger.error(f"Failed to parse YAML from {url}: {e}")
            return None
        except asyncio.TimeoutError:
            logger.error(f"Timeout fetching Clash config from {url}")
            return None
        except Exception as e:
            logger.error(f"Unknown error fetching/parsing Clash config from {url}: {e}")
            return None

async def fetch_all_configs(urls: List[str]) -> List[Dict[str, Any]]:
    """Fetch proxy nodes from multiple URLs, deduplicate, and return combined list."""
    nodes: List[Dict[str, Any]] = []
    seen_nodes = set()

    for url in urls:
        config = await fetch_clash_base_config(url)
        if config is None:
            logger.warning(f"Skipping {url} due to fetch failure")
            continue

        proxies = config.get("proxies", [])
        if not proxies:
            logger.warning(f"No proxies found in {url}")
            continue

        for proxy in proxies:
            unique_key = (
                proxy.get("server", ""),
                proxy.get("port", 0),
                proxy.get("cipher", ""),
                proxy.get("password", ""),
                proxy.get("type", "")
            )
            if unique_key in seen_nodes:
                logger.debug(f"Skipping duplicate node: {proxy.get('name', 'unknown')}")
                continue
            seen_nodes.add(unique_key)
            nodes.append(proxy)

        logger.info(f"Fetched {len(proxies)} nodes from {url}, total unique nodes: {len(nodes)}")

    return nodes

async def parse_shadowsocks(url: str) -> Optional[Dict[str, Any]]:
    """Parse Shadowsocks URL and return Clash proxy config."""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "ss":
            return None

        if "@" not in parsed.netloc:
            logger.warning(f"Invalid SS URL format (missing @): {url}")
            return None

        credentials_b64, server_info = parsed.netloc.split("@", 1)
        server, port_str = server_info.split(":", 1)
        port = int(port_str.split("?")[0])

        method = ""
        password = ""

        try:
            decoded_credentials = base64.b64decode(credentials_b64).decode("utf-8")
            if ":" in decoded_credentials:
                method, password = decoded_credentials.split(":", 1)
            else:
                logger.warning(f"SS URL credentials format invalid (no colon), trying SS 2022: {url}")
                key_bytes = base64.b64decode(credentials_b64)
                if len(key_bytes) == 16:
                    method = "2022-blake3-aes-128-gcm"
                elif len(key_bytes) == 32:
                    method = "2022-blake3-aes-256-gcm"
                else:
                    logger.warning(f"Invalid SS credentials length ({len(key_bytes)} bytes), skipping: {url}")
                    return None
                password = base64.b64encode(key_bytes).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            try:
                key_bytes = base64.b64decode(credentials_b64)
                if len(key_bytes) == 16:
                    method = "2022-blake3-aes-128-gcm"
                elif len(key_bytes) == 32:
                    method = "2022-blake3-aes-256-gcm"
                else:
                    logger.warning(f"Invalid SS credentials length ({len(key_bytes)} bytes), skipping: {url}")
                    return None
                password = base64.b64encode(key_bytes).decode("utf-8")
            except binascii.Error as e:
                logger.warning(f"Failed to parse SS credentials: {url}, error: {e}")
                return None

        query_params = urllib.parse.parse_qs(parsed.query)

        proxy_config = {
            "name": f"ss-{server}-{port}",
            "type": "ss",
            "server": server,
            "port": port,
            "cipher": method,
            "password": password,
        }

        plugin = query_params.get("plugin", [None])[0]
        plugin_opts = query_params.get("plugin_opts", [None])[0]

        if plugin:
            if plugin in ("obfs-local", "simple-obfs"):
                if "obfs=http" in plugin_opts:
                    proxy_config["plugin"] = "obfs"
                    proxy_config["plugin-opts"] = {"mode": "http"}
                    host = re.search(r"obfs-host=([^;]+)", plugin_opts)
                    if host:
                        proxy_config["plugin-opts"]["host"] = host.group(1)
                elif "obfs=tls" in plugin_opts:
                    proxy_config["plugin"] = "obfs"
                    proxy_config["plugin-opts"] = {"mode": "tls"}
                    host = re.search(r"obfs-host=([^;]+)", plugin_opts)
                    if host:
                        proxy_config["plugin-opts"]["host"] = host.group(1)
                else:
                    logger.warning(f"Unknown or unsupported obfs plugin mode: {plugin_opts}, skipping plugin: {url}")
            elif plugin == "v2ray-plugin":
                logger.warning(f"v2ray-plugin support is incomplete, please verify: {url}")
                proxy_config["plugin"] = "v2ray-plugin"
                proxy_config["plugin-opts"] = {"mode": "websocket"}
                if "tls" in plugin_opts:
                    proxy_config["plugin-opts"]["tls"] = True
                if "host" in plugin_opts:
                    host = re.search(r"host=([^;]+)", plugin_opts)
                    if host:
                        proxy_config["plugin-opts"]["host"] = host.group(1)
            else:
                logger.warning(f"Unknown or unsupported plugin type: {plugin}, skipping plugin: {url}")

        return proxy_config
    except Exception as e:
        logger.warning(f"Failed to parse SS URL: {url}, error: {e}")
        return None

async def parse_hysteria2(url: str) -> Optional[Dict[str, Any]]:
    """Parse Hysteria2 URL and return Clash proxy config."""
    try:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "hysteria2":
            return None

        uuid_and_server_info = parsed.netloc
        if "@" not in uuid_and_server_info:
            logger.warning(f"Invalid Hysteria2 URL format (missing @): {url}")
            return None

        uuid_str, server_port_info = uuid_and_server_info.split("@", 1)
        server, port_str = server_port_info.split(":", 1)
        port = int(port_str)

        query_params = urllib.parse.parse_qs(parsed.query)

        password = query_params.get("password", [uuid_str])[0]
        if "password" in query_params:
            password = query_params["password"][0]

        insecure = query_params.get("insecure", ["0"])[0].lower() == "1"
        sni = query_params.get("sni", [server])[0]
        alpn_str = query_params.get("alpn", ["h3"])[0]
        alpn = [alpn_str] if isinstance(alpn_str, str) else alpn_str

        obfs = query_params.get("obfs", [None])[0]
        obfs_password = query_params.get("obfs-password", [None])[0]

        proxy_config = {
            "name": f"hysteria2-{server}-{port}",
            "type": "hysteria2",
            "server": server,
            "port": port,
            "password": password,
            "tls": True,
            "skip-cert-verify": insecure,
            "sni": sni,
            "alpn": alpn,
        }

        if obfs == "salamander" and obfs_password:
            proxy_config["obfs"] = "salamander"
            proxy_config["obfs-password"] = obfs_password
        elif obfs and obfs != "none":
            logger.warning(f"Unsupported obfs type in Hysteria2: {obfs}, skipping obfs: {url}")

        return proxy_config
    except Exception as e:
        logger.warning(f"Failed to parse Hysteria2 URL: {url}, error: {e}")
        return None

def validate_proxy_entry(proxy_entry: Dict[str, Any]) -> bool:
    """Validate proxy node format for Clash compatibility."""
    supported_protocols = ["ss", "vmess", "hysteria2", "vless", "trojan"]
    supported_ciphers = ["chacha20-ietf-poly1305", "aes-128-gcm", "2022-blake3-aes-128-gcm", "aes-256-gcm"]
    try:
        if not isinstance(proxy_entry, dict):
            raise ValueError("Proxy node must be a dictionary")

        if "type" not in proxy_entry:
            raise ValueError("Proxy node missing 'type' field")

        if proxy_entry["type"] not in supported_protocols:
            raise ValueError(f"Unsupported proxy protocol: {proxy_entry['type']}. Supported: {supported_protocols}")

        if "name" not in proxy_entry:
            proxy_entry["name"] = f"{proxy_entry['type']}-{proxy_entry.get('server', 'unknown')}-{proxy_entry.get('port', '0')}"
            logger.warning(f"Proxy node missing 'name' field, generated: {proxy_entry['name']}")

        if "server" not in proxy_entry:
            raise ValueError("Proxy node missing 'server' field")

        if "port" not in proxy_entry:
            raise ValueError("Proxy node missing 'port' field")

        if proxy_entry["server"] == "1.1.1.1" and proxy_entry["port"] == 1:
            logger.warning(f"Skipping invalid node: {proxy_entry['name']}")
            return False

        if proxy_entry["type"] == "ss":
            if "cipher" not in proxy_entry or "password" not in proxy_entry:
                raise ValueError("Shadowsocks node missing 'cipher' or 'password' field")
            if proxy_entry["cipher"] not in supported_ciphers:
                raise ValueError(f"Unsupported Shadowsocks cipher: {proxy_entry['cipher']}. Supported: {supported_ciphers}")
        elif proxy_entry["type"] == "vmess":
            if "uuid" not in proxy_entry or "cipher" not in proxy_entry:
                raise ValueError("VMess node missing 'uuid' or 'cipher' field")
            if proxy_entry.get("network") == "ws" and "ws-opts" not in proxy_entry:
                raise ValueError("VMess WebSocket node missing 'ws-opts' field")
        elif proxy_entry["type"] == "hysteria2":
            if "password" not in proxy_entry and "auth" not in proxy_entry:
                raise ValueError("Hysteria2 node missing 'password' or 'auth' field")
            if proxy_entry.get("obfs") and "obfs-password" not in proxy_entry:
                raise ValueError("Hysteria2 node with obfs missing 'obfs-password' field")
        elif proxy_entry["type"] == "vless":
            if "uuid" not in proxy_entry or "tls" not in proxy_entry:
                raise ValueError("VLESS node missing 'uuid' or 'tls' field")
            if proxy_entry.get("flow") == "xtls-rprx-vision" and "reality-opts" not in proxy_entry:
                raise ValueError("VLESS node with xtls-rprx-vision missing 'reality-opts' field")
        elif proxy_entry["type"] == "trojan":
            if "password" not in proxy_entry:
                raise ValueError("Trojan node missing 'password' field")
            if proxy_entry.get("network") == "ws" and "ws-opts" not in proxy_entry:
                raise ValueError("Trojan WebSocket node missing 'ws-opts' field")

        return True
    except ValueError as e:
        logger.warning(f"Node {proxy_entry.get('name', 'unknown')} validation failed: {str(e)}")
        return False

async def generate_clash_config(proxy_entry: Dict[str, Any], socks_port: int) -> Dict[str, Any]:
    """Generate Clash configuration for a single proxy node."""
    if GLOBAL_CLASH_CONFIG_TEMPLATE is None:
        raise ValueError("Clash base config template not loaded. Call fetch_clash_base_config first.")

    if not validate_proxy_entry(proxy_entry):
        raise ValueError(f"Invalid proxy node {proxy_entry.get('name', 'unknown')}, skipping generation")

    config = json.loads(json.dumps(GLOBAL_CLASH_CONFIG_TEMPLATE))

    config["port"] = random.randint(10000, 15000)
    config["socks-port"] = socks_port
    config["allow-lan"] = False
    config["mode"] = "rule"
    config["log-level"] = "info"

    config.setdefault("proxies", []).clear()
    config["proxies"].append(proxy_entry)

    proxy_name = proxy_entry["name"]
    config["proxy-groups"] = [
        {
            "name": "Proxy",
            "type": "select",
            "proxies": [proxy_name, "DIRECT", "REJECT"]
        }
    ]

    if "rules" not in config or not isinstance(config["rules"], list):
        config["rules"] = [
            "DOMAIN-SUFFIX,google.com,Proxy",
            "DOMAIN-SUFFIX,youtube.com,Proxy",
            "DOMAIN-SUFFIX,cloudflare.com,Proxy",
            "MATCH,Proxy"
        ]
    elif "MATCH,Proxy" not in config["rules"]:
        config["rules"].append("MATCH,Proxy")

    return config

async def test_node(clash_config: Dict[str, Any], node_identifier: str, index: int, total: int) -> bool:
    """Test a single proxy node."""
    temp_dir = Path(tempfile.gettempdir())
    socks_port = random.randint(20000, 25000)
    clash_config["socks-port"] = socks_port
    clash_config["port"] = random.randint(10000, 15000)

    config_path = temp_dir / f"clash_config_{os.getpid()}_{socks_port}.yaml"
    process = None
    try:
        with open(config_path, "w", encoding="utf-8") as f:
            yaml.safe_dump(clash_config, f, allow_unicode=True, sort_keys=False)

        process = await asyncio.create_subprocess_exec(
            CLASH_PATH,
            "-f",
            str(config_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        await asyncio.sleep(2)

        if process.returncode is not None:
            stdout, stderr = await process.communicate()
            logger.error(f"Clash failed to start for node {node_identifier}")
            logger.error(f"Config content:\n{yaml.dump(clash_config, indent=2, sort_keys=False)}")
            logger.error(f"Stdout: {stdout.decode(errors='ignore')}")
            logger.error(f"Stderr: {stderr.decode(errors='ignore')}")
            return False

        try:
            reader, writer = await asyncio.open_connection('127.0.0.1', socks_port)
            writer.close()
            await writer.wait_closed()
        except ConnectionRefusedError:
            logger.warning(f"Clash SOCKS5 port {socks_port} not open for node {node_identifier}")
            return False
        except Exception as e:
            logger.warning(f"Failed to connect to SOCKS5 port {socks_port} for node {node_identifier}: {e}")
            return False

        async with aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(ssl=False),
            timeout=aiohttp.ClientTimeout(total=TIMEOUT),
        ) as session:
            proxy = f"socks5://127.0.0.1:{socks_port}"
            for url in TEST_URLS:
                for attempt in range(MAX_RETRIES):
                    try:
                        async with session.get(url, proxy=proxy) as response:
                            if response.status != 200:
                                logger.info(
                                    f"Node {node_identifier} failed to connect to {url} "
                                    f"(status: {response.status}, attempt {attempt+1}/{MAX_RETRIES})"
                                )
                                if attempt + 1 == MAX_RETRIES:
                                    return False
                                continue
                            break
                    except aiohttp.ClientConnectionError as e:  # Changed to ClientConnectionError
                        logger.info(
                            f"Node {node_identifier} connection to {url} failed: {e} "
                            f"(attempt {attempt+1}/{MAX_RETRIES})"
                        )
                        if attempt + 1 == MAX_RETRIES:
                            return False
                        await asyncio.sleep(1)
                    except asyncio.TimeoutError:
                        logger.info(
                            f"Node {node_identifier} timed out on {url} "
                            f"(attempt {attempt+1}/{MAX_RETRIES})"
                        )
                        if attempt + 1 == MAX_RETRIES:
                            return False
                        await asyncio.sleep(1)
                    except Exception as e:
                        logger.info(
                            f"Node {node_identifier} failed to test {url}: {e} "
                            f"(attempt {attempt+1}/{MAX_RETRIES})"
                        )
                        if attempt + 1 == MAX_RETRIES:
                            return False
                        await asyncio.sleep(1)

        logger.info(f"[{index}/{total}] ✓ Node {node_identifier} passed all tests")
        return True
    except Exception as e:
        logger.error(f"Testing node {node_identifier} failed: {e}")
        return False
    finally:
        if process and process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=2)
            except asyncio.TimeoutError:
                logger.warning(f"Failed to terminate Clash process for node {node_identifier}, killing")
                process.kill()
        if config_path.exists():
            try:
                config_path.unlink()
            except OSError as e:
                logger.warning(f"Failed to delete config file {config_path}: {e}")

async def main():
    """Main function: Load, test, and save valid proxy nodes from multiple URLs."""
    Path("data").mkdir(parents=True, exist_ok=True)

    global GLOBAL_CLASH_CONFIG_TEMPLATE
    for url in CLASH_BASE_CONFIG_URLS:
        GLOBAL_CLASH_CONFIG_TEMPLATE = await fetch_clash_base_config(url)
        if GLOBAL_CLASH_CONFIG_TEMPLATE is not None:
            logger.info(f"Using {url} as Clash config template")
            break
    if GLOBAL_CLASH_CONFIG_TEMPLATE is None:
        logger.error("Failed to fetch Clash base config from any URL, exiting")
        return

    nodes = await fetch_all_configs(CLASH_BASE_CONFIG_URLS)

    for i, node_proxy_dict in enumerate(nodes):
        if "name" not in node_proxy_dict:
            node_proxy_dict["name"] = f"proxy-{i}"
            logger.warning(f"Detected proxy without 'name' field, generated: {node_proxy_dict['name']}")

    logger.info(f"Total unique proxy nodes after deduplication: {len(nodes)}")
    if not nodes:
        logger.error("No proxies found, possibly due to empty or invalid configs")
        return

    if not Path(CLASH_PATH).is_file() or not os.access(CLASH_PATH, os.X_OK):
        logger.error(f"Clash executable '{CLASH_PATH}' not found or not executable. Check CLASH_CORE_PATH")
        return

    valid_proxy_dicts: List[Dict[str, Any]] = []
    failure_reasons: Dict[str, int] = {"server_disconnected": 0, "invalid_format": 0, "timeout": 0, "other": 0}
    semaphore = asyncio.Semaphore(MAX_CONCURRENT)

    for i in range(0, len(nodes), BATCH_SIZE):
        batch = nodes[i:i + BATCH_SIZE]
        tasks = []
        for j, proxy_entry in enumerate(batch):
            async def test_with_semaphore(idx: int, entry: Dict[str, Any]):
                async with semaphore:
                    node_identifier = entry.get("name", "unknown proxy")
                    if not validate_proxy_entry(entry):
                        logger.info(f"[{i + idx + 1}/{len(nodes)}] ✗ Node {node_identifier} invalid format, skipped")
                        failure_reasons["invalid_format"] += 1
                        return None
                    try:
                        clash_config = await generate_clash_config(entry, 0)
                        if await test_node(clash_config, node_identifier, i + idx + 1, len(nodes)):
                            return entry
                        logger.info(f"[{i + idx + 1}/{len(nodes)}] ✗ Node {node_identifier} invalid or high latency, skipped")
                        if "server disconnected" in str(entry).lower():
                            failure_reasons["server_disconnected"] += 1
                        elif "timeout" in str(entry).lower():
                            failure_reasons["timeout"] += 1
                        else:
                            failure_reasons["other"] += 1
                        return None
                    except Exception as e:
                        logger.error(f"[{i + idx + 1}/{len(nodes)}] Testing node {node_identifier} failed: {e}")
                        failure_reasons["other"] += 1
                        return None

            tasks.append(test_with_semaphore(j, proxy_entry))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        valid_batch_proxy_dicts = [r for r in results if isinstance(r, dict) and r is not None]
        valid_proxy_dicts.extend(valid_batch_proxy_dicts)

        if valid_batch_proxy_dicts:
            with open(f"data/temp_valid_batch_{i//BATCH_SIZE + 1}.yaml", "w", encoding="utf-8") as f:
                yaml.safe_dump({"proxies": valid_batch_proxy_dicts}, f, allow_unicode=True, sort_keys=False)
            logger.info(f"Batch {i//BATCH_SIZE + 1} completed, current valid nodes: {len(valid_proxy_dicts)}")
        else:
            logger.info(f"Batch {i//BATCH_SIZE + 1} completed, no valid nodes in this batch")

    if valid_proxy_dicts:
        with open(OUTPUT_FILE_PATH, "w", encoding="utf-8") as f:
            yaml.safe_dump({"proxies": valid_proxy_dicts}, f, allow_unicode=True, sort_keys=False)
        logger.info(f"Testing complete, saved {len(valid_proxy_dicts)} valid nodes to {OUTPUT_FILE_PATH}")
    else:
        logger.warning("No valid nodes found")

    logger.info(f"Test summary: Total nodes: {len(nodes)}, Valid nodes: {len(valid_proxy_dicts)}")
    logger.info(f"Failure reasons: {failure_reasons}")

if __name__ == "__main__":
    asyncio.run(main())
