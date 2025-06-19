import asyncio
import aiohttp
import base64
import json
import logging
import re
import urllib.parse
import yaml
import argparse
import uuid
from collections import defaultdict
from typing import List, Dict, Set
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('proxy_converter.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Regular expressions for node extraction
NODE_PATTERNS = {
    'ss': r'ss://[^\s#]+(?:#[^\n]*)?',
    'vmess': r'vmess://[^\s]+',
    'trojan': r'trojan://[^\s#]+(?:#[^\n]*)?',
    'vless': r'vless://[^\s#]+(?:#[^\n]*)?',
    'hysteria2': r'hysteria2://[^\s#]+(?:#[^\n]*)?'
}

def setup_argparse() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(description='Proxy node extractor and converter')
    parser.add_argument('--sources', default='sources.list', help='Input file with source URLs')
    parser.add_argument('--output', default='data/nodes.txt', help='Output file for nodes')
    parser.add_argument('--clash-output', default='data/clash.yaml', help='Clash YAML output file')
    parser.add_argument('--max-concurrency', type=int, default=50, help='Maximum concurrent requests')
    parser.add_argument('--timeout', type=int, default=20, help='Request timeout in seconds')
    return parser.parse_args()

def decode_base64(data: str) -> str:
    """Decode Base64 string with padding fix."""
    try:
        # Fix padding
        data = data.rstrip().replace('-', '+').replace('_', '/')
        padding = len(data) % 4
        if padding:
            data += '=' * (4 - padding)
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except Exception as e:
        logger.debug(f"Base64 decode error: {e}")
        return ""

def encode_base64(data: str) -> str:
    """Encode string to Base64."""
    return base64.b64encode(data.encode('utf-8')).decode('utf-8')

def convert_clash_proxy_to_url(proxy: Dict) -> str:
    """Convert Clash proxy configuration to URL format."""
    try:
        proxy_type = proxy.get('type', '').lower()
        name = urllib.parse.quote(proxy.get('name', 'unnamed'), safe='')

        if proxy_type == 'ss':
            cipher = proxy.get('cipher', '')
            password = proxy.get('password', '')
            server = proxy.get('server', '')
            port = proxy.get('port', 0)
            if cipher and password and server and port:
                auth = base64.b64encode(f"{cipher}:{password}".encode()).decode()
                return f"ss://{auth}@{server}:{port}#{name}"
        
        elif proxy_type == 'vmess':
            config = {
                'v': '2',
                'ps': proxy.get('name', ''),
                'add': proxy.get('server', ''),
                'port': proxy.get('port', ''),
                'id': proxy.get('uuid', ''),
                'aid': proxy.get('alterId', 0),
                'net': proxy.get('network', 'tcp'),
                'type': proxy.get('cipher', 'auto'),
                'tls': 'tls' if proxy.get('tls', False) else 'none',
                'sni': proxy.get('servername', ''),
            }
            if config['net'] == 'ws':
                config['path'] = proxy.get('ws-opts', {}).get('path', '')
                config['host'] = proxy.get('ws-opts', {}).get('headers', {}).get('Host', '')
            return f"vmess://{encode_base64(json.dumps(config))}"
        
        elif proxy_type in ['trojan', 'vless']:
            password = proxy.get('password', proxy.get('uuid', ''))
            server = proxy.get('server', '')
            port = proxy.get('port', 0)
            params = []
            if proxy.get('sni'):
                params.append(f"sni={urllib.parse.quote(proxy['sni'])}")
            if proxy.get('network') == 'ws':
                ws_opts = proxy.get('ws-opts', {})
                if ws_opts.get('path'):
                    params.append(f"path={urllib.parse.quote(ws_opts['path'])}")
                if ws_opts.get('headers', {}).get('Host'):
                    params.append(f"host={urllib.parse.quote(ws_opts['headers']['Host'])}")
            if proxy.get('flow'):
                params.append(f"flow={proxy['flow']}")
            if proxy.get('client-fingerprint'):
                params.append(f"fp={proxy['client-fingerprint']}")
            params_str = '&'.join(params) if params else ''
            return f"{proxy_type}://{password}@{server}:{port}{'?' + params_str if params_str else ''}#{name}"
        
        elif proxy_type == 'hysteria2':
            password = proxy.get('password', '')
            server = proxy.get('server', '')
            port = proxy.get('port', 0)
            params = []
            if proxy.get('sni'):
                params.append(f"sni={urllib.parse.quote(proxy['sni'])}")
            if proxy.get('skip-cert-verify', False):
                params.append("insecure=1")
            params_str = '&'.join(params) if params else ''
            return f"hysteria2://{password}@{server}:{port}{'?' + params_str if params_str else ''}#{name}"
        
        logger.debug(f"Unsupported proxy type: {proxy_type}")
        return ""
    except Exception as e:
        logger.debug(f"Error converting proxy: {e}")
        return ""

def extract_nodes(content: str) -> List[str]:
    """Extract proxy nodes from content."""
    nodes = []
    content = content.replace('\r\n', '\n').replace('\r', '\n')
    
    # Try Base64 decode
    decoded = decode_base64(content)
    if decoded:
        content += '\n' + decoded

    # Extract nodes using regex
    for protocol, pattern in NODE_PATTERNS.items():
        matches = re.findall(pattern, content, re.MULTILINE)
        nodes.extend(matches)

    # Try parsing as Clash YAML
    try:
        clash_config = yaml.safe_load(content)
        if isinstance(clash_config, dict) and 'proxies' in clash_config:
            for proxy in clash_config['proxies']:
                url = convert_clash_proxy_to_url(proxy)
                if url:
                    nodes.append(url)
    except yaml.YAMLError:
        pass

    # Try parsing as JSON (VMess)
    try:
        json_configs = json.loads(content)
        if isinstance(json_configs, list):
            for config in json_configs:
                url = convert_clash_proxy_to_url(config)
                if url:
                    nodes.append(url)
    except json.JSONDecodeError:
        pass

    # Remove duplicates while preserving order
    seen = set()
    unique_nodes = []
    for node in nodes:
        if node not in seen:
            seen.add(node)
            unique_nodes.append(node)
    
    return unique_nodes

async def fetch_with_retry(session: aiohttp.ClientSession, url: str, retries: int = 3, backoff_factor: float = 1.0) -> str:
    """Fetch URL content with retries."""
    for attempt in range(retries):
        try:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=args.timeout)) as response:
                response.raise_for_status()
                return await response.text()
        except aiohttp.ClientError as e:
            logger.debug(f"Attempt {attempt + 1} failed for {url}: {e}")
            if attempt < retries - 1:
                await asyncio.sleep(backoff_factor * (2 ** attempt))
    logger.error(f"Failed to fetch {url} after {retries} attempts")
    return ""

async def fetch_url_nodes(session: aiohttp.ClientSession, url: str, semaphore: asyncio.Semaphore, url_node_counts: Dict, failed_urls: Set) -> List[str]:
    """Fetch and extract nodes from a single URL."""
    async with semaphore:
        logger.info(f"Fetching URL: {url}")
        try:
            content = await fetch_with_retry(session, url)
            if not content:
                failed_urls.add(url)
                return []
            
            nodes = extract_nodes(content)
            url_node_counts[url] = len(nodes)
            logger.info(f"Extracted {len(nodes)} nodes from {url}")
            return nodes
        except Exception as e:
            logger.error(f"Error processing {url}: {e}")
            failed_urls.add(url)
            return []

async def process_urls(urls: List[str], max_concurrency: int) -> tuple[List[str], Dict, Set]:
    """Process multiple URLs concurrently."""
    semaphore = asyncio.Semaphore(max_concurrency)
    url_node_counts = defaultdict(int)
    failed_urls = set()
    all_nodes = []
    
    async with aiohttp.ClientSession() as session:
        tasks = [fetch_url_nodes(session, url, semaphore, url_node_counts, failed_urls) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for nodes in results:
            if isinstance(nodes, list):
                all_nodes.extend(nodes)
    
    # Remove duplicates
    unique_nodes = list(dict.fromkeys(all_nodes))
    return unique_nodes, url_node_counts, failed_urls

def generate_clash_config(nodes: List[str]) -> Dict:
    """Generate Clash configuration from nodes."""
    proxies = []
    for node in nodes:
        try:
            if node.startswith('ss://'):
                auth = decode_base64(node.split('@')[0][5:])
                cipher, password = auth.split(':')
                server, port = node.split('@')[1].split('#')[0].split(':')
                name = urllib.parse.unquote(node.split('#')[1])
                proxies.append({
                    'type': 'ss',
                    'name': name,
                    'server': server,
                    'port': int(port),
                    'cipher': cipher,
                    'password': password
                })
            # Add other protocol parsing as needed
        except Exception as e:
            logger.debug(f"Error parsing node for Clash: {e}")
    
    return {'proxies': proxies}

def main():
    """Main function."""
    args = setup_argparse()
    
    # Read URLs from file
    try:
        with open(args.sources, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        logger.error(f"Source file {args.sources} not found")
        return
    
    # Process URLs
    start_time = datetime.now()
    logger.info(f"Starting processing with {len(urls)} URLs")
    
    loop = asyncio.get_event_loop()
    nodes, url_node_counts, failed_urls = loop.run_until_complete(process_urls(urls, args.max_concurrency))
    
    # Sort nodes
    nodes.sort()
    
    # Generate report
    total_nodes = len(nodes)
    report = [
        f"Processing completed in {(datetime.now() - start_time).total_seconds():.2f} seconds",
        f"Total unique nodes extracted: {total_nodes}",
        "\nNode counts by URL:"
    ]
    for url, count in sorted(url_node_counts.items(), key=lambda x: x[1], reverse=True):
        report.append(f"{url}: {count} nodes")
    if failed_urls:
        report.append("\nFailed URLs:")
        report.extend(failed_urls)
    
    # Save nodes to file
    try:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write('\n'.join(nodes))
        logger.info(f"Saved {total_nodes} nodes to {args.output}")
    except Exception as e:
        logger.error(f"Error saving nodes: {e}")
    
    # Save Clash config
    clash_config = generate_clash_config(nodes)
    try:
        with open(args.clash_output, 'w', encoding='utf-8') as f:
            yaml.safe_dump(clash_config, f, allow_unicode=True)
        logger.info(f"Saved Clash config to {args.clash_output}")
    except Exception as e:
        logger.error(f"Error saving Clash config: {e}")
    
    # Print report
    print('\n'.join(report))

if __name__ == '__main__':
    main()
