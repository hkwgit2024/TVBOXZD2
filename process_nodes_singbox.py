import asyncio
import json
import os
import urllib.request
import urllib.parse
import subprocess
import logging
from typing import Dict, List, Set
from contextlib import contextmanager

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 支持的协议类型
PROTOCOLS = ['hysteria2', 'vmess', 'trojan', 'ss', 'ssr', 'vless']

class NodeParser:
    def __init__(self):
        self.parsed_nodes: List[Dict] = []
        self.unique_nodes: Set[str] = set()
        self.protocol_counts: Dict[str, int] = {p: 0 for p in PROTOCOLS}

    def parse_hysteria2(self, url: str) -> Dict:
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            return {
                'protocol': 'hysteria2',
                'server': parsed.hostname or '',
                'port': int(parsed.port) if parsed.port else 443,
                'auth': parsed.username or params.get('auth', [''])[0],
                'params': params,
                'raw': url
            }
        except Exception as e:
            logger.error(f"Parse hysteria2 error for {url}: {e}")
            return {}

    def parse_vmess(self, url: str) -> Dict:
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            return {
                'protocol': 'vmess',
                'server': params.get('add', [''])[0],
                'port': int(params.get('port', ['443'])[0]),
                'uuid': params.get('id', [''])[0],
                'alterId': int(params.get('aid', ['0'])[0]),
                'network': params.get('net', ['tcp'])[0],
                'security': params.get('type', ['auto'])[0],
                'raw': url
            }
        except Exception as e:
            logger.error(f"Parse vmess error for {url}: {e}")
            return {}

    def parse_trojan(self, url: str) -> Dict:
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            return {
                'protocol': 'trojan',
                'server': parsed.hostname or '',
                'port': int(parsed.port) if parsed.port else 443,
                'password': parsed.username or '',
                'params': params,
                'raw': url
            }
        except Exception as e:
            logger.error(f"Parse trojan error for {url}: {e}")
            return {}

    def parse_ss(self, url: str) -> Dict:
        try:
            if '@' not in url:
                logger.warning(f"Invalid ss URL format (missing @): {url}")
                return {}
            parts = url.split('://')[1].split('@')
            if len(parts) != 2:
                logger.warning(f"Invalid ss URL format (invalid parts): {url}")
                return {}
            auth, server_info = parts[0], parts[1]
            if ':' not in auth:
                logger.warning(f"Invalid ss auth format (missing : in auth): {url}")
                return {}
            method, password = auth.split(':', 1)  # Use maxsplit=1 to handle passwords with :
            if not method or not password:
                logger.warning(f"Empty method or password in ss URL: {url}")
                return {}
            server_port = server_info.split('#')[0]  # Remove tag if present
            server, port = server_port.rsplit(':', 1)  # Use rsplit to handle IPv6
            return {
                'protocol': 'ss',
                'server': server,
                'port': int(port),
                'method': method,
                'password': password,
                'raw': url
            }
        except Exception as e:
            logger.error(f"Parse ss error for {url}: {e}")
            return {}

    def parse_ssr(self, url: str) -> Dict:
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            return {
                'protocol': 'ssr',
                'server': params.get('server', [''])[0],
                'port': int(params.get('port', ['443'])[0]),
                'protocol_param': params.get('protoparam', [''])[0],
                'method': params.get('method', [''])[0],
                'password': params.get('password', [''])[0],
                'raw': url
            }
        except Exception as e:
            logger.error(f"Parse ssr error for {url}: {e}")
            return {}

    def parse_vless(self, url: str) -> Dict:
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            return {
                'protocol': 'vless',
                'server': parsed.hostname or '',
                'port': int(parsed.port) if parsed.port else 443,
                'uuid': parsed.username or '',
                'params': params,
                'raw': url
            }
        except Exception as e:
            logger.error(f"Parse vless error for {url}: {e}")
            return {}

    def parse_node(self, node_str: str, failed_nodes: Set[str]) -> None:
        if not node_str.strip() or node_str in self.unique_nodes or node_str in failed_nodes:
            return
        protocol = node_str.split('://')[0].lower()
        if protocol not in PROTOCOLS:
            return
        self.unique_nodes.add(node_str)
        self.protocol_counts[protocol] += 1

        parser_map = {
            'hysteria2': self.parse_hysteria2,
            'vmess': self.parse_vmess,
            'trojan': self.parse_trojan,
            'ss': self.parse_ss,
            'ssr': self.parse_ssr,
            'vless': self.parse_vless
        }

        parsed = parser_map[protocol](node_str)
        if parsed and parsed.get('server') and parsed.get('port'):
            self.parsed_nodes.append(parsed)

@contextmanager
def file_lock(filename: str):
    try:
        yield
    finally:
        if os.path.exists(filename):
            try:
                os.remove(filename)
            except Exception as e:
                logger.error(f"Failed to remove {filename}: {e}")

async def test_connectivity(node: Dict) -> bool:
    try:
        # 创建 Sing-box 配置文件
        config = {
            'log': {'level': 'error'},
            'outbounds': [{
                'type': node['protocol'],
                'server': node['server'],
                'server_port': node['port']
            }]
        }
        if node['protocol'] == 'hysteria2':
            config['outbounds'][0]['password'] = node.get('auth', '')
        elif node['protocol'] == 'vmess':
            config['outbounds'][0]['uuid'] = node.get('uuid', '')
            config['outbounds'][0]['alter_id'] = node.get('alterId', 0)
            config['outbounds'][0]['security'] = node.get('security', 'auto')
            config['outbounds'][0]['transport'] = {'type': node.get('network', 'tcp')}
        elif node['protocol'] == 'trojan':
            config['outbounds'][0]['password'] = node.get('password', '')
        elif node['protocol'] == 'ss':
            config['outbounds'][0]['method'] = node.get('method', '')
            config['outbounds'][0]['password'] = node.get('password', '')
        elif node['protocol'] == 'ssr':
            config['outbounds'][0]['method'] = node.get('method', '')
            config['outbounds'][0]['password'] = node.get('password', '')
            config['outbounds'][0]['protocol_param'] = node.get('protocol_param', '')
        elif node['protocol'] == 'vless':
            config['outbounds'][0]['uuid'] = node.get('uuid', '')

        with file_lock('temp_config.json'):
            with open('temp_config.json', 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2)

            # 使用 sing-box 测试连通性（3秒超时）
            process = await asyncio.create_subprocess_exec(
                'sing-box', 'check', '-c', 'temp_config.json',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=1024 * 1024
            )
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=3.0)
                if process.returncode != 0:
                    logger.warning(f"Test failed for node {node['raw']}: {stderr.decode('utf-8', errors='ignore')}")
                    return False
                return True
            except asyncio.TimeoutError:
                logger.warning(f"Test timeout for node {node['raw']}")
                return False
    except Exception as e:
        logger.error(f"Test connectivity error for node {node['raw']}: {e}")
        return False

async def process_nodes():
    parser = NodeParser()
    failed_nodes: Set[str] = set()

    try:
        # 读取历史失败节点
        if os.path.exists('data/failed.txt'):
            with open('data/failed.txt', 'r', encoding='utf-8') as f:
                failed_nodes = set(line.strip() for line in f if line.strip())
            logger.info(f"Loaded {len(failed_nodes)} failed nodes from data/failed.txt")

        # 下载节点
        with urllib.request.urlopen('https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/sub.txt') as response:
            nodes = response.read().decode('utf-8').split('\n')
        logger.info(f"Downloaded {len(nodes)} nodes")

        # 解析节点（分批处理）
        batch_size = 1000
        for i in range(0, len(nodes), batch_size):
            batch = nodes[i:i + batch_size]
            for node in batch:
                parser.parse_node(node, failed_nodes)
            logger.info(f"Processed {i + len(batch)}/{len(nodes)} nodes")
        logger.info(f"Parsed {len(parser.parsed_nodes)} unique nodes after filtering")
        logger.info(f"Protocol counts: {parser.protocol_counts}")

        # 测试连通性
        valid_nodes = []
        new_failed_nodes = []
        total_nodes = len(parser.parsed_nodes)
        for i, node in enumerate(parser.parsed_nodes, 1):
            if await test_connectivity(node):
                valid_nodes.append(node)
            else:
                new_failed_nodes.append(node)
            if i % 100 == 0:
                logger.info(f"Tested {i}/{total_nodes} nodes ({i/total_nodes*100:.1f}%)")

        # 保存成功节点（原始明文 URL）
        os.makedirs('data', exist_ok=True)
        with open('data/all.txt', 'w', encoding='utf-8') as f:
            for node in valid_nodes:
                f.write(node['raw'] + '\n')
        logger.info(f"Saved {len(valid_nodes)} valid nodes to data/all.txt")

        # 保存失败节点（合并历史和新失败节点）
        all_failed_nodes = failed_nodes.union(node['raw'] for node in new_failed_nodes)
        with open('data/failed.txt', 'w', encoding='utf-8') as f:
            for node in all_failed_nodes:
                f.write(node + '\n')
        logger.info(f"Saved {len(all_failed_nodes)} failed nodes to data/failed.txt")

    except Exception as e:
        logger.error(f"Error processing nodes: {e}")
        raise

if __name__ == '__main__':
    asyncio.run(process_nodes())
