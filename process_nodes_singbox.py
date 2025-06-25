import asyncio
import json
import os
import urllib.request
import urllib.parse
import subprocess
import logging
from typing import Dict, List, Set
from contextlib import contextmanager

# 配置日志，调整为 WARNING 级别以减少输出
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# 支持的协议类型
PROTOCOLS = ['hysteria2', 'vmess', 'trojan', 'ss', 'ssr', 'vless']

class NodeParser:
    def __init__(self):
        self.parsed_nodes: List[Dict] = []
        self.unique_nodes: Set[str] = set()
        self.protocol_counts: Dict[str, int] = {p: 0 for p in PROTOCOLS}
        self.invalid_nodes: int = 0
        self.malformed_nodes: List[str] = []  # 暂存无效节点

    def parse_hysteria2(self, url: str) -> Dict:
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            node = {
                'protocol': 'hysteria2',
                'server': parsed.hostname or '',
                'port': int(parsed.port) if parsed.port else 443,
                'auth': parsed.username or params.get('auth', [''])[0],
                'params': params,
                'raw': url
            }
            if not node['server']:
                raise ValueError("服务器地址为空")
            return node
        except Exception as e:
            logger.error(f"解析 hysteria2 错误: {url}: {e}")
            self.invalid_nodes += 1
            self.malformed_nodes.append(url)
            return {}

    def parse_vmess(self, url: str) -> Dict:
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            node = {
                'protocol': 'vmess',
                'server': params.get('add', [''])[0],
                'port': int(params.get('port', ['443'])[0]),
                'uuid': params.get('id', [''])[0],
                'alterId': int(params.get('aid', ['0'])[0]),
                'network': params.get('net', ['tcp'])[0],
                'security': params.get('type', ['auto'])[0],
                'raw': url
            }
            if not node['server'] or not node['uuid']:
                raise ValueError("服务器地址或 UUID 为空")
            return node
        except Exception as e:
            logger.error(f"解析 vmess 错误: {url}: {e}")
            self.invalid_nodes += 1
            self.malformed_nodes.append(url)
            return {}

    def parse_trojan(self, url: str) -> Dict:
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            node = {
                'protocol': 'trojan',
                'server': parsed.hostname or '',
                'port': int(parsed.port) if parsed.port else 443,
                'password': parsed.username or '',
                'params': params,
                'raw': url
            }
            if not node['server'] or not node['password']:
                raise ValueError("服务器地址或密码为空")
            return node
        except Exception as e:
            logger.error(f"解析 trojan 错误: {url}: {e}")
            self.invalid_nodes += 1
            self.malformed_nodes.append(url)
            return {}

    def parse_ss(self, url: str) -> Dict:
        try:
            if '@' not in url:
                logger.warning(f"无效的 ss URL 格式 (缺少 @): {url}")
                self.invalid_nodes += 1
                self.malformed_nodes.append(url)
                return {}
            parts = url.split('://')[1].split('@')
            if len(parts) != 2:
                logger.warning(f"无效的 ss URL 格式 (部分数量错误): {url}")
                self.invalid_nodes += 1
                self.malformed_nodes.append(url)
                return {}
            auth, server_info = parts[0], parts[1]
            if ':' not in auth:
                logger.warning(f"无效的 ss auth 格式 (缺少 :): {url}")
                self.invalid_nodes += 1
                self.malformed_nodes.append(url)
                return {}
            method, password = auth.split(':', 1)
            if not method or not password:
                logger.warning(f"ss URL 中的 method 或 password 为空: {url}")
                self.invalid_nodes += 1
                self.malformed_nodes.append(url)
                return {}
            server_port = server_info.split('#')[0]
            server, port = server_port.rsplit(':', 1)
            node = {
                'protocol': 'ss',
                'server': server,
                'port': int(port),
                'method': method,
                'password': password,
                'raw': url
            }
            if not node['server'] or not node['port']:
                raise ValueError("服务器地址或端口为空")
            return node
        except Exception as e:
            logger.error(f"解析 ss 错误: {url}: {e}")
            self.invalid_nodes += 1
            self.malformed_nodes.append(url)
            return {}

    def parse_ssr(self, url: str) -> Dict:
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            node = {
                'protocol': 'ssr',
                'server': params.get('server', [''])[0],
                'port': int(params.get('port', ['443'])[0]),
                'protocol_param': params.get('protoparam', [''])[0],
                'method': params.get('method', [''])[0],
                'password': params.get('password', [''])[0],
                'raw': url
            }
            if not node['server'] or not node['password']:
                raise ValueError("服务器地址或密码为空")
            return node
        except Exception as e:
            logger.error(f"解析 ssr 错误: {url}: {e}")
            self.invalid_nodes += 1
            self.malformed_nodes.append(url)
            return {}

    def parse_vless(self, url: str) -> Dict:
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            node = {
                'protocol': 'vless',
                'server': parsed.hostname or '',
                'port': int(parsed.port) if parsed.port else 443,
                'uuid': parsed.username or '',
                'params': params,
                'raw': url
            }
            if not node['server'] or not node['uuid']:
                raise ValueError("服务器地址或 UUID 为空")
            return node
        except Exception as e:
            logger.error(f"解析 vless 错误: {url}: {e}")
            self.invalid_nodes += 1
            self.malformed_nodes.append(url)
            return {}

    def parse_node(self, node_str: str, failed_nodes: Set[str]) -> None:
        if not node_str.strip() or node_str in self.unique_nodes or node_str in failed_nodes:
            self.invalid_nodes += 1
            return
        protocol = node_str.split('://')[0].lower()
        if protocol not in PROTOCOLS:
            logger.warning(f"不支持的协议: {protocol} in {node_str}")
            self.invalid_nodes += 1
            self.malformed_nodes.append(node_str)
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

    def save_malformed_nodes(self):
        if self.malformed_nodes:
            with open('data/malformed.txt', 'a', encoding='utf-8') as f:
                f.write('\n'.join(self.malformed_nodes) + '\n')
            logger.warning(f"保存了 {len(self.malformed_nodes)} 个无效节点到 data/malformed.txt")
            self.malformed_nodes.clear()

@contextmanager
def file_lock(filename: str):
    try:
        yield
    finally:
        if os.path.exists(filename):
            try:
                os.remove(filename)
            except Exception as e:
                logger.error(f"删除 {filename} 失败: {e}")

async def test_connectivity(node: Dict) -> bool:
    try:
 Ascending
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

            process = await asyncio.create_subprocess_exec(
                'sing-box', 'check', '-c', 'temp_config.json',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                limit=1024 * 1024
            )
            try:
                stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=3.0)
                if process.returncode != 0:
                    logger.warning(f"测试失败: {node['raw']}: {stderr.decode('utf-8', errors='ignore')}")
                    return False
                return True
            except asyncio.TimeoutError:
                logger.warning(f"测试超时: {node['raw']}")
                return False
    except Exception as e:
        logger.error(f"测试连通性错误: {node['raw']}: {e}")
        return False

async def process_nodes():
    parser = NodeParser()
    failed_nodes: Set[str] = set()

    try:
        if os.path.exists('data/failed.txt'):
            with open('data/failed.txt', 'r', encoding='utf-8', errors='ignore') as f:
                failed_nodes = set(line.strip() for line in f if line.strip())
            logger.warning(f"加载了 {len(failed_nodes)} 个历史失败节点")

        with urllib.request.urlopen('https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/sub.txt') as response:
            nodes = response.read().decode('utf-8', errors='ignore').split('\n')
        logger.warning(f"下载了 {len(nodes)} 个节点")

        batch_size = 5000
        for i in range(0, len(nodes), batch_size):
            batch = nodes[i:i + batch_size]
            for node in batch:
                parser.parse_node(node, failed_nodes)
            logger.warning(f"处理了 {i + len(batch)}/{len(nodes)} 个节点")
        logger.warning(f"解析了 {len(parser.parsed_nodes)} 个唯一节点，跳过了 {parser.invalid_nodes} 个无效节点")
        logger.warning(f"协议统计: {parser.protocol_counts}")

        parser.save_malformed_nodes()

        valid_nodes = []
        new_failed_nodes = []
        total_nodes = len(parser.parsed_nodes)
        for i, node in enumerate(parser.parsed_nodes, 1):
            if await test_connectivity(node):
                valid_nodes.append(node)
            else:
                new_failed_nodes.append(node)
            if i % 500 == 0:
                logger.warning(f"测试了 {i}/{total_nodes} 个节点 ({i/total_nodes*100:.1f}%)")

        with open('data/all.txt', 'w', encoding='utf-8') as f:
            for node in valid_nodes:
                safe_raw = urllib.parse.quote(node['raw'], safe=':/?=&%#')
                f.write(safe_raw + '\n')
        logger.warning(f"保存了 {len(valid_nodes)} 个有效节点到 data/all.txt")

        all_failed_nodes = failed_nodes.union(node['raw'] for node in new_failed_nodes)
        with open('data/failed.txt', 'w', encoding='utf-8') as f:
            for node in all_failed_nodes:
                f.write(node + '\n')
        logger.warning(f"保存了 {len(all_failed_nodes)} 个失败节点到 data/failed.txt")

    except Exception as e:
        logger.error(f"处理节点错误: {e}")
        raise

if __name__ == '__main__':
    asyncio.run(process_nodes())
