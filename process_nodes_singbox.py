import asyncio
import json
import os
import urllib.request
import urllib.parse
import subprocess
import logging
import httpx # 引入 httpx
from typing import Dict, List, Set
from contextlib import asynccontextmanager # 使用异步上下文管理器

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
            os.makedirs('data', exist_ok=True) # 确保data目录存在
            with open('data/malformed.txt', 'a', encoding='utf-8') as f:
                f.write('\n'.join(self.malformed_nodes) + '\n')
            logger.warning(f"保存了 {len(self.malformed_nodes)} 个无效节点到 data/malformed.txt")
            self.malformed_nodes.clear()

@asynccontextmanager # 使用异步上下文管理器
async def singbox_proxy(node: Dict, config_path: str = 'temp_config.json', proxy_port: int = 2080):
    """
    启动 Sing-box 作为代理服务器，并提供一个代理地址。
    """
    config = {
        'log': {'level': 'error'},
        'inbounds': [
            {
                'type': 'socks',
                'listen': '127.0.0.1',
                'listen_port': proxy_port
            }
        ],
        'outbounds': [{
            'type': node['protocol'],
            'server': node['server'],
            'server_port': node['port']
        }]
    }
    # 根据协议类型填充出站配置
    if node['protocol'] == 'hysteria2':
        config['outbounds'][0]['password'] = node.get('auth', '')
        # Hysteria2 可能需要 tls 相关的配置，这里简化处理，如果缺少可能导致连接失败
        # config['outbounds'][0]['tls'] = {'enabled': True, 'server_name': node['server']} # 示例
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
        # SSR 通常还需要 obfs, protocol, obfs_param 等参数，这里简化处理，可能需要根据实际情况补充
    elif node['protocol'] == 'vless':
        config['outbounds'][0]['uuid'] = node.get('uuid', '')
        # VLESS 通常需要 flow, transport, tls 等配置，这里简化处理，可能需要根据实际情况补充
        # config['outbounds'][0]['tls'] = {'enabled': True, 'server_name': node['server']} # 示例


    process = None
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)

        # 启动 sing-box 进程
        # 注意: sing-box -c config.json 默认会启动，不会像 check 命令一样立即退出
        process = await asyncio.create_subprocess_exec(
            'sing-box', 'run', '-c', config_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        logger.debug(f"Sing-box 进程 {process.pid} 已启动，监听 127.0.0.1:{proxy_port}")

        # 给予 sing-box 启动时间
        await asyncio.sleep(1)

        yield f"socks5://127.0.0.1:{proxy_port}" # 提供代理地址
    except Exception as e:
        logger.error(f"启动 Sing-box 代理失败: {e}")
        yield None # 如果启动失败，返回None
    finally:
        if process:
            try:
                process.terminate() # 尝试终止进程
                await asyncio.wait_for(process.wait(), timeout=1.0) # 等待进程结束
            except asyncio.TimeoutError:
                process.kill() # 如果无法终止，则强制杀死
            logger.debug(f"Sing-box 进程 {process.pid} 已终止")
        if os.path.exists(config_path):
            try:
                os.remove(config_path)
            except Exception as e:
                logger.error(f"删除 {config_path} 失败: {e}")


async def test_connectivity(node: Dict) -> bool:
    """
    通过 Sing-box 代理实际访问一个网页来测试节点连通性。
    """
    test_url = "http://www.google.com/generate_204" # Google 提供的无内容响应，用于测试连接
    # 也可以使用其他稳定的网站，例如 "https://www.baidu.com"
    config_file = 'temp_test_config.json' # 为每个测试使用独立的临时配置文件

    async with singbox_proxy(node, config_path=config_file) as proxy_address:
        if not proxy_address:
            logger.warning(f"无法启动 Sing-box 代理进行测试: {node['raw']}")
            return False

        try:
            async with httpx.AsyncClient(proxies={"http://": proxy_address, "https://": proxy_address}, timeout=5) as client:
                response = await client.get(test_url)
                if 200 <= response.status_code < 400: # 检查状态码是否为成功范围
                    logger.info(f"测试成功: {node['raw']}")
                    return True
                else:
                    logger.warning(f"测试失败 (HTTP 状态码 {response.status_code}): {node['raw']}")
                    return False
        except httpx.RequestError as e:
            logger.warning(f"测试失败 (请求错误): {node['raw']}: {e}")
            return False
        except asyncio.TimeoutError:
            logger.warning(f"测试超时: {node['raw']}")
            return False
        except Exception as e:
            logger.error(f"测试连通性时发生未知错误: {node['raw']}: {e}")
            return False


async def process_nodes():
    parser = NodeParser()
    failed_nodes: Set[str] = set()

    try:
        os.makedirs('data', exist_ok=True) # 确保data目录存在

        if os.path.exists('data/failed.txt'):
            with open('data/failed.txt', 'r', encoding='utf-8', errors='ignore') as f:
                failed_nodes = set(line.strip() for line in f if line.strip())
            logger.warning(f"加载了 {len(failed_nodes)} 个历史失败节点")

        # 尝试从本地文件加载节点，如果文件不存在则从GitHub下载
        node_source = 'data/sub.txt'
        if not os.path.exists(node_source):
            try:
                logger.warning("本地 data/sub.txt 不存在，尝试从 GitHub 下载...")
                with urllib.request.urlopen('https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/sub.txt') as response:
                    nodes = response.read().decode('utf-8', errors='ignore').split('\n')
                with open(node_source, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(nodes)) # 将下载的节点保存到本地
                logger.warning(f"从 GitHub 下载并保存了 {len(nodes)} 个节点到 {node_source}")
            except Exception as e:
                logger.error(f"从 GitHub 下载节点失败: {e}")
                logger.error("请检查网络连接或 GitHub 链接是否有效。")
                return # 下载失败则退出
        else:
            with open(node_source, 'r', encoding='utf-8', errors='ignore') as f:
                nodes = f.read().split('\n')
            logger.warning(f"从本地 {node_source} 加载了 {len(nodes)} 个节点")


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
            logger.warning(f"正在测试第 {i}/{total_nodes} 个节点: {node.get('server', '未知服务器')} ({node['protocol']})")
            if await test_connectivity(node):
                valid_nodes.append(node)
            else:
                new_failed_nodes.append(node)
            # 每隔一段时间打印进度，或在完成一定数量时打印
            if i % 100 == 0 or i == total_nodes:
                logger.warning(f"测试进度: {i}/{total_nodes} 个节点 ({i/total_nodes*100:.1f}%)")

        with open('data/all.txt', 'w', encoding='utf-8') as f:
            for node in valid_nodes:
                # 确保保存的是原始的，未编码的 URL，因为通常订阅链接是直接的 URL
                # 如果是 Base64 编码的订阅，原始 URL 应该已经解码过了
                f.write(node['raw'] + '\n')
        logger.warning(f"保存了 {len(valid_nodes)} 个有效节点到 data/all.txt")

        # 合并所有失败节点，包括本次新失败的和历史失败的
        all_failed_nodes = failed_nodes.union(node['raw'] for node in new_failed_nodes)
        with open('data/failed.txt', 'w', encoding='utf-8') as f:
            for node_url in all_failed_nodes: # 确保写入的是原始 URL 字符串
                f.write(node_url + '\n')
        logger.warning(f"保存了 {len(all_failed_nodes)} 个失败节点到 data/failed.txt")

    except Exception as e:
        logger.error(f"处理节点错误: {e}")
        raise

if __name__ == '__main__':
    asyncio.run(process_nodes())
