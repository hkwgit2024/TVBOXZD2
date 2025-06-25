import asyncio
import json
import os
import base64
import urllib.request
import urllib.parse
import subprocess
import logging
import httpx
import re
from typing import Dict, List, Set
from contextlib import asynccontextmanager

# --- Configure Logging ---
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Constants ---
PROTOCOLS = ['hysteria2', 'vmess', 'trojan', 'ss', 'ssr', 'vless']
UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
IP_DOMAIN_PATTERN = re.compile(
    r'^(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}|\[[0-9a-fA-F:]+\])$'
)
TEST_URL = "http://www.google.com/generate_204"
VLESS_PARAM_PATTERNS = [r'security=(tls|reality)', r'flow=xtls-rprx-vision', r'sni=', r'type=(ws|grpc|xhttp)']

# --- NodeParser Class: Responsible for Parsing Node Links ---
class NodeParser:
    def __init__(self):
        self.parsed_nodes: List[Dict] = []
        self.unique_nodes: Set[str] = set()
        self.protocol_counts: Dict[str, int] = {p: 0 for p in PROTOCOLS}
        self.invalid_nodes: int = 0
        self.malformed_nodes: List[str] = []

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
            if not node['server'] or not IP_DOMAIN_PATTERN.match(node['server']):
                raise ValueError("无效的服务器地址")
            return node
        except Exception as e:
            logger.error(f"解析 hysteria2 错误: {url}: {e}")
            self.invalid_nodes += 1
            self.malformed_nodes.append(url)
            return {}

    def parse_vmess(self, url: str) -> Dict:
        try:
            parsed = urllib.parse.urlparse(url)
            if parsed.hostname is None and parsed.path:
                try:
                    decoded_json_str = urllib.parse.unquote(parsed.path.lstrip('/')).encode('utf-8')
                    missing_padding = len(decoded_json_str) % 4
                    if missing_padding:
                        decoded_json_str += b'=' * (4 - missing_padding)
                    decoded_data = json.loads(base64.b64decode(decoded_json_str).decode('utf-8'))
                    node = {
                        'protocol': 'vmess',
                        'server': decoded_data.get('add', ''),
                        'port': int(decoded_data.get('port', 443)),
                        'uuid': decoded_data.get('id', ''),
                        'alterId': int(decoded_data.get('aid', 0)),
                        'network': decoded_data.get('net', 'tcp'),
                        'security': decoded_data.get('type', 'auto'),
                        'transport_settings': decoded_data.get('tlsSettings', {}),
                        'raw': url
                    }
                except (json.JSONDecodeError, base64.binascii.Error) as je:
                    logger.warning(f"VMess Base64 解析失败，尝试按 direct URL 格式解析: {url} - {je}")
                    node = {
                        'protocol': 'vmess',
                        'server': parsed.hostname or '',
                        'port': int(parsed.port) if parsed.port else 443,
                        'uuid': parsed.username or '',
                        'alterId': int(urllib.parse.parse_qs(parsed.query).get('aid', ['0'])[0]),
                        'network': urllib.parse.parse_qs(parsed.query).get('net', ['tcp'])[0],
                        'security': urllib.parse.parse_qs(parsed.query).get('type', ['auto'])[0],
                        'params': urllib.parse.parse_qs(parsed.query),
                        'raw': url
                    }
            else:
                node = {
                    'protocol': 'vmess',
                    'server': parsed.hostname or '',
                    'port': int(parsed.port) if parsed.port else 443,
                    'uuid': parsed.username or '',
                    'alterId': int(urllib.parse.parse_qs(parsed.query).get('aid', ['0'])[0]),
                    'network': urllib.parse.parse_qs(parsed.query).get('net', ['tcp'])[0],
                    'security': urllib.parse.parse_qs(parsed.query).get('type', ['auto'])[0],
                    'params': urllib.parse.parse_qs(parsed.query),
                    'raw': url
                }
            if not node['server'] or not IP_DOMAIN_PATTERN.match(node['server']) or not node['uuid']:
                raise ValueError("服务器地址或 UUID 为空或无效")
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
            if not node['server'] or not IP_DOMAIN_PATTERN.match(node['server']) or not node['password']:
                raise ValueError("服务器地址或密码为空或无效")
            return node
        except Exception as e:
            logger.error(f"解析 trojan 错误: {url}: {e}")
            self.invalid_nodes += 1
            self.malformed_nodes.append(url)
            return {}

    def parse_ss(self, url: str) -> Dict:
        try:
            parts = url.split('://', 1)
            if len(parts) < 2:
                raise ValueError("无效的 SS URL 格式")
            auth_server_parts = parts[1].split('@', 1)
            if len(auth_server_parts) < 2:
                raise ValueError("SS URL 缺少 @ 分隔符")
            auth_part_raw = auth_server_parts[0]
            server_info_part = auth_server_parts[1]
            method = ""
            password = ""
            try:
                decoded_auth_part = urllib.parse.unquote(auth_part_raw)
                missing_padding = len(decoded_auth_part) % 4
                if missing_padding:
                    decoded_auth_part += '=' * (4 - missing_padding)
                decoded_auth_bytes = base64.b64decode(decoded_auth_part.encode('utf-8'))
                decoded_auth_str = decoded_auth_bytes.decode('utf-8')
                if ':' in decoded_auth_str:
                    method, password = decoded_auth_str.split(':', 1)
                else:
                    logger.warning(f"SS Base64 解码后缺少 ':'，尝试直接解析 auth 部分: {decoded_auth_str}")
                    method = "aes-256-gcm"
                    password = decoded_auth_str
            except (base64.binascii.Error, UnicodeDecodeError):
                if ':' in auth_part_raw:
                    method, password = auth_part_raw.split(':', 1)
                else:
                    method = "aes-256-gcm"
                    password = auth_part_raw
            server_port_params = server_info_part.split('#', 1)[0]
            port_str = server_port_params.rsplit(':', 1)[-1].split('?', 1)[0].strip('/')
            try:
                port = int(port_str)
            except ValueError:
                raise ValueError(f"无法解析端口: {port_str}")
            server = server_port_params.rsplit(':', 1)[0]
            if server.startswith('[') and server.endswith(']'):
                server = server[1:-1]
            node = {
                'protocol': 'ss',
                'server': server.strip(),
                'port': port,
                'method': method.strip(),
                'password': password.strip(),
                'raw': url
            }
            if not node['server'] or not IP_DOMAIN_PATTERN.match(node['server']) or not node['port'] or not node['method'] or not node['password']:
                raise ValueError("SS 节点关键信息不完整")
            return node
        except Exception as e:
            logger.error(f"解析 ss 错误: {url}: {e}")
            self.invalid_nodes += 1
            self.malformed_nodes.append(url)
            return {}

    def parse_ssr(self, url: str) -> Dict:
        try:
            parsed_base = url.split('ssr://', 1)[1]
            missing_padding = len(parsed_base) % 4
            if missing_padding:
                parsed_base += '=' * (4 - missing_padding)
            decoded_base = base64.b64decode(parsed_base.replace('-', '+').replace('_', '/')).decode('utf-8')
            parts = decoded_base.split(':')
            if len(parts) < 6:
                raise ValueError("SSR 链接参数不足")
            server = parts[0]
            port = int(parts[1])
            protocol = parts[2]
            method = parts[3]
            obfs = parts[4]
            password_base64 = parts[5].split('/')[0]
            password = base64.b64decode(password_base64.replace('-', '+').replace('_', '/')).decode('utf-8')
            params = {}
            if len(parts) > 6:
                query_string_and_remarks = parts[5].split('/', 1)[1] if '/' in parts[5] else ''
                if '#' in query_string_and_remarks:
                    query_string, remarks = query_string_and_remarks.split('#', 1)
                else:
                    query_string = query_string_and_remarks
                    remarks = ''
                if '?' in query_string:
                    obfs_proto_params = query_string.split('?', 1)[1]
                    params = urllib.parse.parse_qs(obfs_proto_params)
            node = {
                'protocol': 'ssr',
                'server': server,
                'port': port,
                'protocol_ssr': protocol,
                'method': method,
                'obfs': obfs,
                'password': password,
                'protocol_param': params.get('protoparam', [''])[0],
                'obfs_param': params.get('obfsparam', [''])[0],
                'remarks': urllib.parse.unquote(remarks),
                'raw': url
            }
            if not node['server'] or not IP_DOMAIN_PATTERN.match(node['server']) or not node['password']:
                raise ValueError("SSR 服务器地址或密码为空或无效")
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
            if not node['server'] or not IP_DOMAIN_PATTERN.match(node['server']) or not node['uuid']:
                raise ValueError("服务器地址或 UUID 为空或无效")
            node['transport_type'] = params.get('type', ['tcp'])[0]
            node['transport_path'] = params.get('path', [''])[0]
            node['transport_host'] = params.get('host', [''])[0]
            node['transport_headers'] = json.loads(params.get('headers', ['{}'])[0])
            node['transport_max_early_data'] = int(params.get('maxearlydata', ['0'])[0])
            node['transport_early_data_header'] = params.get('earlydataheader', [''])[0]
            node['tls_enabled'] = params.get('security', ['none'])[0].lower() == 'tls' or \
                                 params.get('tls', ['none'])[0].lower() == 'tls'
            node['tls_server_name'] = params.get('sni', [node['server']])[0] or params.get('host', [node['server']])[0]
            node['tls_insecure'] = params.get('allowInsecure', ['0'])[0] == '1'
            node['tls_fingerprint'] = params.get('fp', [''])[0]
            node['tls_reality_short_id'] = params.get('pbk', [''])[0]
            node['tls_reality_public_key'] = params.get('sid', [''])[0]
            node['flow'] = params.get('flow', [''])[0]
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
        original_protocol_prefix = node_str.split('://')[0].lower()
        detected_protocol = original_protocol_prefix
        if original_protocol_prefix == 'ss':
            try:
                parts_after_prefix = node_str.split('://', 1)[1]
                if '@' in parts_after_prefix:
                    potential_auth_part_encoded = parts_after_prefix.split('@', 1)[0]
                    decoded_auth_part_url = urllib.parse.unquote(potential_auth_part_encoded)
                    potential_uuid = None
                    try:
                        missing_padding = len(decoded_auth_part_url) % 4
                        if missing_padding:
                            decoded_auth_part_url += '=' * (4 - missing_padding)
                        b64_decoded_auth = base64.b64decode(decoded_auth_part_url.encode('utf-8')).decode('utf-8')
                        if UUID_PATTERN.match(b64_decoded_auth):
                            potential_uuid = b64_decoded_auth
                    except Exception:
                        if UUID_PATTERN.match(decoded_auth_part_url):
                            potential_uuid = decoded_auth_part_url
                    query_part = parts_after_prefix.split('?', 1)[1] if '?' in parts_after_prefix else ''
                    if potential_uuid or any(re.search(pattern, query_part) for pattern in VLESS_PARAM_PATTERNS):
                        detected_protocol = 'vless'
                        logger.debug(f"SS 链接疑似包含 UUID 或 VLESS 参数，尝试按 VLESS 解析: {node_str}")
            except Exception as e:
                logger.debug(f"SS 伪装检测失败: {node_str}: {e}")
        if detected_protocol not in PROTOCOLS:
            logger.warning(f"不支持的协议: {detected_protocol} (原始: {original_protocol_prefix}) in {node_str}")
            self.invalid_nodes += 1
            self.malformed_nodes.append(node_str)
            return
        self.unique_nodes.add(node_str)
        self.protocol_counts[detected_protocol] += 1
        if detected_protocol != original_protocol_prefix and original_protocol_prefix in self.protocol_counts:
            if self.protocol_counts[original_protocol_prefix] > 0:
                self.protocol_counts[original_protocol_prefix] -= 1
        parser_map = {
            'hysteria2': self.parse_hysteria2,
            'vmess': self.parse_vmess,
            'trojan': self.parse_trojan,
            'ss': self.parse_ss,
            'ssr': self.parse_ssr,
            'vless': self.parse_vless
        }
        parsed = {}
        if detected_protocol in parser_map:
            parsed = parser_map[detected_protocol](node_str)
        else:
            logger.warning(f"未知协议前缀: {node_str}")
            self.invalid_nodes += 1
            self.malformed_nodes.append(node_str)
            return
        if parsed and parsed.get('server') and parsed.get('port'):
            self.parsed_nodes.append(parsed)

    def save_malformed_nodes(self):
        if self.malformed_nodes:
            os.makedirs('data', exist_ok=True)
            with open('data/malformed.txt', 'a', encoding='utf-8') as f:
                f.write('\n'.join(self.malformed_nodes) + '\n')
            logger.warning(f"保存了 {len(self.malformed_nodes)} 个无效节点到 data/malformed.txt")
            self.malformed_nodes.clear()

@asynccontextmanager
async def singbox_proxy(node: Dict, config_path: str = 'temp_config.json', proxy_port: int = 2080):
    outbound_config = {
        'type': node['protocol'],
        'server': node['server'],
        'server_port': node['port']
    }
    if node['protocol'] == 'hysteria2':
        outbound_config['password'] = node.get('auth', '')
    elif node['protocol'] == 'vmess':
        outbound_config['uuid'] = node.get('uuid', '')
        outbound_config['alter_id'] = node.get('alterId', 0)
        outbound_config['security'] = node.get('security', 'auto')
        transport_type = node.get('network', 'tcp')
        outbound_config['transport'] = {'type': transport_type}
        if transport_type == 'ws':
            outbound_config['transport']['path'] = node.get('params', {}).get('path', [''])[0]
            outbound_config['transport']['headers'] = {'Host': node.get('params', {}).get('host', [node['server']])[0]}
        if node.get('security', '').lower() == 'tls':
            outbound_config['tls'] = {
                'enabled': True,
                'server_name': node.get('params', {}).get('sni', [node['server']])[0] or node['server'],
                'insecure': node.get('params', {}).get('allowInsecure', ['0'])[0] == '1'
            }
        if 'tls' in node.get('params', {}):
            outbound_config['tls'] = {'enabled': True}
            if 'sni' in node.get('params', {}):
                outbound_config['tls']['server_name'] = node['params']['sni'][0]
            if 'host' in node.get('params', {}):
                outbound_config['tls']['server_name'] = node['params']['host'][0]
            if 'allowInsecure' in node.get('params', {}):
                outbound_config['tls']['insecure'] = node['params']['allowInsecure'][0] == '1'
    elif node['protocol'] == 'trojan':
        outbound_config['password'] = node.get('password', '')
        if node.get('params', {}).get('type', [''])[0].lower() == 'ws':
            outbound_config['transport'] = {
                'type': 'ws',
                'path': node.get('params', {}).get('path', [''])[0],
                'headers': {'Host': node.get('params', {}).get('host', [node['server']])[0]}
            }
        if node.get('params', {}).get('security', [''])[0].lower() == 'tls' or \
           node.get('params', {}).get('tls', [''])[0].lower() == 'tls':
            outbound_config['tls'] = {
                'enabled': True,
                'server_name': node.get('params', {}).get('sni', [node['server']])[0] or node['server'],
                'insecure': node.get('params', {}).get('allowInsecure', ['0'])[0] == '1'
            }
    elif node['protocol'] == 'ss':
        outbound_config['method'] = node.get('method', '')
        outbound_config['password'] = node.get('password', '')
    elif node['protocol'] == 'ssr':
        outbound_config['method'] = node.get('method', '')
        outbound_config['password'] = node.get('password', '')
        outbound_config['protocol'] = node.get('protocol_ssr', 'origin')
        outbound_config['protocol_param'] = node.get('protocol_param', '')
        outbound_config['obfs'] = node.get('obfs', 'plain')
        outbound_config['obfs_param'] = node.get('obfs_param', '')
    elif node['protocol'] == 'vless':
        outbound_config['uuid'] = node.get('uuid', '')
        outbound_config['flow'] = node.get('flow', '')
        transport_type = node.get('transport_type', 'tcp')
        outbound_config['transport'] = {'type': transport_type}
        if transport_type == 'ws':
            outbound_config['transport']['path'] = node.get('transport_path', '')
            outbound_config['transport']['headers'] = {'Host': node.get('transport_host', node['server'])}
        elif transport_type == 'grpc':
            outbound_config['transport']['service_name'] = node.get('params', {}).get('serviceName', [''])[0]
            outbound_config['transport']['idle_timeout'] = int(node.get('params', {}).get('idleTimeout', ['0'])[0])
        if node.get('tls_enabled'):
            outbound_config['tls'] = {
                'enabled': True,
                'server_name': node.get('tls_server_name', node['server']),
                'insecure': node.get('tls_insecure', False)
            }
            if node.get('tls_fingerprint'):
                outbound_config['tls']['fingerprint'] = node.get('tls_fingerprint')
            if node.get('tls_reality_short_id') and node.get('tls_reality_public_key'):
                outbound_config['tls']['reality'] = {
                    'enabled': True,
                    'public_key': node.get('tls_reality_public_key'),
                    'short_id': node.get('tls_reality_short_id')
                }
    config = {
        'log': {'level': 'error'},
        'inbounds': [
            {
                'type': 'socks',
                'listen': '127.0.0.1',
                'listen_port': proxy_port
            }
        ],
        'outbounds': [outbound_config]
    }
    process = None
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)
        process = await asyncio.create_subprocess_exec(
            'sing-box', 'run', '-c', config_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        logger.debug(f"Sing-box 进程 {process.pid} 已启动，监听 127.0.0.1:{proxy_port}")
        await asyncio.sleep(1)
        if process.returncode is not None:
            stderr = await process.stderr.read() if process.stderr else b''
            raise RuntimeError(f"Sing-box 进程启动后立即退出，Exit Code: {process.returncode}, Stderr: {stderr.decode('utf-8', errors='ignore')}")
        yield f"socks5://127.0.0.1:{proxy_port}"
    except Exception as e:
        logger.error(f"启动 Sing-box 代理失败，节点: {node['raw']}: {e}")
        yield None
    finally:
        if process and process.returncode is None:
            try:
                process.terminate()
                await asyncio.wait_for(process.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                process.kill()
            except ProcessLookupError:
                logger.debug(f"Sing-box 进程 {process.pid} 已提前终止")
            logger.debug(f"Sing-box 进程 {process.pid} 已终止")
        if os.path.exists(config_path):
            try:
                os.remove(config_path)
            except Exception as e:
                logger.error(f"删除 {config_path} 失败: {e}")

async def test_connectivity(node: Dict) -> bool:
    config_file = 'temp_test_config.json'
    async with singbox_proxy(node, config_path=config_file) as proxy_address:
        if not proxy_address:
            logger.warning(f"无法启动 Sing-box 代理进行测试: {node.get('raw', '未知节点')}")
            return False
        try:
            async with httpx.AsyncClient(proxy=proxy_address, timeout=7) as client:
                response = await client.get(TEST_URL)
                if 200 <= response.status_code < 400:
                    logger.info(f"测试成功: {node.get('raw', '未知节点')}")
                    return True
                else:
                    logger.warning(f"测试失败 (HTTP 状态码 {response.status_code}): {node.get('raw', '未知节点')}")
                    return False
        except httpx.RequestError as e:
            logger.warning(f"测试失败 (请求错误): {node.get('raw', '未知节点')}: {e}")
            return False
        except asyncio.TimeoutError:
            logger.warning(f"测试超时: {node.get('raw', '未知节点')}")
            return False
        except Exception as e:
            logger.error(f"测试连通性时发生未知错误: {node.get('raw', '未知节点')}: {e}")
            return False

async def process_nodes():
    parser = NodeParser()
    failed_nodes: Set[str] = set()
    try:
        os.makedirs('data', exist_ok=True)
        if os.path.exists('data/failed.txt'):
            with open('data/failed.txt', 'r', encoding='utf-8', errors='ignore') as f:
                failed_nodes = set(line.strip() for line in f if line.strip())
            logger.warning(f"加载了 {len(failed_nodes)} 个历史失败节点")
        node_source_file = 'data/sub.txt'
        nodes = []
        if not os.path.exists(node_source_file):
            try:
                logger.warning(f"本地 {node_source_file} 不存在，尝试从 GitHub 下载...")
                github_url = 'https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/sub.txt'
                with urllib.request.urlopen(github_url, timeout=10) as response:
                    nodes = response.read().decode('utf-8', errors='ignore').split('\n')
                with open(node_source_file, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(nodes))
                logger.warning(f"从 GitHub 下载并保存了 {len(nodes)} 个节点到 {node_source_file}")
            except Exception as e:
                logger.error(f"从 GitHub 下载节点失败: {e}")
                logger.error("请检查网络连接或 GitHub 链接是否有效。程序将退出。")
                return
        else:
            with open(node_source_file, 'r', encoding='utf-8', errors='ignore') as f:
                nodes = f.read().split('\n')
            logger.warning(f"从本地 {node_source_file} 加载了 {len(nodes)} 个节点")
        nodes = [node.strip() for node in nodes if node.strip() and node.strip() not in failed_nodes]
        if not nodes:
            logger.warning("没有可供解析的新节点或所有节点都已在失败列表中。")
            return
        batch_size = 5000
        for i in range(0, len(nodes), batch_size):
            batch = nodes[i:i + batch_size]
            for node_url in batch:
                parser.parse_node(node_url, failed_nodes)
            logger.warning(f"处理了 {min(i + len(batch), len(nodes))}/{len(nodes)} 个节点")
        logger.warning(f"解析完成: {len(parser.parsed_nodes)} 个唯一且格式正确的节点，跳过了 {parser.invalid_nodes} 个无效节点")
        logger.warning(f"协议统计: {parser.protocol_counts}")
        parser.save_malformed_nodes()
        valid_nodes = []
        new_failed_nodes = []
        total_nodes_to_test = len(parser.parsed_nodes)
        if total_nodes_to_test == 0:
            logger.warning("没有可测试的节点。")
            return
        for i, node in enumerate(parser.parsed_nodes, 1):
            if await test_connectivity(node):
                valid_nodes.append(node)
            else:
                new_failed_nodes.append(node)
            if i % 100 == 0 or i == total_nodes_to_test:
                logger.warning(f"测试进度: {i}/{total_nodes_to_test} 个节点 (有效: {len(valid_nodes)}, 失败: {len(new_failed_nodes)})")
        with open('data/all.txt', 'w', encoding='utf-8') as f:
            for node_data in valid_nodes:
                f.write(node_data['raw'] + '\n')
        logger.warning(f"保存了 {len(valid_nodes)} 个有效节点到 data/all.txt")
        all_failed_nodes = failed_nodes.union(node_data['raw'] for node_data in new_failed_nodes)
        with open('data/failed.txt', 'w', encoding='utf-8') as f:
            for node_url in all_failed_nodes:
                f.write(node_url + '\n')
        logger.warning(f"保存了 {len(all_failed_nodes)} 个失败节点到 data/failed.txt")
    except Exception as e:
        logger.exception(f"处理节点时发生致命错误: {e}")
        raise

if __name__ == '__main__':
    asyncio.run(process_nodes())
