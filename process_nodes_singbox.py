import asyncio
import json
import os
import base64
import urllib.request
import urllib.parse
import subprocess
import logging
import httpx # 引入 httpx
import re    # 引入正则表达式模块
from typing import Dict, List, Set
from contextlib import asynccontextmanager # 使用异步上下文管理器

# --- 配置日志 ---
# 调整为 WARNING 级别以减少输出，可以根据需要改为 INFO 或 DEBUG 了解更多细节
logging.basicConfig(level=logging.WARNING, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- 常量定义 ---
PROTOCOLS = ['hysteria2', 'vmess', 'trojan', 'ss', 'ssr', 'vless']
# 用于匹配 UUID 的正则表达式模式
UUID_PATTERN = re.compile(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', re.IGNORECASE)
# 测试连通性的目标 URL
TEST_URL = "http://www.google.com/generate_204" # Google 提供的无内容响应，用于测试连接

# --- NodeParser 类：负责解析节点链接 ---
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
            # VMess 通常是 vmess://base64_encoded_json
            # 但有些客户端可能直接支持 vmess://uuid@server:port?params
            # urlllib.parse.urlparse 能够处理这种情况
            parsed = urllib.parse.urlparse(url)
            
            # 尝试解码 Base64 部分 (如果存在)
            if parsed.hostname is None and parsed.path: # vmess://base64_encoded_json 模式
                try:
                    decoded_json_str = urllib.parse.unquote(parsed.path.lstrip('/')).encode('utf-8')
                    # Base64 解码，需要处理可能的填充
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
                        'security': decoded_data.get('type', 'auto'), # 这里type通常是加密方式
                        'transport_settings': decoded_data.get('tlsSettings', {}), # 捕获传输层设置
                        'raw': url
                    }
                except (json.JSONDecodeError, base64.binascii.Error) as je:
                    logger.warning(f"VMess Base64 解析失败，尝试按 direct URL 格式解析: {url} - {je}")
                    # 如果 Base64 解析失败，则回退到直接 URL 解析
                    # vmess://uuid@server:port?params
                    node = {
                        'protocol': 'vmess',
                        'server': parsed.hostname or '',
                        'port': int(parsed.port) if parsed.port else 443,
                        'uuid': parsed.username or '', # vmess的username通常是uuid
                        'alterId': int(urllib.parse.parse_qs(parsed.query).get('aid', ['0'])[0]),
                        'network': urllib.parse.parse_qs(parsed.query).get('net', ['tcp'])[0],
                        'security': urllib.parse.parse_qs(parsed.query).get('type', ['auto'])[0],
                        'params': urllib.parse.parse_qs(parsed.query),
                        'raw': url
                    }
            else: # vmess://uuid@server:port?params 模式
                node = {
                    'protocol': 'vmess',
                    'server': parsed.hostname or '',
                    'port': int(parsed.port) if parsed.port else 443,
                    'uuid': parsed.username or '', # vmess的username通常是uuid
                    'alterId': int(urllib.parse.parse_qs(parsed.query).get('aid', ['0'])[0]),
                    'network': urllib.parse.parse_qs(parsed.query).get('net', ['tcp'])[0],
                    'security': urllib.parse.parse_qs(parsed.query).get('type', ['auto'])[0],
                    'params': urllib.parse.parse_qs(parsed.query),
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
            # SS 链接通常是 ss://base64(method:password)@server:port#remarks
            # 或者 ss://method:password@server:port#remarks (不常见，但某些客户端可能支持)
            # 或 ss://base64_encoded_info@server:port?params
            
            # 解析 URL 结构
            parts = url.split('://', 1)
            if len(parts) < 2:
                raise ValueError("无效的 SS URL 格式")
            
            # auth_part 可能是 base64 编码的 method:password，也可能是直接的 method:password
            # server_info_part 是 server:port?params#remarks
            auth_server_parts = parts[1].split('@', 1)
            if len(auth_server_parts) < 2:
                 raise ValueError("SS URL 缺少 @ 分隔符")
            
            auth_part_raw = auth_server_parts[0]
            server_info_part = auth_server_parts[1]

            method = ""
            password = ""
            
            # 尝试 Base64 解码 auth 部分
            try:
                # 尝试 URL 解码后再 Base64 解码
                decoded_auth_part = urllib.parse.unquote(auth_part_raw)
                missing_padding = len(decoded_auth_part) % 4
                if missing_padding:
                    decoded_auth_part += '=' * (4 - missing_padding)
                
                decoded_auth_bytes = base64.b64decode(decoded_auth_part.encode('utf-8'))
                decoded_auth_str = decoded_auth_bytes.decode('utf-8')
                
                if ':' in decoded_auth_str:
                    method, password = decoded_auth_str.split(':', 1)
                else:
                    # 如果 Base64 解码后没有冒号，可能是旧的单一密码模式，或解码失败
                    logger.warning(f"SS Base64 解码后缺少 ':'，尝试直接解析 auth 部分: {decoded_auth_str}")
                    method = "auto" # 假设一个默认方法
                    password = decoded_auth_str
            except (base64.binascii.Error, UnicodeDecodeError):
                # 如果 Base64 解码失败，尝试直接将 auth_part_raw 作为 method:password
                if ':' in auth_part_raw:
                    method, password = auth_part_raw.split(':', 1)
                else:
                    # 如果直接解析也没有冒号，则格式不正确
                    raise ValueError(f"SS auth 格式无效 (缺少 : 或 Base64 解码失败): {auth_part_raw}")

            # 解析服务器地址和端口
            server_port_params = server_info_part.split('#')[0] # 移除备注
            
            # 分割服务器和端口，考虑 IPv6 地址
            if ']:' in server_port_params: # IPv6 with port
                server = server_port_params.split(']:')[0] + ']'
                port = server_port_params.split(']:')[1].split('?', 1)[0]
            elif ':' in server_port_params and server_port_params.count(':') > 1 and '[' not in server_port_params: # IPv6 without bracket, but with params
                # This case is tricky, might need more robust IPv6 parsing
                # For simplicity, we assume standard host:port or [IPv6]:port
                raise ValueError("无法解析带有非标准 IPv6 格式的 SS URL")
            elif ':' in server_port_params: # IPv4 or hostname with port
                server = server_port_params.rsplit(':', 1)[0]
                port = server_port_params.rsplit(':', 1)[1].split('?', 1)[0] # 移除 query string
            else:
                raise ValueError("SS URL 缺少端口信息")
            
            node = {
                'protocol': 'ss',
                'server': server.strip(),
                'port': int(port),
                'method': method.strip(),
                'password': password.strip(),
                'raw': url
            }
            if not node['server'] or not node['port'] or not node['method'] or not node['password']:
                raise ValueError("SS 节点关键信息不完整")
            return node
        except Exception as e:
            logger.error(f"解析 ss 错误: {url}: {e}")
            self.invalid_nodes += 1
            self.malformed_nodes.append(url)
            return {}

    def parse_ssr(self, url: str) -> Dict:
        try:
            # SSR 链接通常是 ssr://base64_encoded_params
            parsed_base = url.split('ssr://', 1)[1]
            missing_padding = len(parsed_base) % 4
            if missing_padding:
                parsed_base += '=' * (4 - missing_padding)
            decoded_base = base64.b64decode(parsed_base.replace('-', '+').replace('_', '/')).decode('utf-8')
            
            # 从解码后的字符串中提取各个部分
            parts = decoded_base.split(':')
            if len(parts) < 6:
                raise ValueError("SSR 链接参数不足")

            server = parts[0]
            port = int(parts[1])
            protocol = parts[2]
            method = parts[3]
            obfs = parts[4]
            password_base64 = parts[5].split('/')[0] # 密码部分，可能包含斜杠

            password = base64.b64decode(password_base64.replace('-', '+').replace('_', '/')).decode('utf-8')

            # 提取可选参数
            params = {}
            if len(parts) > 6:
                # 处理 obfsparam, protoparam, remarks 等
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
                'protocol_ssr': protocol, # SSR 协议类型
                'method': method,
                'obfs': obfs, # 混淆类型
                'password': password,
                'protocol_param': params.get('protoparam', [''])[0],
                'obfs_param': params.get('obfsparam', [''])[0],
                'remarks': urllib.parse.unquote(remarks),
                'raw': url
            }
            
            if not node['server'] or not node['password']:
                raise ValueError("SSR 服务器地址或密码为空")
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

            # VLESS 链接通常是 vless://uuid@server:port?params
            node = {
                'protocol': 'vless',
                'server': parsed.hostname or '',
                'port': int(parsed.port) if parsed.port else 443,
                'uuid': parsed.username or '',
                'params': params, # 存储所有查询参数
                'raw': url
            }
            if not node['server'] or not node['uuid']:
                raise ValueError("服务器地址或 UUID 为空")

            # 从 params 中提取 VLESS 相关的详细配置
            # transport (type, path, host etc.)
            node['transport_type'] = params.get('type', ['tcp'])[0]
            node['transport_path'] = params.get('path', [''])[0]
            node['transport_host'] = params.get('host', [''])[0]
            node['transport_headers'] = json.loads(params.get('headers', ['{}'])[0]) # 尝试解析 JSON 格式的 headers
            node['transport_max_early_data'] = int(params.get('maxearlydata', ['0'])[0])
            node['transport_early_data_header'] = params.get('earlydataheader', [''])[0]
            
            # TLS settings
            node['tls_enabled'] = params.get('security', ['none'])[0].lower() == 'tls' or \
                                  params.get('tls', ['none'])[0].lower() == 'tls' # security=tls 或 tls=tls
            node['tls_server_name'] = params.get('sni', [node['server']])[0] or params.get('host', [node['server']])[0] # SNI
            node['tls_insecure'] = params.get('allowInsecure', ['0'])[0] == '1'
            node['tls_fingerprint'] = params.get('fp', [''])[0] # 指纹
            node['tls_reality_short_id'] = params.get('pbk', [''])[0] # Reality
            node['tls_reality_public_key'] = params.get('sid', [''])[0] # Reality
            node['flow'] = params.get('flow', [''])[0] # VLESS flow

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
        detected_protocol = original_protocol_prefix # 初始假定协议

        # --- 智能协议识别逻辑 (针对伪装的 SS 链接) ---
        if original_protocol_prefix == 'ss':
            try:
                # 尝试提取 @ 符号前的内容，这通常是 SS 的 method:password 或伪装的 UUID
                parts_after_prefix = node_str.split('://', 1)[1]
                if '@' in parts_after_prefix:
                    potential_auth_part_encoded = parts_after_prefix.split('@', 1)[0]
                    
                    # 尝试 URL 解码
                    decoded_auth_part_url = urllib.parse.unquote(potential_auth_part_encoded)
                    
                    potential_uuid = None
                    try:
                        # 尝试 Base64 解码，如果成功且是 UUID，则可能是伪装
                        missing_padding = len(decoded_auth_part_url) % 4
                        if missing_padding:
                            decoded_auth_part_url += '=' * (4 - missing_padding)
                        b64_decoded_auth = base64.b64decode(decoded_auth_part_url.encode('utf-8')).decode('utf-8')
                        if UUID_PATTERN.match(b64_decoded_auth):
                            potential_uuid = b64_decoded_auth
                    except Exception:
                        # Base64 解码失败或不是有效的 UTF-8，则可能是直接的非 Base64 编码的 UUID
                        if UUID_PATTERN.match(decoded_auth_part_url):
                            potential_uuid = decoded_auth_part_url

                    if potential_uuid:
                        # 如果是 UUID，那么很可能是 VLESS 或 VMess
                        # 考虑到你提供的例子中有很多像 type=ws, host 等参数，VLESS 更常见这种格式
                        # 将协议更正为 vless
                        detected_protocol = 'vless'
                        logger.debug(f"SS链接 '{node_str}' 疑似包含 UUID '{potential_uuid}'，尝试按 '{detected_protocol}' 解析。")
            except Exception as e:
                logger.debug(f"尝试检查 SS 链接是否伪装失败: {e}")
        # --- 智能协议识别逻辑结束 ---

        if detected_protocol not in PROTOCOLS:
            logger.warning(f"不支持的协议: {detected_protocol} (原始: {original_protocol_prefix}) in {node_str}")
            self.invalid_nodes += 1
            self.malformed_nodes.append(node_str)
            return

        self.unique_nodes.add(node_str)
        
        # 使用检测到的协议进行计数
        self.protocol_counts[detected_protocol] += 1
        # 如果协议被更正了，减少原始协议的计数
        if detected_protocol != original_protocol_prefix:
            if original_protocol_prefix in self.protocol_counts: # 确保存在
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
        # 根据检测到的协议调用相应的解析器
        if detected_protocol in parser_map:
            parsed = parser_map[detected_protocol](node_str)
        else:
            # 这部分理论上不应该执行，因为前面已经过滤了不支持的协议
            logger.warning(f"未知协议前缀 (应该被过滤): {node_str}")
            self.invalid_nodes += 1
            self.malformed_nodes.append(node_str)
            return

        if parsed and parsed.get('server') and parsed.get('port'):
            self.parsed_nodes.append(parsed)

    def save_malformed_nodes(self):
        if self.malformed_nodes:
            os.makedirs('data', exist_ok=True) # 确保data目录存在
            with open('data/malformed.txt', 'a', encoding='utf-8') as f:
                f.write('\n'.join(self.malformed_nodes) + '\n')
            logger.warning(f"保存了 {len(self.malformed_nodes)} 个无效节点到 data/malformed.txt")
            self.malformed_nodes.clear()

# --- singbox_proxy 异步上下文管理器：启动 Sing-box 作为本地代理 ---
@asynccontextmanager
async def singbox_proxy(node: Dict, config_path: str = 'temp_config.json', proxy_port: int = 2080):
    """
    启动 Sing-box 作为代理服务器，并提供一个代理地址。
    此函数会动态构建 Sing-box 配置文件。
    """
    outbound_config = {
        'type': node['protocol'],
        'server': node['server'],
        'server_port': node['port']
    }

    # 根据协议类型填充出站配置的详细参数
    if node['protocol'] == 'hysteria2':
        outbound_config['password'] = node.get('auth', '')
        # Hysteria2 可能还需要其他参数，例如 up/down, alpn, obfs 等，这里根据需要添加
    elif node['protocol'] == 'vmess':
        outbound_config['uuid'] = node.get('uuid', '')
        outbound_config['alter_id'] = node.get('alterId', 0)
        outbound_config['security'] = node.get('security', 'auto')
        # VMess 传输层设置
        transport_type = node.get('network', 'tcp')
        outbound_config['transport'] = {'type': transport_type}
        if transport_type == 'ws':
            outbound_config['transport']['path'] = node.get('params', {}).get('path', [''])[0]
            outbound_config['transport']['headers'] = {'Host': node.get('params', {}).get('host', [node['server']])[0]}
        # VMess TLS 设置
        if node.get('security', '').lower() == 'tls': # 如果 security 指示 TLS
            outbound_config['tls'] = {
                'enabled': True,
                'server_name': node.get('params', {}).get('sni', [node['server']])[0] or node['server'],
                'insecure': node.get('params', {}).get('allowInsecure', ['0'])[0] == '1'
            }
        # 兼容旧版 VMess 参数
        if 'tls' in node.get('params', {}): # 如果原始链接有 tls=1
            outbound_config['tls'] = {'enabled': True} # 至少启用 TLS
            if 'sni' in node.get('params', {}):
                outbound_config['tls']['server_name'] = node['params']['sni'][0]
            if 'host' in node.get('params', {}):
                outbound_config['tls']['server_name'] = node['params']['host'][0] # Host 也可以作为 SNI
            if 'allowInsecure' in node.get('params', {}):
                outbound_config['tls']['insecure'] = node['params']['allowInsecure'][0] == '1'


    elif node['protocol'] == 'trojan':
        outbound_config['password'] = node.get('password', '')
        # Trojan 传输和 TLS 设置
        # 例如，如果链接中有 type=ws, security=tls, sni=...
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
        # Shadowsocks 通常没有复杂的传输和 TLS 配置，但一些变种可能有
        # 如果需要支持 ss over ws/tls, 需要在此处添加复杂的解析和配置
        # 目前脚本中 SS 解析不处理 transport 和 TLS 参数，但 Sing-box 可能需要

    elif node['protocol'] == 'ssr':
        outbound_config['method'] = node.get('method', '')
        outbound_config['password'] = node.get('password', '')
        outbound_config['protocol'] = node.get('protocol_ssr', 'origin') # SSR 协议参数
        outbound_config['protocol_param'] = node.get('protocol_param', '')
        outbound_config['obfs'] = node.get('obfs', 'plain') # SSR 混淆参数
        outbound_config['obfs_param'] = node.get('obfs_param', '')

    elif node['protocol'] == 'vless':
        outbound_config['uuid'] = node.get('uuid', '')
        outbound_config['flow'] = node.get('flow', '') # VLESS flow

        # VLESS 传输层设置
        transport_type = node.get('transport_type', 'tcp')
        outbound_config['transport'] = {'type': transport_type}
        if transport_type == 'ws':
            outbound_config['transport']['path'] = node.get('transport_path', '')
            outbound_config['transport']['headers'] = {'Host': node.get('transport_host', node['server'])}
        elif transport_type == 'grpc': # 示例，如果支持 gRPC
             outbound_config['transport']['service_name'] = node.get('params', {}).get('serviceName', [''])[0]
             outbound_config['transport']['idle_timeout'] = int(node.get('params', {}).get('idleTimeout', ['0'])[0])
             # 其他 gRPC 参数

        # VLESS TLS 设置
        if node.get('tls_enabled'):
            outbound_config['tls'] = {
                'enabled': True,
                'server_name': node.get('tls_server_name', node['server']),
                'insecure': node.get('tls_insecure', False)
            }
            if node.get('tls_fingerprint'):
                outbound_config['tls']['fingerprint'] = node['tls_fingerprint']
            if node.get('tls_reality_short_id') and node.get('tls_reality_public_key'): # Reality
                outbound_config['tls']['reality'] = {
                    'enabled': True,
                    'public_key': node['tls_reality_public_key'],
                    'short_id': node['tls_reality_short_id']
                }


    config = {
        'log': {'level': 'error'}, # Sing-box 日志级别
        'inbounds': [
            {
                'type': 'socks', # 监听 Socks5 代理
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

        # 启动 sing-box 进程
        process = await asyncio.create_subprocess_exec(
            'sing-box', 'run', '-c', config_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        logger.debug(f"Sing-box 进程 {process.pid} 已启动，监听 127.0.0.1:{proxy_port}")

        # 给予 sing-box 启动时间
        await asyncio.sleep(1) # 给足时间让 Sing-box 完全启动

        yield f"socks5://127.0.0.1:{proxy_port}" # 提供代理地址
    except Exception as e:
        logger.error(f"启动 Sing-box 代理失败，节点: {node['raw']}: {e}")
        yield None # 如果启动失败，返回None
    finally:
        if process:
            try:
                process.terminate() # 尝试终止进程
                await asyncio.wait_for(process.wait(), timeout=2.0) # 等待进程结束
            except asyncio.TimeoutError:
                process.kill() # 如果无法终止，则强制杀死
            logger.debug(f"Sing-box 进程 {process.pid} 已终止")
        if os.path.exists(config_path):
            try:
                os.remove(config_path)
            except Exception as e:
                logger.error(f"删除 {config_path} 失败: {e}")

# --- test_connectivity 函数：通过代理测试网页连通性 ---
async def test_connectivity(node: Dict) -> bool:
    """
    通过 Sing-box 代理实际访问一个网页来测试节点连通性。
    """
    config_file = 'temp_test_config.json' # 为每个测试使用独立的临时配置文件

    async with singbox_proxy(node, config_path=config_file) as proxy_address:
        if not proxy_address:
            logger.warning(f"无法启动 Sing-box 代理进行测试: {node.get('raw', '未知节点')}")
            return False

        try:
            # httpx 客户端，配置代理和超时
            async with httpx.AsyncClient(proxies={"http://": proxy_address, "https://": proxy_address}, timeout=7) as client:
                response = await client.get(TEST_URL)
                # 检查 HTTP 状态码是否表示成功
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

# --- process_nodes 主函数：管理节点处理流程 ---
async def process_nodes():
    parser = NodeParser()
    failed_nodes: Set[str] = set()

    try:
        os.makedirs('data', exist_ok=True) # 确保data目录存在

        # 加载历史失败节点
        if os.path.exists('data/failed.txt'):
            with open('data/failed.txt', 'r', encoding='utf-8', errors='ignore') as f:
                failed_nodes = set(line.strip() for line in f if line.strip())
            logger.warning(f"加载了 {len(failed_nodes)} 个历史失败节点")

        # 尝试从本地文件加载节点，如果文件不存在则从GitHub下载
        node_source_file = 'data/sub.txt'
        nodes = []
        if not os.path.exists(node_source_file):
            try:
                logger.warning(f"本地 {node_source_file} 不存在，尝试从 GitHub 下载...")
                github_url = 'https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/sub.txt'
                with urllib.request.urlopen(github_url, timeout=10) as response:
                    nodes = response.read().decode('utf-8', errors='ignore').split('\n')
                with open(node_source_file, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(nodes)) # 将下载的节点保存到本地
                logger.warning(f"从 GitHub 下载并保存了 {len(nodes)} 个节点到 {node_source_file}")
            except Exception as e:
                logger.error(f"从 GitHub 下载节点失败: {e}")
                logger.error("请检查网络连接或 GitHub 链接是否有效。程序将退出。")
                return # 下载失败则退出
        else:
            with open(node_source_file, 'r', encoding='utf-8', errors='ignore') as f:
                nodes = f.read().split('\n')
            logger.warning(f"从本地 {node_source_file} 加载了 {len(nodes)} 个节点")

        # 过滤掉空行和已经失败的节点
        nodes = [node.strip() for node in nodes if node.strip() and node.strip() not in failed_nodes]
        if not nodes:
            logger.warning("没有可供解析的新节点或所有节点都已在失败列表中。")
            return

        # 批量解析节点
        batch_size = 5000 # 可以根据内存调整
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

        # 异步并发测试节点
        # 可以使用 asyncio.gather 来并发测试，但这会同时启动大量 Sing-box 进程，可能导致资源耗尽
        # 更稳健的做法是使用 asyncio.Semaphore 来限制并发数量
        
        # 为简化，这里仍使用顺序测试，但每次打印进度
        for i, node in enumerate(parser.parsed_nodes, 1):
            if await test_connectivity(node):
                valid_nodes.append(node)
            else:
                new_failed_nodes.append(node)
            
            # 每隔 100 个节点或在测试结束时打印进度
            if i % 100 == 0 or i == total_nodes_to_test:
                logger.warning(f"测试进度: {i}/{total_nodes_to_test} 个节点 (有效: {len(valid_nodes)}, 失败: {len(new_failed_nodes)})")

        # 保存有效节点到 all.txt
        with open('data/all.txt', 'w', encoding='utf-8') as f:
            for node_data in valid_nodes:
                f.write(node_data['raw'] + '\n') # 保存原始链接
        logger.warning(f"保存了 {len(valid_nodes)} 个有效节点到 data/all.txt")

        # 合并所有失败节点，包括本次新失败的和历史失败的
        all_failed_nodes = failed_nodes.union(node_data['raw'] for node_data in new_failed_nodes)
        with open('data/failed.txt', 'w', encoding='utf-8') as f:
            for node_url in all_failed_nodes:
                f.write(node_url + '\n')
        logger.warning(f"保存了 {len(all_failed_nodes)} 个失败节点到 data/failed.txt")

    except Exception as e:
        logger.exception(f"处理节点时发生致命错误: {e}") # 使用 exception 打印完整的堆栈信息
        raise

# --- 脚本入口点 ---
if __name__ == '__main__':
    asyncio.run(process_nodes())
