import asyncio
import aiohttp
import json
import os
import re
import subprocess
import time
import base64
import urllib.parse
from urllib.parse import urlparse, unquote, parse_qs
import logging
import socket
from tqdm import tqdm
import psutil

# 常量配置
SUB_FILE = os.path.join("data", "sub.txt")
ALL_FILE = "all.txt"
FAILED_NODES_FILE = os.path.join("data", "failed.txt")
DATA_DIR = "data"
SINGBOX_CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
SINGBOX_LOG_PATH = os.path.join(DATA_DIR, "singbox.log")
SINGBOX_PATH = "./sing-box"
PORT_RANGE = range(10809, 10910)
TEST_TIMEOUT = 8
CONCURRENCY_LIMIT = 1
BATCH_SIZE = 5
MAX_BATCH_TIME = 30
TARGET_URLS = ["https://www.google.com", "https://1.1.1.1"]
RETRY_ATTEMPTS = 2

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(DATA_DIR, "test.log"), encoding='utf-8', errors='ignore'),
        logging.StreamHandler()
    ]
)

def log_message(message, level="info"):
    """记录日志信息"""
    if level == "info":
        logging.info(message)
    elif level == "error":
        logging.error(message)
    elif level == "warning":
        logging.warning(message)

# 创建数据目录
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# 检查 sing-box 可执行文件
if not os.path.exists(SINGBOX_PATH):
    log_message(f"错误：未找到 sing-box 可执行文件 {SINGBOX_PATH}。请确保已下载并放置在工作目录。", "error")
    exit(1)

def get_free_port():
    """查找一个可用的空闲端口"""
    for port in PORT_RANGE:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except socket.error:
                continue
    log_message("错误：无法找到可用端口", "error")
    return None

def cleanup_singbox_processes():
    """清理所有残留的 sing-box 进程"""
    for proc in psutil.process_iter(['name']):
        try:
            # 检查进程名是否为 sing-box 或 sing-box 可执行文件的相对路径
            if proc.name() == "sing-box" or proc.name() == os.path.basename(SINGBOX_PATH):
                proc.kill()
                log_message(f"清理残留 sing-box 进程 PID: {proc.pid}", "info")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def base64_decode_if_needed(data: str) -> str:
    """尝试对 Base64 编码的数据进行解码"""
    try:
        data += '=' * (-len(data) % 4) # 填充 Base64 字符串
        return base64.b64decode(data).decode('utf-8', errors='ignore')
    except Exception as e:
        log_message(f"Base64 解码失败: {e}", "warning")
        return data

def is_valid_node_url(node_url: str) -> bool:
    """检查节点 URL 是否有效"""
    try:
        parsed = urlparse(node_url)
        if not parsed.scheme or not parsed.netloc:
            return False
        host = parsed.netloc.split('@')[-1].split(':')[0]
        if host.startswith('[') and host.endswith(']'): # IPv6
            host = host[1:-1]
            return re.match(r'^[0-9a-fA-F:]+$', host) is not None
        # IPv4
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            return all(0 <= int(octet) <= 255 for octet in host.split('.'))
        # 域名
        return re.match(r"^[a-zA-Z0-9][a-zA-Z0-9\-]*(\.[a-zA-Z0-9\-]+)*$", host) is not None
    except Exception:
        return False

def parse_tag_info(tag: str) -> dict:
    """从节点标签中解析国家、速度和成功率信息"""
    country = "未知"
    speed = None
    success_rate = None

    if "美国" in tag or "US" in tag.upper():
        country = "美国"
    elif "日本" in tag or "JP" in tag.upper():
        country = "日本"
    elif "香港" in tag or "HK" in tag.upper():
        country = "香港"
    elif "土耳其" in tag or "TR" in tag.upper():
        country = "土耳其"
    # 添加更多国家或地区
    elif "新加坡" in tag or "SG" in tag.upper():
        country = "新加坡"
    elif "德国" in tag or "DE" in tag.upper():
        country = "德国"
    elif "英国" in tag or "UK" in tag.upper() or "GB" in tag.upper():
        country = "英国"
    elif "加拿大" in tag or "CA" in tag.upper():
        country = "加拿大"
    elif "法国" in tag or "FR" in tag.upper():
        country = "法国"
    elif "韩国" in tag or "KR" in tag.upper():
        country = "韩国"
    elif "台湾" in tag or "TW" in tag.upper():
        country = "台湾"
    elif "俄罗斯" in tag or "RU" in tag.upper():
        country = "俄罗斯"
    elif "荷兰" in tag or "NL" in tag.upper():
        country = "荷兰"
    elif "澳大利亚" in tag or "AU" in tag.upper():
        country = "澳大利亚"


    match = re.search(r"⬇️\s*([\d.]+)\s*MB/s", tag)
    if match:
        speed = float(match.group(1))
    match = re.search(r"\|(\d+)%\|", tag)
    if match:
        success_rate = int(match.group(1))
    return {"country": country, "speed": speed, "success_rate": success_rate}

def safe_unquote(s: str) -> str:
    """安全地进行 URL 解码"""
    try:
        return unquote(s, encoding='utf-8', errors='ignore')
    except Exception:
        return s

def extract_node_info(node_url: str) -> dict:
    """从节点 URL 中提取基本信息"""
    if not is_valid_node_url(node_url):
        log_message(f"节点 URL 格式非法，跳过: {node_url}", "warning")
        return None
    parsed_url = urlparse(node_url)
    tag = safe_unquote(parsed_url.fragment) if parsed_url.fragment else "未知"
    node_info = {"url": node_url.strip(), "tag": tag}
    node_info.update(parse_tag_info(tag))
    return node_info

def generate_singbox_config(node_url: str, port: int) -> dict:
    """根据节点 URL 生成 sing-box 配置文件"""
    try:
        parsed_url = urlparse(node_url)
        protocol = parsed_url.scheme.lower()
        netloc = parsed_url.netloc
        query_params = parse_qs(parsed_url.query)
        
        # 处理用户信息（密码或 UUID）
        user_info_part = netloc.split('@')[0] if '@' in netloc else ""
        
        # 处理主机和端口
        host_port_part = netloc.split('@')[1] if '@' in netloc else netloc
        host = host_port_part.split(':')[0]
        server_port = int(host_port_part.split(':')[1]) if ':' in host_port_part else (443 if protocol in ["vless", "trojan", "hysteria2"] else 80)

        # 移除 IPv6 地址的方括号
        if host.startswith('[') and host.endswith(']'):
            host = host[1:-1]

        outbound_config = {
            "tag": safe_unquote(parsed_url.fragment) if parsed_url.fragment else "test-node",
            "server": host,
            "server_port": server_port
        }

        # TLS 设置 (通用部分)
        tls_enabled = query_params.get('security', [''])[0].lower() == 'tls' or (protocol == "hysteria2" and query_params.get('obfs', [''])[0].lower() == 'none') or protocol == "trojan"
        
        tls_settings = {
            "enabled": tls_enabled,
            "server_name": query_params.get('sni', [host])[0],
            "insecure": query_params.get('allowInsecure', ['0'])[0] == '1' or query_params.get('insecure', ['0'])[0] == '1'
        }
        if 'alpn' in query_params:
            tls_settings["alpn"] = query_params['alpn']

        # 协议特定配置
        if protocol == "hysteria2":
            outbound_config["type"] = "hysteria2"
            outbound_config["password"] = user_info_part
            outbound_config["tls"] = {
                "enabled": True, # Hysteria2 默认启用 TLS
                "server_name": query_params.get('sni', [host])[0],
                "insecure": query_params.get('insecure', ['0'])[0] == '1'
            }
            if 'obfs' in query_params:
                obfs_type = query_params['obfs'][0]
                obfs_password = query_params.get('obfsParam', [''])[0] or query_params.get('obfs-password', [''])[0]
                if obfs_type and obfs_password and obfs_type != 'none': # obfs=none 表示无混淆
                    outbound_config["obfs"] = {
                        "type": obfs_type,
                        "password": obfs_password
                    }
            if 'mport' in query_params:
                outbound_config["ports"] = query_params['mport'][0]
            if 'up' in query_params:
                outbound_config["up_mbps"] = int(query_params['up'][0])
            if 'down' in query_params:
                outbound_config["down_mbps"] = int(query_params['down'][0])

        elif protocol == "vless":
            outbound_config["type"] = "vless"
            outbound_config["uuid"] = user_info_part
            if 'flow' in query_params:
                outbound_config["flow"] = query_params['flow'][0]
            
            # 传输协议配置
            if 'type' in query_params:
                transport_type = query_params['type'][0].lower()
                transport_config = {"type": transport_type}

                if transport_type == 'ws':
                    # 修复：将 'host' 映射到 'hostname'
                    if 'host' in query_params:
                        transport_config["hostname"] = query_params['host'][0]
                    if 'path' in query_params:
                        transport_config["path"] = query_params['path'][0]
                    if 'headers' in query_params: # 添加 headers 支持，虽然 sing-box 不一定直接支持所有
                        try:
                            headers_str = query_params['headers'][0]
                            headers_dict = json.loads(headers_str) # 假设 headers 是 JSON 字符串
                            transport_config["headers"] = headers_dict
                        except json.JSONDecodeError:
                            log_message(f"VLESS 节点 {node_url} headers 参数非有效 JSON", "warning")
                elif transport_type == 'http':
                    if 'host' in query_params:
                        transport_config["host"] = query_params['host'] # host 可以是列表
                    if 'path' in query_params:
                        transport_config["path"] = query_params['path'][0]
                elif transport_type == 'grpc':
                    transport_config["service_name"] = query_params.get('serviceName', [''])[0]
                    transport_config["idle_timeout"] = query_params.get('idleTimeout', [''])[0] # 示例
                
                outbound_config["transport"] = transport_config

            if tls_settings['enabled']:
                outbound_config["tls"] = tls_settings
            
            # reality 额外处理 (虽然 sing-box 通常在 TLS 层配置)
            if query_params.get('security', [''])[0].lower() == 'reality':
                outbound_config["tls"] = outbound_config.get("tls", {"enabled": True}) # 确保 TLS 启用
                outbound_config["tls"]["reality"] = {
                    "enabled": True,
                    "handshake_server": query_params.get('fp', [''])[0], # fingerprint
                    "server_public_key": query_params.get('pbk', [''])[0],
                    "short_id": query_params.get('sid', [''])[0],
                    "spider_x": query_params.get('spx', [''])[0]
                }


        elif protocol == "vmess":
            outbound_config["type"] = "vmess"
            vmess_raw = node_url[len("vmess://"):]
            decoded_json = base64_decode_if_needed(vmess_raw)
            try:
                vmess_data = json.loads(decoded_json)
                outbound_config["server"] = vmess_data.get('add', host)
                outbound_config["server_port"] = int(vmess_data.get('port', server_port))
                outbound_config["uuid"] = vmess_data.get('id', '')
                outbound_config["alter_id"] = int(vmess_data.get('aid', 0))
                outbound_config["security"] = vmess_data.get('scy', 'auto') # 加密方式

                # 传输协议配置 (Vmess 同样需要处理)
                transport_type = vmess_data.get('net', 'tcp').lower()
                transport_config = {"type": transport_type}
                
                if transport_type == 'ws':
                    # 修复：将 'host' 映射到 'hostname'
                    if 'host' in vmess_data: # vmess URL 中 'host' 通常在顶层
                        transport_config["hostname"] = vmess_data['host']
                    if 'path' in vmess_data:
                        transport_config["path"] = vmess_data['path']
                    if 'headers' in vmess_data:
                        try:
                            headers_dict = json.loads(vmess_data['headers'])
                            transport_config["headers"] = headers_dict
                        except json.JSONDecodeError:
                             log_message(f"VMESS 节点 {node_url} headers 参数非有效 JSON", "warning")
                elif transport_type == 'http':
                    if 'host' in vmess_data:
                        transport_config["host"] = vmess_data['host']
                    if 'path' in vmess_data:
                        transport_config["path"] = vmess_data['path']
                elif transport_type == 'grpc':
                    transport_config["service_name"] = vmess_data.get('serviceName', '')
                    
                if transport_type != 'tcp': # 只有非 TCP 才有 transport 配置
                    outbound_config["transport"] = transport_config

                # TLS 配置 (Vmess 同样需要处理)
                if vmess_data.get('tls', '0') == 'tls':
                    outbound_config["tls"] = {
                        "enabled": True,
                        "server_name": vmess_data.get('sni', host),
                        "insecure": vmess_data.get('allowInsecure', '0') == '1'
                    }
                    if 'alpn' in vmess_data:
                        outbound_config["tls"]["alpn"] = vmess_data['alpn'].split(',') # ALPN 可能是一个逗号分隔的字符串
                elif tls_settings['enabled']: # Fallback to general TLS settings if not explicitly in VMess data
                    outbound_config["tls"] = tls_settings

            except json.JSONDecodeError as e:
                log_message(f"无法解析 VMESS 节点 JSON {node_url}: {e}", "warning")
                return None
            except Exception as e:
                log_message(f"处理 VMESS 节点 {node_url} 失败: {e}", "warning")
                return None

        elif protocol == "trojan":
            outbound_config["type"] = "trojan"
            outbound_config["password"] = user_info_part
            if tls_settings['enabled']:
                outbound_config["tls"] = tls_settings

        elif protocol == "ss": # Shadowsocks
            if query_params.get('security', [''])[0].lower() == 'reality':
                log_message(f"SS 节点 {node_url} 使用不支持的 Reality 配置，跳过", "warning")
                return None
            
            outbound_config["type"] = "shadowsocks"
            
            if user_info_part and ':' in user_info_part:
                method, password = user_info_part.split(':', 1)
                outbound_config["method"] = method
                outbound_config["password"] = password
            else:
                # 尝试从 URL fragment 或默认值中获取 method 和 password
                # SS URL 格式通常是 ss://method:password@host:port#tag
                # 如果 user_info_part 为空，可能协议部分未包含认证信息
                log_message(f"SS 节点 {node_url} 缺少加密方法或密码，尝试默认 aes-256-gcm", "warning")
                outbound_config["method"] = "aes-256-gcm" # 默认加密方式
                outbound_config["password"] = user_info_part # 将 user_info_part 作为密码，尽管可能不正确

            # Shadowsocks 插件通常不支持 sing-box 的 direct transport
            if 'plugin' in query_params:
                log_message(f"SS 节点 {node_url} 包含插件，sing-box 可能不支持: {query_params['plugin'][0]}", "warning")
                # 可以尝试解析插件参数，但这里暂时跳过复杂插件配置
                return None 
            
            # Shadowsocks 传输类型
            if 'type' in query_params:
                transport_type = query_params['type'][0].lower()
                if transport_type != 'tcp': # sing-box 默认是 tcp
                    log_message(f"SS 节点 {node_url} 使用非 TCP 传输类型: {transport_type}，sing-box 可能不支持或需要特殊配置", "warning")
                    return None
            
            # http headerType 混淆
            if query_params.get('headerType', [''])[0].lower() == 'http':
                # sing-box 的 Shadowsocks 模块通常不支持 http 混淆，这会是问题
                log_message(f"SS 节点 {node_url} 使用 headerType=http，sing-box Shadowsocks 协议不支持此混淆。", "warning")
                return None # 或者选择继续，但可能测试失败

            if tls_settings['enabled']:
                outbound_config["tls"] = tls_settings

        elif protocol == "ssr": # ShadowsocksR
            ssr_raw = node_url[len("ssr://"):]
            decoded = base64_decode_if_needed(ssr_raw)
            parts = decoded.split(':')
            if len(parts) >= 6:
                outbound_config["type"] = "shadowsocksr"
                outbound_config["server"] = parts[0]
                outbound_config["server_port"] = int(parts[1])
                outbound_config["protocol"] = parts[2] # 协议
                outbound_config["method"] = parts[3] # 加密方法
                outbound_config["obfs"] = parts[4] # 混淆方式
                
                # 密码需要再次 Base64 解码
                password_encoded = parts[5].split('/')[0]
                outbound_config["password"] = base64_decode_if_needed(password_encoded)
                
                params = parse_qs(parts[5].split('?')[1]) if '?' in parts[5] else {}
                outbound_config["obfs_param"] = base64_decode_if_needed(params.get('obfsparam', [''])[0]) if params.get('obfsparam') else ""
                outbound_config["protocol_param"] = base64_decode_if_needed(params.get('protoparam', [''])[0]) if params.get('protoparam') else ""
            else:
                log_message(f"SSR 节点 {node_url} 格式无效", "warning")
                return None

        elif protocol == "socks5":
            outbound_config["type"] = "socks"
            if user_info_part and ':' in user_info_part:
                username, password = user_info_part.split(':', 1)
                outbound_config["username"] = username
                outbound_config["password"] = password
            if tls_settings['enabled']:
                outbound_config["tls"] = tls_settings

        else:
            log_message(f"不支持的协议: {protocol}", "warning")
            return None

        # 构建最终的 sing-box 配置
        config = {
            "log": {"level": "info", "output": SINGBOX_LOG_PATH},
            "inbounds": [
                {
                    "type": "http", # 或 "socks"
                    "listen": "127.0.0.1",
                    "listen_port": port
                }
            ],
            "outbounds": [outbound_config]
        }
        return config
    except Exception as e:
        log_message(f"生成 sing-box 配置失败 {node_url}: {e}", "error")
        return None

async def run_singbox_test_inner(node_url: str, session: aiohttp.ClientSession, port: int) -> tuple[bool, float]:
    """内部函数：运行 sing-box 并测试节点连通性"""
    config = generate_singbox_config(node_url, port)
    if not config:
        return False, 0

    process = None
    start_time = time.time()
    try:
        with open(SINGBOX_CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2)

        process = await asyncio.create_subprocess_exec(
            SINGBOX_PATH, 'run', '-c', SINGBOX_CONFIG_PATH,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        # 等待 sing-box 启动
        await asyncio.sleep(1)
        
        # 检查 sing-box 是否立即退出
        if process.returncode is not None:
            stderr_data = await process.stderr.read()
            log_message(f"sing-box 启动失败: {node_url}, 端口: {port}, 错误: {stderr_data.decode('utf-8', errors='ignore')}", "error")
            return False, 0

        proxies = {
            "http": f"http://127.0.0.1:{port}",
            "https": f"http://127.0.0.1:{port}"
        }
        
        # 依次测试目标 URL，只要一个成功就算成功
        for target_url in TARGET_URLS:
            try:
                async with session.get(target_url, proxy=proxies["https"], timeout=TEST_TIMEOUT) as response:
                    if response.status == 200:
                        latency = (time.time() - start_time) * 1000
                        log_message(f"HTTP 请求成功 {node_url}, 目标: {target_url}, 端口: {port}, 延迟: {latency:.2f}ms")
                        return True, latency
            except (asyncio.TimeoutError, aiohttp.ClientError) as e:
                log_message(f"测试 URL {target_url} 失败: {e}", "warning")
                continue # 尝试下一个 URL
        
        return False, 0 # 所有目标 URL 都失败了

    except asyncio.TimeoutError:
        log_message(f"HTTP 请求超时: {node_url}, 端口: {port}", "warning")
        return False, 0
    except aiohttp.ClientError as e:
        log_message(f"HTTP 客户端错误 {node_url}, 端口: {port}: {e}", "warning")
        return False, 0
    except Exception as e:
        log_message(f"测试节点 {node_url} 失败, 端口: {port}: {e}", "error")
        return False, 0
    finally:
        # 终止 sing-box 进程
        if process and process.returncode is None:
            try:
                process.terminate()
                await asyncio.wait_for(process.wait(), timeout=3)
            except asyncio.TimeoutError:
                process.kill()
                log_message(f"强制终止 sing-box 进程: {node_url}, 端口: {port}", "warning")
            except Exception as e:
                log_message(f"终止 sing-box 进程失败: {node_url}, 端口: {port}: {e}", "error")
        
        # 清理配置文件
        if os.path.exists(SINGBOX_CONFIG_PATH):
            try:
                os.remove(SINGBOX_CONFIG_PATH)
            except Exception as e:
                log_message(f"删除配置文件失败: {SINGBOX_CONFIG_PATH}: {e}", "error")
        
        cleanup_singbox_processes() # 确保彻底清理

async def run_singbox_test(node_url: str, session: aiohttp.ClientSession) -> tuple[bool, float]:
    """运行 sing-box 测试并进行重试"""
    for attempt in range(1, RETRY_ATTEMPTS + 1):
        port = get_free_port()
        if not port:
            log_message(f"尝试 {attempt}/{RETRY_ATTEMPTS} 测试节点 {node_url} 失败：无可用端口", "error")
            return False, 0
        
        log_message(f"尝试 {attempt}/{RETRY_ATTEMPTS} 测试节点: {node_url}, 端口: {port}")
        success, latency = await run_singbox_test_inner(node_url, session, port)
        if success:
            return success, latency
        await asyncio.sleep(1) # 每次重试间隔 1 秒
    return False, 0

async def test_node_connectivity(session: aiohttp.ClientSession, node_info: dict) -> tuple[dict, float]:
    """测试单个节点的连通性并返回结果"""
    node_url = node_info["url"]
    success, latency = await run_singbox_test(node_url, session)
    if success:
        return node_info, latency
    return None, 0

def load_failed_nodes():
    """加载历史失败的节点 URL 列表"""
    failed_nodes = set()
    if os.path.exists(FAILED_NODES_FILE):
        with open(FAILED_NODES_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            failed_nodes.update(line.strip() for line in f if line.strip())
    return failed_nodes

async def process_batch(session: aiohttp.ClientSession, nodes_batch: list) -> list:
    """处理一批节点，并发测试"""
    batch_start_time = time.time()
    successful_nodes = []
    failed_nodes_in_batch = [] # 记录当前批次中失败的节点 URL
    
    # 使用 asyncio.gather 而不是 as_completed 来保持原始顺序，或者更简单地直接迭代
    tasks = [test_node_connectivity(session, node) for node in nodes_batch]
    results = await asyncio.gather(*tasks, return_exceptions=True) # 捕获异常

    for i, res in enumerate(results):
        original_node_url = nodes_batch[i]["url"]
        if isinstance(res, Exception):
            log_message(f"测试节点 {original_node_url} 发生未捕获异常: {res}", "error")
            failed_nodes_in_batch.append(original_node_url)
        else:
            node_result, latency = res
            if node_result:
                node_result["latency"] = latency
                successful_nodes.append(node_result)
            else:
                failed_nodes_in_batch.append(original_node_url)
    
    # 将当前批次失败的节点写入文件
    if failed_nodes_in_batch:
        with open(FAILED_NODES_FILE, 'a', encoding='utf-8', errors='ignore') as f:
            for node_url in failed_nodes_in_batch:
                f.write(f"{node_url}\n")
    
    batch_time = time.time() - batch_start_time
    if batch_time > MAX_BATCH_TIME:
        log_message(f"批次处理耗时 {batch_time:.2f}秒，超过阈值 {MAX_BATCH_TIME}秒，可能存在卡住风险", "warning")
            
    return successful_nodes

async def main():
    """主函数：加载节点、测试并保存结果"""
    cleanup_singbox_processes() # 启动前先清理
    
    if not os.path.exists(SUB_FILE):
        log_message(f"错误：未找到输入文件 {SUB_FILE}", "error")
        exit(1)

    failed_nodes = load_failed_nodes()
    nodes_info = []
    seen_nodes = set() # 用于去重，防止重复测试
    
    with open(SUB_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        lines = f.readlines()
        if not lines or all(line.strip().startswith('#') or not line.strip() for line in lines):
            log_message(f"错误：{SUB_FILE} 为空或仅包含注释", "error")
            exit(1)
        
        for line in lines:
            line = line.strip()
            # 过滤掉注释行、空行和不符合协议前缀的行
            if line and not line.startswith('#') and re.match(r"^(hysteria2|vless|vmess|ss|trojan|ssr|socks5)://", line, re.IGNORECASE):
                if line in failed_nodes:
                    log_message(f"跳过历史失败节点: {line}", "info")
                    continue
                
                node_info = extract_node_info(line)
                if node_info:
                    # 使用一个更鲁棒的方式进行节点去重
                    # 考虑协议、主机、端口和路径（对 WS 等重要）
                    parsed = urlparse(node_info["url"])
                    # 对查询参数进行排序，确保一致性
                    sorted_query = urllib.parse.urlencode(sorted(parse_qs(parsed.query).items()), doseq=True)
                    # 组合成一个唯一的键
                    key = (parsed.scheme, parsed.netloc.split('@')[-1], parsed.path, sorted_query, node_info["tag"])
                    
                    if key not in seen_nodes:
                        seen_nodes.add(key)
                        nodes_info.append(node_info)
    
    log_message(f"读取到 {len(nodes_info)} 个节点（跳过 {len(failed_nodes)} 个历史失败节点）")

    successful_nodes = []
    # aiohttp.TCPConnector 的 limit 参数控制并发连接数
    connector = aiohttp.TCPConnector(limit=CONCURRENCY_LIMIT)
    
    async with aiohttp.ClientSession(connector=connector) as session:
        for i in range(0, len(nodes_info), BATCH_SIZE):
            batch = nodes_info[i:i + BATCH_SIZE]
            log_message(f"处理批次 {i//BATCH_SIZE + 1}/{len(nodes_info)//BATCH_SIZE + (1 if len(nodes_info) % BATCH_SIZE != 0 else 0)}，节点数: {len(batch)}")
            
            # 使用 asyncio.Semaphore 进一步控制并发，以避免同时启动过多 sing-box 进程
            # 虽然 TCPConnector 限制了 HTTP 请求并发，但 sing-box 进程启动仍是独立的
            semaphore = asyncio.Semaphore(CONCURRENCY_LIMIT) 
            
            # 创建带有信号量的任务
            batch_tasks = [
                asyncio.create_task(
                    semaphore.acquire() and await_release_semaphore(test_node_connectivity(session, node), semaphore)
                ) for node in batch
            ]
            batch_successful = []
            for task_future in tqdm(asyncio.as_completed(batch_tasks), total=len(batch_tasks), desc="测试节点"):
                try:
                    result_tuple = await task_future
                    if result_tuple[0]: # result_tuple 是 (node_info, latency)
                        batch_successful.append(result_tuple[0])
                except Exception as e:
                    log_message(f"批次测试任务中发生错误: {e}", "error")


            successful_nodes.extend(batch_successful)
            log_message(f"批次 {i//BATCH_SIZE + 1} 完成，当前成功节点数: {len(successful_nodes)}")
            await asyncio.sleep(1) # 每批次之间间隔 1 秒

    successful_nodes.sort(key=lambda x: x["latency"] if x.get("latency") is not None else float('inf'))
    
    with open(ALL_FILE, 'w', encoding='utf-8', errors='ignore') as f:
        for node in successful_nodes:
            url = node['url'].replace('\n', '') # 确保 URL 没有换行符
            f.write(f"{url}\n")
            log_message(
                f"可用节点: {url} | 国家: {node['country']} | 延迟: {node['latency']:.2f}ms"
                f"{' | 速度: ' + str(node['speed']) + 'MB/s' if node['speed'] else ''}"
                f"{' | 成功率: ' + str(node['success_rate']) + '%' if node['success_rate'] else ''}"
            )

    log_message(f"测试完成！共发现 {len(successful_nodes)} 个可用节点，保存到 {ALL_FILE}")

# 辅助函数用于信号量释放
async def await_release_semaphore(coro, semaphore):
    """一个辅助函数，用于在协程完成后释放信号量"""
    try:
        return await coro
    finally:
        semaphore.release()

if __name__ == "__main__":
    asyncio.run(main())
