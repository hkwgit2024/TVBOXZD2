import os
import re
import asyncio
import aiohttp
import json
import subprocess
import time
from urllib.parse import urlparse, parse_qs, unquote, unquote_plus
import base64

# 定义data目录和文件路径
DATA_DIR = "data"
SUB_FILE = os.path.join(DATA_DIR, "sub.txt")
ALL_FILE = os.path.join(DATA_DIR, "all.txt")

# 目标测试网站
TARGET_URL = "https://www.google.com" # 请替换为你想测试的网站，例如 "https://www.baidu.com"
TEST_TIMEOUT = 15 # 每个节点测试超时时间（秒）
SINGBOX_SOCKS5_PORT = 1080 # Singbox 本地 SOCKS5 代理端口
SINGBOX_HTTP_PORT = 1081 # Singbox 本地 HTTP 代理端口
SINGBOX_BIN_PATH = "/usr/local/bin/singbox" # Singbox 可执行文件路径，确保在 GitHub Actions 中正确安装

def base64_decode_if_needed(s):
    """尝试Base64解码字符串，如果失败则返回原字符串"""
    try:
        # URL-safe base64 decode first
        s_padded = s + '=' * (-len(s) % 4)
        return base64.urlsafe_b64decode(s_padded).decode('utf-8')
    except Exception:
        # Fallback to standard base64 if urlsafe fails
        try:
            return base64.b64decode(s).decode('utf-8')
        except Exception:
            return s

def generate_singbox_config(node_url: str, socks_port: int, http_port: int) -> dict:
    """
    根据节点 URL 生成 Singbox 的配置字典。
    这是一个尝试解析常见协议的函数，可能无法覆盖所有复杂情况。
    """
    parsed_url = urlparse(node_url)
    protocol = parsed_url.scheme
    netloc_parts = parsed_url.netloc.split('@', 1)
    
    user_info = None
    host_port = netloc_parts[-1]
    
    if len(netloc_parts) > 1:
        user_info = netloc_parts[0]

    host, port_str = (host_port.split(':') + [''])[:2]
    port = int(port_str) if port_str.isdigit() else (443 if protocol in ['hysteria2', 'trojan', 'vless', 'vmess'] else 80)
    
    query_params = parse_qs(parsed_url.query)
    fragment = unquote(parsed_url.fragment) if parsed_url.fragment else f"{protocol} node"
    
    # 基础入站配置
    inbounds = [
        {
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "listen_port": socks_port
        },
        {
            "type": "http",
            "tag": "http-in",
            "listen": "127.0.0.1",
            "listen_port": http_port
        }
    ]

    outbounds = []
    outbound_config = {
        "tag": "proxy",
        "type": protocol,
        "server": host,
        "server_port": port,
        # Default UUID/Password, will be overridden by protocol-specific logic
        "uuid": user_info if user_info else "", 
        "password": user_info if user_info else "", 
    }

    # TLS 设置
    tls_settings = {"enabled": False} # Default to disabled
    if parsed_url.scheme in ['vless', 'vmess', 'trojan', 'hysteria2']:
        if 'security' in query_params:
            if query_params['security'][0].lower() == 'tls':
                tls_settings['enabled'] = True
            elif query_params['security'][0].lower() == 'none':
                tls_settings['enabled'] = False
        else: # Assume TLS if protocol typically uses it and not explicitly 'none'
             tls_settings['enabled'] = True

        # Common TLS parameters
        if 'insecure' in query_params:
            tls_settings['insecure'] = query_params['insecure'][0] == '1'
        if 'sni' in query_params:
            tls_settings['server_name'] = query_params['sni'][0]
        elif 'host' in query_params and query_params['host'][0]: # For WebSocket host
             tls_settings['server_name'] = query_params['host'][0]
        else:
             tls_settings['server_name'] = host # Fallback to server host if no SNI provided
        
        # for vless/vmess reality/xudp
        if 'fp' in query_params:
            tls_settings['reality_fingerprint'] = query_params['fp'][0]
        if 'pbk' in query_params:
            tls_settings['reality_public_key'] = query_params['pbk'][0]
        if 'sid' in query_params:
            tls_settings['reality_short_id'] = query_params['sid'][0]

        if tls_settings['enabled']:
            outbound_config['tls'] = tls_settings
        else:
            outbound_config.pop('tls', None) # Remove TLS if not enabled

    # 针对不同协议的特定解析
    if protocol == "hysteria2":
        outbound_config["type"] = "hysteria2"
        outbound_config["password"] = user_info if user_info else ""
        if 'obfs' in query_params and query_params['obfs'][0] == 'salamander':
            outbound_config['obfs'] = 'salamander'
            if 'obfs-password' in query_params:
                outbound_config['obfs_password'] = query_params['obfs-password'][0]
        
        if 'up_mbps' in query_params:
            outbound_config['up_mbps'] = int(query_params['up_mbps'][0])
        if 'down_mbps' in query_params:
            outbound_config['down_mbps'] = int(query_params['down_mbps'][0])

    elif protocol == "vless":
        outbound_config["type"] = "vless"
        outbound_config["uuid"] = user_info if user_info else ""
        outbound_config.pop("password", None) # VLESS uses UUID

        # VLESS 传输协议
        transport = {}
        if 'type' in query_params:
            transport_type = query_params['type'][0]
            transport['type'] = transport_type
            if transport_type == 'ws':
                ws_settings = {}
                if 'path' in query_params:
                    ws_settings['path'] = unquote_plus(query_params['path'][0])
                if 'host' in query_params:
                    ws_settings['headers'] = {"Host": query_params['host'][0]}
                if ws_settings:
                    transport['websocket'] = ws_settings
            elif transport_type == 'grpc':
                grpc_settings = {}
                if 'serviceName' in query_params: # Singbox uses service_name
                    grpc_settings['service_name'] = query_params['serviceName'][0]
                if grpc_settings:
                    transport['grpc'] = grpc_settings
            # Other transports (h2, quic, tcp) can be extended here
        if transport:
            outbound_config['transport'] = transport

    elif protocol == "vmess":
        # VMESS 节点通常是 base64 编码的 JSON
        try:
            # Vmess url: vmess://base64(json)
            # The netloc_parts[0] should be the base64 encoded json.
            # However, the user's sub.txt example has uuid@host:port, so we need to be careful.
            # Assuming the full part after vmess:// is base64 encoded.
            vmess_raw = node_url[len("vmess://"):]
            decoded_json = base64_decode_if_needed(vmess_raw)
            vmess_data = json.loads(decoded_json)

            outbound_config["type"] = "vmess"
            outbound_config["server"] = vmess_data.get('add', host)
            outbound_config["server_port"] = int(vmess_data.get('port', port))
            outbound_config["uuid"] = vmess_data.get('id', '')
            outbound_config["alter_id"] = int(vmess_data.get('aid', 0))
            outbound_config["security"] = vmess_data.get('scy', 'auto') 
            outbound_config.pop("password", None) # VMess uses UUID

            # VMESS 传输协议
            transport = {}
            transport_type = vmess_data.get('net', 'tcp')
            transport['type'] = transport_type
            
            if transport_type == 'ws':
                ws_settings = {}
                if 'path' in vmess_data:
                    ws_settings['path'] = vmess_data['path']
                if 'host' in vmess_data: # host in vmess json is HTTP Host header
                    ws_settings['headers'] = {"Host": vmess_data['host']}
                if ws_settings:
                    transport['websocket'] = ws_settings
            elif transport_type == 'grpc':
                grpc_settings = {}
                if 'serviceName' in vmess_data:
                    grpc_settings['service_name'] = vmess_data['serviceName']
                if grpc_settings:
                    transport['grpc'] = grpc_settings
            # Other transports (h2, quic, tcp, kcp) can be extended here

            if transport:
                outbound_config['transport'] = transport

            # VMESS TLS
            if vmess_data.get('tls') == 'tls':
                tls_settings_vmess = {
                    "enabled": True,
                    "server_name": vmess_data.get('host', host) or host, # SNI for vmess is 'host' in json
                    "insecure": vmess_data.get('skip-cert-verify', False)
                }
                outbound_config['tls'] = tls_settings_vmess
            else:
                outbound_config.pop('tls', None)


        except Exception as e:
            print(f"Warning: Failed to parse VMESS node {node_url}: {e}")
            return None # 无法解析，返回 None

    elif protocol == "trojan":
        outbound_config["type"] = "trojan"
        outbound_config["password"] = user_info if user_info else ""
        outbound_config.pop("uuid", None) # Trojan uses password

    elif protocol == "ss":
        outbound_config["type"] = "shadowsocks"
        # ss://method:password@server:port#tag
        ss_user_info = user_info if user_info else ""
        if ':' in ss_user_info:
            method, password = ss_user_info.split(':', 1)
            outbound_config["method"] = method
            outbound_config["password"] = password
        outbound_config.pop("uuid", None) # SS uses password and method
        outbound_config.pop("tls", None) # SS doesn't have native TLS

    elif protocol == "ssr":
        # SSR 格式复杂，通常是 base64 编码，这里只提供一个基本框架
        # SSR URL: ssr://base64_encoded_params
        # decoded_params format: server:port:protocol:method:obfs:password_base64/?params
        try:
            ssr_raw = node_url[len("ssr://"):]
            decoded_ssr_info = base64_decode_if_needed(ssr_raw)

            # Remove fragment if present
            if '#' in decoded_ssr_info:
                decoded_ssr_info = decoded_ssr_info.split('#')[0]

            ssr_parts = decoded_ssr_info.split(':')
            if len(ssr_parts) >= 6:
                outbound_config["type"] = "shadowsocksr"
                outbound_config["server"] = ssr_parts[0]
                outbound_config["server_port"] = int(ssr_parts[1])
                outbound_config["protocol"] = ssr_parts[2]
                outbound_config["method"] = ssr_parts[3]
                outbound_config["obfs"] = ssr_parts[4]
                outbound_config["password"] = base64_decode_if_needed(ssr_parts[5])

                # Parse params (optional)
                if '?' in decoded_ssr_info:
                    params_str = decoded_ssr_info.split('?', 1)[1]
                    ssr_query = parse_qs(params_str)
                    if 'obfsparam' in ssr_query:
                        outbound_config['obfs_param'] = base64_decode_if_needed(ssr_query['obfsparam'][0])
                    if 'protoparam' in ssr_query:
                        outbound_config['protocol_param'] = base64_decode_if_needed(ssr_query['protoparam'][0])
                
                outbound_config.pop("uuid", None) # SSR doesn't use UUID
                outbound_config.pop("tls", None) # SSR doesn't have native TLS
            else:
                print(f"Warning: Could not parse SSR node {node_url} due to incorrect format.")
                return None
        except Exception as e:
            print(f"Warning: Failed to parse SSR node {node_url}: {e}")
            return None
        
    else:
        print(f"警告：不支持的协议类型 {protocol}，跳过此节点: {node_url}")
        return None

    # Add direct outbound for routing
    outbounds.append(outbound_config)
    outbounds.append({"tag": "direct", "type": "direct"}) 

    # Main config structure
    singbox_full_config = {
        "log": {
            "level": "info"
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "rule_set": [], # Can add more rules if needed
            "default_outbound": "proxy" # Default traffic to the 'proxy' outbound
        }
    }
    
    return singbox_full_config

async def run_singbox_test(node_url: str, session: aiohttp.ClientSession) -> bool:
    """
    通过 subprocess 调用 Singbox 进行节点测试。
    """
    # 增加一个小的延迟，以缓解资源释放问题
    await asyncio.sleep(0.1) # 100ms 延迟

    print(f"尝试通过 Singbox 测试节点: {node_url}")
    
    config_data = generate_singbox_config(node_url, SINGBOX_SOCKS5_PORT, SINGBOX_HTTP_PORT)
    if config_data is None:
        print(f"无法为节点 {node_url} 生成 Singbox 配置。")
        return False

    config_file_path = f"/tmp/singbox_config_{os.getpid()}.json"
    singbox_process = None
    try:
        print(f"DEBUG: 正在生成并保存 Singbox 配置到 {config_file_path}") # <-- 新增
        with open(config_file_path, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2)
        print("DEBUG: Singbox 配置保存成功。") # <-- 新增

        command = [SINGBOX_BIN_PATH, "run", "-c", config_file_path]
        print(f"DEBUG: 尝试执行命令: {' '.join(command)}") # <-- 新增
        
        try:
            singbox_process = subprocess.Popen(
                command, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True 
            )
            print(f"DEBUG: Singbox 进程成功启动，PID: {singbox_process.pid}. 等待 2 秒...") # <-- 新增
            await asyncio.sleep(2) 

            # 检查 Singbox 是否成功启动 (简单检查，更健壮的方式是监听其日志或API)
            # 尝试读取一些输出，确保进程没有立即崩溃
            stdout_peek = ""
            stderr_peek = ""
            if singbox_process.stdout:
                try:
                    stdout_peek = singbox_process.stdout.peek(1024).decode('utf-8') # Peek up to 1KB
                except ValueError: # handle empty buffer
                    pass
            if singbox_process.stderr:
                try:
                    stderr_peek = singbox_process.stderr.peek(1024).decode('utf-8')
                except ValueError:
                    pass

            if "error" in stdout_peek.lower() or "error" in stderr_peek.lower():
                print(f"DEBUG: Singbox 启动时检测到错误日志。Stdout: {stdout_peek[:200]} Stderr: {stderr_peek[:200]}")
                # Try to get full output before returning False
                stdout, stderr = singbox_process.communicate(timeout=5)
                print(f"DEBUG: Singbox Full Stdout:\n{stdout}\nDEBUG: Singbox Full Stderr:\n{stderr}")
                return False

            poll_result = singbox_process.poll()
            if poll_result is not None:
                stdout, stderr = singbox_process.communicate()
                print(f"DEBUG: Singbox 进程启动失败，退出码: {poll_result}")
                print(f"DEBUG: Stdout:\n{stdout}\nDEBUG: Stderr:\n{stderr}")
                return False

        except OSError as e:
            print(f"DEBUG: 捕获到 OSError: {e}") # <-- 新增
            if e.errno == 11: # Resource temporarily unavailable
                print(f"ERROR: 启动 Singbox 进程时资源暂时不可用: {e}. 请考虑降低并发或检查系统资源限制。")
            else:
                print(f"ERROR: 启动 Singbox 进程时发生操作系统错误: {e}")
            return False
        except Exception as e:
            print(f"DEBUG: 捕获到一般异常: {e}") # <-- 新增
            print(f"ERROR: 启动 Singbox 进程时发生未知错误: {e}")
            return False

        print(f"DEBUG: Singbox 进程已启动，尝试通过代理访问 {TARGET_URL}...") # <-- 新增
        try:
            proxies = {
                "http": f"http://127.0.0.1:{SINGBOX_HTTP_PORT}",
                "https": f"http://127.0.0.1:{SINGBOX_HTTP_PORT}"
            }
            async with session.get(TARGET_URL, proxy=proxies["https"], timeout=TEST_TIMEOUT) as response:
                if response.status == 200:
                    print(f"DEBUG: HTTP 请求成功，状态码 200。") # <-- 新增
                    print(f"通过 Singbox 访问 {TARGET_URL} 成功。")
                    return True
                else:
                    print(f"DEBUG: HTTP 请求失败，状态码 {response.status}。") # <-- 新增
                    print(f"通过 Singbox 访问 {TARGET_URL} 失败，HTTP 状态码: {response.status}")
                    return False
        except asyncio.TimeoutError:
            print(f"DEBUG: HTTP 请求超时。") # <-- 新增
            print(f"通过 Singbox 访问 {TARGET_URL} 超时。")
            return False
        except aiohttp.ClientError as e:
            print(f"DEBUG: 发生客户端错误: {e}") # <-- 新增
            print(f"通过 Singbox 访问 {TARGET_URL} 发生客户端错误: {e}")
            return False
        except Exception as e:
            print(f"DEBUG: 通过 Singbox 代理访问时发生未知错误: {e}") # <-- 新增
            print(f"通过 Singbox 代理访问时发生未知错误: {e}")
            return False

    except FileNotFoundError:
        print(f"ERROR: '{SINGBOX_BIN_PATH}' 命令未找到。请确保 Singbox 已正确安装并添加到 PATH。") # <-- 统一错误格式
        return False
    except Exception as e:
        print(f"ERROR: 执行 Singbox 测试时发生未知错误（配置或进程管理阶段）: {e}") # <-- 统一错误格式
        return False
    finally:
        print(f"DEBUG: 进入 finally 块，清理 Singbox 进程和配置文件。") # <-- 新增
        if singbox_process and singbox_process.poll() is None: # 确保进程还在运行
            print(f"DEBUG: 正在终止 Singbox 进程 PID: {singbox_process.pid}...") # <-- 新增
            singbox_process.terminate()
            try:
                # 给进程一点时间来清理资源
                singbox_process.wait(timeout=5) 
            except subprocess.TimeoutExpired:
                print(f"DEBUG: 强制杀死 Singbox 进程 PID: {singbox_process.pid}...") # <-- 新增
                singbox_process.kill()
        else:
            print("DEBUG: Singbox 进程未运行或已终止。") # <-- 新增
        
        # 确保管道被关闭，避免僵尸进程或资源泄露
        if singbox_process:
            if singbox_process.stdout:
                singbox_process.stdout.close()
            if singbox_process.stderr:
                singbox_process.stderr.close()

        if os.path.exists(config_file_path):
            os.remove(config_file_path)
            print(f"DEBUG: 已删除临时配置文件: {config_file_path}") # <-- 新增

async def test_node_connectivity(session, node_url):
    """
    测试单个节点的连通性。
    """
    print(f"--> 开始测试节点: {node_url}")
    is_successful = await run_singbox_test(node_url, session)
    
    if is_successful:
        print(f"<-- 节点连通成功: {node_url}")
        return node_url
    else:
        print(f"<-- 节点连通失败: {node_url}")
        return None

async def main():
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR)

    nodes = []
    try:
        with open(SUB_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                # 过滤掉注释行和空行，只保留节点链接
                if line and not line.startswith('#') and re.match(r"^(hysteria2|vless|vmess|ss|trojan|ssr)://", line, re.IGNORECASE):
                    nodes.append(line)
    except FileNotFoundError:
        print(f"错误：文件 {SUB_FILE} 未找到。请确保文件存在。")
        return

    if not nodes:
        print("未从 sub.txt 中读取到任何有效节点。")
        return

    print(f"共读取到 {len(nodes)} 个节点，开始并行测试...")

    successful_nodes = []
    
    # 异步并发执行，控制并发数。
    # 对于 10W+ 节点，一次性全部并发可能导致资源耗尽或被封禁。
    # 建议采取分批处理或分布式测试策略。
    # GitHub Actions 免费层级可能限制并发连接数，此值需要根据实际运行情况反复测试和调整。
    # 从更保守的数字开始，例如 5 或 10，如果稳定再逐渐增加。
    concurrency_limit = 10 

    # 使用 aiohttp.TCPConnector 限制并发连接数
    connector = aiohttp.TCPConnector(limit=concurrency_limit, force_close=True) 
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [test_node_connectivity(session, node) for node in nodes]
        
        # 使用 asyncio.as_completed 以便在任务完成时处理结果，而不是等待所有任务完成
        for i, task_future in enumerate(asyncio.as_completed(tasks)):
            try:
                result = await task_future
                if result:
                    successful_nodes.append(result)
            except Exception as e:
                print(f"WARNING: 任务处理过程中发生未捕获异常: {e}") # 捕获任务内部的未处理异常
            
            # 每处理一定数量的节点打印进度
            if (i + 1) % 50 == 0 or (i + 1) == len(nodes):
                print(f"已处理 {i + 1} / {len(nodes)} 个节点，当前成功节点数: {len(successful_nodes)}")

    print(f"\n测试完成。成功节点数量: {len(successful_nodes)}")

    with open(ALL_FILE, 'w', encoding='utf-8') as f:
        # 确保目录存在
        os.makedirs(DATA_DIR, exist_ok=True)
        # 获取当前时间（在 GitHub Actions 上可能不是本地时区）
        current_time = time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime())
        f.write(f"# Successful Nodes ({current_time})\n")
        f.write("-------------------------------------\n")
        for node in successful_nodes:
            f.write(node + "\n")

    print(f"成功节点已保存到 {ALL_FILE}")

if __name__ == "__main__":
    asyncio.run(main())
