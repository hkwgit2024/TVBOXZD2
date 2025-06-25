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
        "uuid": user_info if user_info else "", # 用于 vmess, vless, hysteria2 (password)
        "password": user_info if user_info else "", # 用于 trojan, ss, ssr, hysteria2 (password)
    }

    # TLS 设置
    tls_settings = {}
    if parsed_url.scheme in ['vless', 'vmess', 'trojan', 'hysteria2']:
        tls_enabled = '0' not in query_params.get('tls', ['1']) and '1' in query_params.get('tls', ['1'])
        if 'insecure' in query_params:
            tls_settings['reality_fingerprint'] = query_params.get('fp', [''])[0]
            tls_settings['insecure'] = query_params['insecure'][0] == '1'
        if 'sni' in query_params:
            tls_settings['server_name'] = query_params['sni'][0]
        elif 'host' in query_params: # for ws host
             tls_settings['server_name'] = query_params['host'][0]
        else:
             tls_settings['server_name'] = host # Default to server name if no sni
        
        if tls_settings.get('server_name') and tls_settings.get('server_name').lower().endswith(".cdn.cloudflare.net"):
             # Cloudflare SNI issue, often needs specific config for Singbox
             pass # For simplicity, we ignore it here
        
        if tls_settings:
            outbound_config['tls'] = tls_settings

    # 针对不同协议的特定解析
    if protocol == "hysteria2":
        outbound_config["type"] = "hysteria2"
        outbound_config["password"] = user_info if user_info else ""
        if 'obfs' in query_params and query_params['obfs'][0] == 'salamander':
            outbound_config['obfs'] = 'salamander'
            if 'obfs-password' in query_params:
                outbound_config['obfs_password'] = query_params['obfs-password'][0]
        
        # Hysteria2 流量控制
        if 'up_mbps' in query_params:
            outbound_config['up_mbps'] = int(query_params['up_mbps'][0])
        if 'down_mbps' in query_params:
            outbound_config['down_mbps'] = int(query_params['down_mbps'][0])

    elif protocol == "vless":
        outbound_config["type"] = "vless"
        outbound_config["uuid"] = user_info if user_info else ""
        outbound_config.pop("password", None) # VLESS用UUID
        
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
            # 其他传输协议 (grpc, h2, tcp) 可以在这里扩展
        if transport:
            outbound_config['transport'] = transport

    elif protocol == "vmess":
        # VMESS 节点通常是 base64 编码的 JSON
        try:
            decoded_json = base64_decode_if_needed(host) # host 部分通常是 base64 编码
            vmess_data = json.loads(decoded_json)
            outbound_config["type"] = "vmess"
            outbound_config["server"] = vmess_data.get('add', host)
            outbound_config["server_port"] = int(vmess_data.get('port', port))
            outbound_config["uuid"] = vmess_data.get('id', '')
            outbound_config["alter_id"] = int(vmess_data.get('aid', 0))
            outbound_config["security"] = vmess_data.get('scy', 'auto') # auto, aes-128-gcm, chacha20-poly1305 etc.

            # VMESS 传输协议
            transport = {}
            transport_type = vmess_data.get('net', 'tcp')
            transport['type'] = transport_type
            
            if transport_type == 'ws':
                ws_settings = {}
                if 'path' in vmess_data:
                    ws_settings['path'] = vmess_data['path']
                if 'host' in vmess_data:
                    ws_settings['headers'] = {"Host": vmess_data['host']}
                if ws_settings:
                    transport['websocket'] = ws_settings
            # 其他传输协议 (grpc, h2, quic, tcp, kcp) 可以在这里扩展

            if transport:
                outbound_config['transport'] = transport

            # VMESS TLS
            if vmess_data.get('tls') == 'tls':
                tls_settings = {
                    "enabled": True,
                    "server_name": vmess_data.get('host', host) or host,
                    "insecure": vmess_data.get('skip-cert-verify', False)
                }
                outbound_config['tls'] = tls_settings

        except Exception as e:
            print(f"Warning: Failed to parse VMESS node {node_url}: {e}")
            return None # 无法解析，返回 None

    elif protocol == "trojan":
        outbound_config["type"] = "trojan"
        outbound_config["password"] = user_info if user_info else ""
        # Trojan 通常默认 TLS，所以在这里不额外设置 tls: true
        # TLS 设置已在上方通用部分处理

    elif protocol == "ss":
        outbound_config["type"] = "shadowsocks"
        # ss://method:password@server:port#tag
        ss_user_info = user_info if user_info else ""
        if ':' in ss_user_info:
            method, password = ss_user_info.split(':', 1)
            outbound_config["method"] = method
            outbound_config["password"] = password
        outbound_config.pop("uuid", None) # SS 用 password 和 method

    elif protocol == "ssr":
        # SSR 格式复杂，通常是 base64 编码，这里只提供一个基本框架
        try:
            # 尝试解码 SSR 链接，格式为 ssr://base64(server:port:protocol:method:obfs:password_base64/?params_base64)
            # 这部分解析可能需要一个专门的 SSR 解析库
            decoded_ssr_info = base64_decode_if_needed(host) # 通常是 host 字段被编码
            if not decoded_ssr_info.startswith(host): # 简单的验证
                 print(f"Warning: SSR node {node_url} is not a standard base64 encoded format. Attempting direct parse.")
                 decoded_ssr_info = node_url.replace("ssr://", "")
                 if "#" in decoded_ssr_info:
                     decoded_ssr_info = decoded_ssr_info.split("#")[0] # remove fragment
                     
            ssr_parts = decoded_ssr_info.split(':')
            if len(ssr_parts) >= 6:
                outbound_config["type"] = "shadowsocksr"
                outbound_config["server"] = ssr_parts[0]
                outbound_config["server_port"] = int(ssr_parts[1])
                outbound_config["protocol"] = ssr_parts[2]
                outbound_config["method"] = ssr_parts[3]
                outbound_config["obfs"] = ssr_parts[4]
                outbound_config["password"] = base64_decode_if_needed(ssr_parts[5])

                # 解析 params
                if '?' in decoded_ssr_info:
                    params_str = decoded_ssr_info.split('?', 1)[1]
                    ssr_query = parse_qs(params_str)
                    if 'obfsparam' in ssr_query:
                        outbound_config['obfs_param'] = base64_decode_if_needed(ssr_query['obfsparam'][0])
                    if 'protoparam' in ssr_query:
                        outbound_config['protocol_param'] = base64_decode_if_needed(ssr_query['protoparam'][0])
                
                # SSR 没有原生 TLS 支持，一般通过 obfs 或额外代理层
                outbound_config.pop("tls", None) # Remove TLS for SSR
            else:
                print(f"Warning: Could not parse SSR node {node_url} due to incorrect format.")
                return None
        except Exception as e:
            print(f"Warning: Failed to parse SSR node {node_url}: {e}")
            return None
        
    else:
        print(f"警告：不支持的协议类型 {protocol}，跳过此节点: {node_url}")
        return None

    outbounds.append(outbound_config)
    outbounds.append({"tag": "direct", "type": "direct"}) # 添加 direct 出站

    # 主配置结构
    singbox_full_config = {
        "log": {
            "level": "info"
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "rule_set": [], # 可以添加更多规则
            "default_outbound": "proxy" # 默认流量走 proxy
        }
    }
    
    return singbox_full_config

async def run_singbox_test(node_url: str, session: aiohttp.ClientSession) -> bool:
    """
    通过 subprocess 调用 Singbox 进行节点测试。
    """
    print(f"尝试通过 Singbox 测试节点: {node_url}")
    
    # 1. 动态生成 Singbox 配置
    config_data = generate_singbox_config(node_url, SINGBOX_SOCKS5_PORT, SINGBOX_HTTP_PORT)
    if config_data is None:
        print(f"无法为节点 {node_url} 生成 Singbox 配置。")
        return False

    config_file_path = f"/tmp/singbox_config_{os.getpid()}.json"
    try:
        with open(config_file_path, "w", encoding="utf-8") as f:
            json.dump(config_data, f, indent=2)
        # print(f"临时 Singbox 配置已保存到: {config_file_path}")

        # 2. 启动 Singbox 进程
        command = [SINGBOX_BIN_PATH, "run", "-c", config_file_path]
        singbox_process = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True # 创建新会话，避免子进程继承父进程的信号
        )
        print(f"Singbox 进程启动中 (PID: {singbox_process.pid})...")
        await asyncio.sleep(2) # 等待 Singbox 启动

        # 检查 Singbox 是否成功启动 (简单检查，更健壮的方式是监听其日志或API)
        poll_result = singbox_process.poll()
        if poll_result is not None:
            stdout, stderr = singbox_process.communicate()
            print(f"Singbox 进程启动失败，退出码: {poll_result}")
            print(f"Stdout:\n{stdout}\nStderr:\n{stderr}")
            return False

        # 3. 通过 Singbox 代理访问目标网站
        proxies = {
            "http": f"http://127.0.0.1:{SINGBOX_HTTP_PORT}",
            "https": f"http://127.0.0.1:{SINGBOX_HTTP_PORT}"
        }
        
        try:
            async with session.get(TARGET_URL, proxy=proxies["https"], timeout=TEST_TIMEOUT) as response:
                if response.status == 200:
                    print(f"通过 Singbox 访问 {TARGET_URL} 成功。")
                    return True
                else:
                    print(f"通过 Singbox 访问 {TARGET_URL} 失败，HTTP 状态码: {response.status}")
                    return False
        except asyncio.TimeoutError:
            print(f"通过 Singbox 访问 {TARGET_URL} 超时。")
            return False
        except aiohttp.ClientError as e:
            print(f"通过 Singbox 访问 {TARGET_URL} 发生客户端错误: {e}")
            return False

    except FileNotFoundError:
        print(f"错误：'{SINGBOX_BIN_PATH}' 命令未找到。请确保 Singbox 已正确安装并添加到 PATH。")
        return False
    except Exception as e:
        print(f"执行 Singbox 测试时发生未知错误: {e}")
        return False
    finally:
        # 4. 停止 Singbox 进程并清理
        if singbox_process and singbox_process.poll() is None: # 确保进程还在运行
            print(f"终止 Singbox 进程 (PID: {singbox_process.pid})...")
            singbox_process.terminate()
            try:
                # 给进程一点时间来清理资源
                singbox_process.wait(timeout=5) 
            except subprocess.TimeoutExpired:
                print(f"强制杀死 Singbox 进程 (PID: {singbox_process.pid})...")
                singbox_process.kill()
        if os.path.exists(config_file_path):
            os.remove(config_file_path)
            # print(f"已删除临时配置文件: {config_file_path}")

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
                # 扩展匹配更多协议
                if line and not line.startswith('#') and re.match(r"^(hysteria2|vless|vmess|ss|trojan|ssr)://", line):
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
    # GitHub Actions 免费层级可能限制并发连接数，谨慎调整此值。
    concurrency_limit = 20 # 建议从一个较小的值开始测试，例如 10-50

    # 使用 aiohttp.TCPConnector 限制并发连接数
    connector = aiohttp.TCPConnector(limit=concurrency_limit, force_close=True) 
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [test_node_connectivity(session, node) for node in nodes]
        
        # 使用 asyncio.as_completed 以便在任务完成时处理结果，而不是等待所有任务完成
        for i, task in enumerate(asyncio.as_completed(tasks)):
            result = await task
            if result:
                successful_nodes.append(result)
            
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
