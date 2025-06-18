import requests
import yaml
import base64
import time
import subprocess
import os
import re
import json
from urllib.parse import urlparse, parse_qs

# --- Configuration ---
# 节点的来源列表。每个来源可以指定 'url' 和 'format'。
# 'format' 可以是:
# - 'auto': 尝试 Base64 解码，然后尝试 YAML 解析，否则视为纯文本链接。
# - 'base64-links': 强制 Base64 解码，然后解析为多行链接。
# - 'plain-links': 直接解析为多行链接。
# - 'clash-yaml': 强制解析为 Clash YAML 格式，并提取 'proxies' 列表。
NODES_SOURCES = [
    {
        "url": "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt",
        "format": "auto"
    },
    # 您可以根据需要添加更多节点来源，例如：
    # {
    #       "url": "http://example.com/your_base64_encoded_subscription.txt",
    #       "format": "base64-links"
    # },
    {
        "url": "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/data/clash.yaml",
        "format": "clash-yaml"
    }
]

CLASH_CORE_VERSION = "v1.19.10" # Mihomo 版本
CLASH_DOWNLOAD_URL = f"https://github.com/MetaCubeX/mihomo/releases/download/{CLASH_CORE_VERSION}/mihomo-linux-amd64-{CLASH_CORE_VERSION}.gz"
CLASH_BIN_PATH = "clash_bin/mihomo"
CLASH_CONFIG_PATH = "clash_config.yaml"
COLLECT_SUB_PATH = "data/collectSub.txt"
CLASH_LOG_PATH = "clash_bin/clash_debug.log" # Clash core will log here

CLASH_API_URL = "http://127.0.0.1:9090"
CLASH_PROXY_URL = "http://127.0.0.1:7890"

SPEED_TEST_URL = "http://ipv4.download.thinkbroadband.com/5MB.zip" # 用于测速的文件
SPEED_TEST_TIMEOUT = 30 # 单个节点测速超时时间

# --- Helper Functions for Format Detection ---

def is_base64(s):
    """简单的Base64字符串启发式检测"""
    if not isinstance(s, str) or not s.strip():
        return False
    # 尝试解码并检查是否是有效的UTF-8
    try:
        decoded_bytes = base64.b64decode(s.strip(), validate=True)
        # 进一步检查解码内容是否看起来像文本，避免二进制数据误判
        # 这里的判断可能会过于严格，实际中更常见的是直接尝试解码，如果无异常就认为是Base64
        # 但为了避免二进制数据的误判，这里添加了尝试解码为UTF-8的逻辑
        # 如果解码为UTF-8失败，可能它仍然是有效的Base64编码，只是内容不是文本
        # 根据实际需要调整这里的严格程度
        return decoded_bytes.decode('utf-8') is not None
    except Exception:
        return False

def is_yaml(s):
    """尝试判断字符串是否是YAML格式"""
    if not isinstance(s, str) or not s.strip():
        return False
    try:
        data = yaml.safe_load(s)
        return isinstance(data, dict) or isinstance(data, list)
    except yaml.YAMLError:
        return False
    except Exception: # 捕获其他可能的异常，例如解析器内部错误
        return False

# --- Core Functions ---

def setup_clash_core():
    """下载并解压 Clash Core"""
    os.makedirs("clash_bin", exist_ok=True) # 确保 clash_bin 目录存在
    if not os.path.exists(CLASH_BIN_PATH):
        print(f"Downloading Clash core from {CLASH_DOWNLOAD_URL}...")
        try:
            response = requests.get(CLASH_DOWNLOAD_URL, stream=True, timeout=300)
            response.raise_for_status()
            with open(CLASH_BIN_PATH + ".gz", 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print("Decompressing Clash core...")
            subprocess.run(["gunzip", CLASH_BIN_PATH + ".gz"], check=True)
            subprocess.run(["chmod", "+x", CLASH_BIN_PATH], check=True)
            print("Clash core setup complete.")
        except Exception as e:
            print(f"Error setting up Clash core: {e}")
            exit(1)
    else:
        print("Clash core already exists. Skipping download.")

def parse_link(link, i):
    """解析各种代理链接并转换为 Clash 配置字典"""
    link = link.strip()
    if not link:
        return None

    try:
        if link.startswith("ss://"):
            # SS 链接格式: ss://method:password@server:port#name
            # 或者 ss://base64_encoded_userinfo@server:port#name
            parts = link[5:].split('@')
            if len(parts) != 2:
                raise ValueError("Invalid SS link format (missing @)")

            user_info_encoded = parts[0]
            try:
                # 尝试 Base64 解码 userinfo 部分，处理可能存在的填充
                user_info_decoded = base64.b64decode(user_info_encoded + '==').decode('utf-8')
                method, password = user_info_decoded.split(':', 1)
            except Exception:
                # 如果解码失败，假定 userinfo 未编码
                method, password = user_info_encoded.split(':', 1)
            
            server_port_name = parts[1]
            server_port_parts = server_port_name.split('#', 1)
            server_port = server_port_parts[0]
            name = server_port_parts[1] if len(server_port_parts) > 1 else f"SS-Proxy-{i}"

            server, port_str = server_port.rsplit(':', 1)
            port = int(port_str)

            return {
                "name": name,
                "type": "ss",
                "server": server,
                "port": port,
                "cipher": method,
                "password": password
            }

        elif link.startswith("vmess://"):
            # VMESS 链接是 Base64 编码的 JSON
            encoded_data = link[8:]
            # 兼容处理 Base64 填充
            missing_padding = len(encoded_data) % 4
            if missing_padding != 0:
                encoded_data += '=' * (4 - missing_padding)
            
            decoded_data = base64.b64decode(encoded_data).decode('utf-8')
            vmess_data = json.loads(decoded_data)

            name = (vmess_data.get('ps') if vmess_data.get('ps') else f"VMESS-Proxy-{i}").strip()
            server = vmess_data.get('add')
            port = int(vmess_data.get('port'))
            uuid = vmess_data.get('id')
            alterId = int(vmess_data.get('aid', 0))
            cipher = vmess_data.get('scy', 'auto') # Clash uses 'cipher' for security type

            proxy_dict = {
                "name": name,
                "type": "vmess",
                "server": server,
                "port": port,
                "uuid": uuid,
                "alterId": alterId,
                "cipher": cipher
            }

            # 处理网络传输协议
            network = vmess_data.get('net', 'tcp')
            proxy_dict['network'] = network

            if network == 'ws':
                ws_opts = {}
                if 'path' in vmess_data:
                    ws_opts['path'] = vmess_data['path']
                if 'host' in vmess_data: # Host header
                    ws_opts['headers'] = {'Host': vmess_data['host']}
                if ws_opts:
                    proxy_dict['ws-opts'] = ws_opts
            elif network == 'grpc':
                grpc_opts = {}
                if 'serviceName' in vmess_data:
                    grpc_opts['service-name'] = vmess_data['serviceName']
                if grpc_opts:
                    proxy_dict['grpc-opts'] = grpc_opts
            elif network == 'h2': # http/2
                h2_opts = {}
                if 'path' in vmess_data:
                    h2_opts['path'] = vmess_data['path']
                if h2_opts:
                    proxy_dict['h2-opts'] = h2_opts

            # TLS 选项
            if vmess_data.get('tls', '0') == 'tls':
                proxy_dict['tls'] = True
                if 'host' in vmess_data: # VMESS的host字段通常用作SNI
                    proxy_dict['servername'] = vmess_data['host']
                if vmess_data.get('allowInsecure', '0') == '1': # insecure/跳过证书验证
                    proxy_dict['skip-cert-verify'] = True
                if 'alpn' in vmess_data and vmess_data['alpn']:
                    proxy_dict['alpn'] = [s.strip() for s in vmess_data['alpn'].split(',')]

            # 旧版混淆 obfs
            if vmess_data.get('type') == 'http': # HTTP 混淆
                proxy_dict['network'] = 'http'
            elif vmess_data.get('obfs') == 'websocket': # 旧版 WS 混淆
                proxy_dict['network'] = 'ws'
                ws_opts = proxy_dict.get('ws-opts', {})
                if 'obfs-host' in vmess_data:
                    ws_opts['headers'] = {'Host': vmess_data['obfs-host']}
                proxy_dict['ws-opts'] = ws_opts

            return proxy_dict

        elif link.startswith("vless://"):
            parsed_url = urlparse(link)
            userinfo_part = parsed_url.netloc # uuid@server:port
            uuid = userinfo_part.split('@')[0]
            server_port = userinfo_part.split('@')[1]
            server = server_port.split(':')[0]
            port = int(server_port.split(':')[1])

            params = parse_qs(parsed_url.query)
            name = (parsed_url.fragment if parsed_url.fragment else f"VLESS-Proxy-{i}").strip()

            proxy_dict = {
                "name": name,
                "type": "vless",
                "server": server,
                "port": port,
                "uuid": uuid,
            }

            # 处理查询参数
            if 'tls' in params:
                proxy_dict['tls'] = params['tls'][0].lower() == 'true'
            if 'flow' in params:
                proxy_dict['flow'] = params['flow'][0]
            if 'sni' in params: # servername for SNI
                proxy_dict['servername'] = params['sni'][0]
            if 'alpn' in params and params['alpn'][0]:
                proxy_dict['alpn'] = [s.strip() for s in params['alpn'][0].split(',')]
            if 'skip-cert-verify' in params:
                proxy_dict['skip-cert-verify'] = params['skip-cert-verify'][0].lower() == 'true'

            network = params.get('type', ['tcp'])[0] # VLESS type in query means network type
            proxy_dict['network'] = network

            if network == 'ws':
                ws_opts = {}
                if 'path' in params:
                    ws_opts['path'] = params['path'][0]
                if 'host' in params: # host in query is for Host header in ws-opts
                    ws_opts['headers'] = {'Host': params['host'][0]}
                if ws_opts:
                    proxy_dict['ws-opts'] = ws_opts
            elif network == 'grpc':
                grpc_opts = {}
                if 'serviceName' in params:
                    grpc_opts['service-name'] = params['serviceName'][0]
                if grpc_opts:
                    proxy_dict['grpc-opts'] = grpc_opts
            elif network == 'h2': # http/2
                h2_opts = {}
                if 'path' in params:
                    h2_opts['path'] = params['path'][0]
                if h2_opts:
                    proxy_dict['h2-opts'] = h2_opts

            return proxy_dict

        elif link.startswith("trojan://"):
            # Trojan 链接格式: trojan://password@server:port#name
            # 或 trojan://password@server:port?params#name
            parsed_url = urlparse(link)
            userinfo_part = parsed_url.netloc # password@server:port
            password = userinfo_part.split('@')[0]
            server_port = userinfo_part.split('@')[1]
            server = server_port.split(':')[0]
            port = int(server_port.split(':')[1])

            params = parse_qs(parsed_url.query)
            name = (parsed_url.fragment if parsed_url.fragment else f"Trojan-Proxy-{i}").strip()

            proxy_dict = {
                "name": name,
                "type": "trojan",
                "server": server,
                "port": port,
                "password": password,
                "tls": True # Trojan 默认开启 TLS
            }

            # 处理查询参数
            if 'sni' in params:
                proxy_dict['servername'] = params['sni'][0]
            if 'skip-cert-verify' in params:
                proxy_dict['skip-cert-verify'] = params['skip-cert-verify'][0].lower() == 'true'
            if 'alpn' in params and params['alpn'][0]:
                proxy_dict['alpn'] = [s.strip() for s in params['alpn'][0].split(',')]

            # WebSocket 或 gRPC over Trojan
            network = params.get('type', ['tcp'])[0] # type in query means network type
            proxy_dict['network'] = network

            if network == 'ws':
                ws_opts = {}
                if 'path' in params:
                    ws_opts['path'] = params['path'][0]
                if 'host' in params: # host in query is for Host header in ws-opts
                    ws_opts['headers'] = {'Host': params['host'][0]}
                if ws_opts:
                    proxy_dict['ws-opts'] = ws_opts
            elif network == 'grpc':
                grpc_opts = {}
                if 'serviceName' in params:
                    grpc_opts['service-name'] = params['serviceName'][0]
                if grpc_opts:
                    proxy_dict['grpc-opts'] = grpc_opts

            return proxy_dict
            
        elif link.startswith("hy2://"):
            # Hysteria2 链接格式: hy2://uuid@server:port?params#name
            parsed_url = urlparse(link)
            userinfo_part = parsed_url.netloc # uuid@server:port
            auth = userinfo_part.split('@')[0]
            server_port = userinfo_part.split('@')[1]
            server = server_port.split(':')[0]
            port = int(server_port.split(':')[1])

            params = parse_qs(parsed_url.query)
            name = (parsed_url.fragment if parsed_url.fragment else f"Hysteria2-Proxy-{i}").strip()

            proxy_dict = {
                "name": name,
                "type": "hysteria2",
                "server": server,
                "port": port,
                "password": auth, # Hysteria2 uses password field for authentication string
                "tls": True, # Hysteria2 always uses TLS
            }

            # Handle query parameters
            if 'insecure' in params:
                proxy_dict['insecure'] = params['insecure'][0].lower() == '1' # Insecure means skip-cert-verify
            if 'sni' in params:
                proxy_dict['servername'] = params['sni'][0]
            if 'alpn' in params and params['alpn'][0]:
                proxy_dict['alpn'] = [s.strip() for s in params['alpn'][0].split(',')]

            # Hysteria2 specific parameters (optional)
            if 'fastopen' in params:
                proxy_dict['fast-open'] = params['fastopen'][0].lower() == '1'
            if 'mptcp' in params:
                proxy_dict['mptcp'] = params['mptcp'][0].lower() == '1'
            if 'up' in params:
                proxy_dict['up'] = int(params['up'][0])
            if 'down' in params:
                proxy_dict['down'] = int(params['down'][0])

            return proxy_dict

    except Exception as e:
        print(f"Warning: Failed to parse link '{link}'. Error: {e}")
    return None

def fetch_and_parse_nodes():
    """从配置的来源获取并解析所有节点"""
    all_parsed_proxies = []

    for source in NODES_SOURCES:
        url = source["url"]
        node_format = source.get("format", "auto")
        print(f"Fetching nodes from: {url} (Format: {node_format})")
        try:
            response = requests.get(url, timeout=15) # Increased timeout
            response.raise_for_status()
            content = response.text

            processed_content = content
            # 1. 尝试 Base64 解码
            if node_format == "base64-links" or (node_format == "auto" and is_base64(content)):
                try:
                    processed_content = base64.b64decode(content).decode('utf-8')
                    print(f"Successfully decoded content from base64 for {url}")
                except Exception as e:
                    print(f"Warning: Failed to base64 decode {url}. Treating as plain text. Error: {e}")
                    processed_content = content # 解码失败则回退为原始内容

            # 2. 尝试 YAML 解析 (Clash proxies 格式)
            # 只有在明确指定为 clash-yaml 格式或 auto 模式下检测到 YAML 时才尝试解析
            if node_format == "clash-yaml" or (node_format == "auto" and is_yaml(processed_content) and 'proxies' in yaml.safe_load(processed_content)):
                try:
                    yaml_data = yaml.safe_load(processed_content)
                    if isinstance(yaml_data, dict) and 'proxies' in yaml_data and isinstance(yaml_data['proxies'], list):
                        print(f"Successfully parsed Clash YAML proxies from {url}")
                        for proxy_dict in yaml_data['proxies']:
                            if isinstance(proxy_dict, dict) and 'name' in proxy_dict and 'type' in proxy_dict:
                                all_parsed_proxies.append(proxy_dict)
                            else:
                                print(f"Warning: Invalid proxy entry in YAML from {url}: {proxy_dict}")
                        continue # YAML 格式处理完毕，跳到下一个来源
                    else:
                        print(f"Warning: YAML from {url} does not contain a valid 'proxies' list. Treating as plain links.")
                except yaml.YAMLError as e:
                    print(f"Warning: Failed to parse YAML from {url}. Treating as plain links. Error: {e}")
            
            # 3. 如果不是 YAML 或 YAML 不包含 proxies，则视为纯文本链接列表
            raw_links = processed_content.splitlines()
            print(f"Processing {len(raw_links)} raw links from {url}")
            for i, link in enumerate(raw_links):
                if not link.strip():
                    continue
                proxy = parse_link(link.strip(), i)
                if proxy:
                    all_parsed_proxies.append(proxy)

        except requests.exceptions.RequestException as e:
            print(f"Error fetching {url}: {e}")
        except Exception as e:
            print(f"An unexpected error occurred while processing {url}: {e}")
    
    return all_parsed_proxies


def generate_clash_config(proxies):
    """生成 Clash 配置文件"""
    config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule", # 可以根据需要改为 global 或 direct
        "log-level": "debug", # 关键的调试日志级别
        "external-controller": "127.0.0.1:9090",
        "secret": "", # API 密钥，如果不需要可以留空
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "测速",
                "type": "select",
                "proxies": [p["name"] for p in proxies] if proxies else ["DIRECT"]
            },
            {
                "name": "DIRECT",
                "type": "direct"
            },
            {
                "name": "REJECT",
                "type": "reject"
            }
        ],
        "rules": [
            "MATCH,测速"
        ]
    }
    with open(CLASH_CONFIG_PATH, 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    print(f"Clash config generated at {CLASH_CONFIG_PATH}")


def start_clash():
    """启动 Clash Core"""
    print("Starting Clash core...")
    # 指定日志文件
    clash_process = subprocess.Popen(
        [CLASH_BIN_PATH, "-f", CLASH_CONFIG_PATH, "-d", "."],
        stdout=open(CLASH_LOG_PATH, 'a'), # Append to log file
        stderr=subprocess.STDOUT
    )
    # 等待 Clash 启动
    time.sleep(5) # 给予更多时间确保Clash完全启动
    print("Clash core started.")
    return clash_process


def test_proxy(proxy_name):
    """测试单个代理的速度"""
    try:
        # 切换 Clash 的全局代理到当前节点
        headers = {'Content-Type': 'application/json'}
        payload = {"name": proxy_name}
        
        # 确保API可用
        response = requests.get(f"{CLASH_API_URL}/proxies", timeout=5)
        response.raise_for_status() # 检查API是否响应

        # 切换代理
        response = requests.put(f"{CLASH_API_URL}/proxies/%E6%B5%8B%E9%80%9F", # '测速' URL 编码
                                 headers=headers, json=payload, timeout=5)
        response.raise_for_status() # 检查切换是否成功
        print(f"Switched proxy to: {proxy_name}")
        time.sleep(1) # 等待代理切换生效

        # 进行测速
        start_time = time.time()
        with requests.get(SPEED_TEST_URL, stream=True, timeout=SPEED_TEST_TIMEOUT, proxies={'http': CLASH_PROXY_URL, 'https': CLASH_PROXY_URL}) as r:
            r.raise_for_status()
            total_size = 0
            for chunk in r.iter_content(chunk_size=8192):
                total_size += len(chunk)
            
        end_time = time.time()
        duration = end_time - start_time
        
        if duration > 0:
            speed_mbps = (total_size * 8) / (1024 * 1024 * duration)
            print(f"Proxy: {proxy_name} # Speed: {speed_mbps:.2f} Mbps")
            return f"Proxy: {proxy_name} # 速度: {speed_mbps:.2f} Mbps"
        else:
            print(f"Proxy: {proxy_name} # Speed: 0 Mbps (Duration too short)")
            return f"Proxy: {proxy_name} # 速度: 0 Mbps (Duration too short)"

    except requests.exceptions.Timeout:
        print(f"Proxy: {proxy_name} # Speed: 测试超时")
        return f"Proxy: {proxy_name} # 速度: 测试超时"
    except requests.exceptions.RequestException as e:
        print(f"Proxy: {proxy_name} # Speed: 测试失败 (通过 {CLASH_PROXY_URL}): {e}")
        return f"Proxy: {proxy_name} # 速度: 测试失败 (通过 {CLASH_PROXY_URL}): {e}"
    except Exception as e:
        print(f"An unexpected error occurred during test for {proxy_name}: {e}")
        return f"Proxy: {proxy_name} # 速度: 未知错误: {e}"


def main():
    os.makedirs("data", exist_ok=True) # 确保 data 目录存在
    # 清空旧日志文件。注意：此行应在 setup_clash_core() 之前，因为 setup_clash_core 会确保 clash_bin 存在。
    # 也可以在 setup_clash_core() 中创建 clash_bin 后再清空日志。
    # 但根据当前逻辑，这里先尝试清空，如果 clash_bin 不存在，会在 open() 时引发错误。
    # 更好的做法是在确保目录存在后再清空。
    # 鉴于 setup_clash_core 已经处理了 clash_bin 的创建，我们可以在这里直接清空。
    open(CLASH_LOG_PATH, 'w').close() # 清空旧日志文件

    setup_clash_core()
    proxies = fetch_and_parse_nodes()

    if not proxies:
        print("No valid proxies found to test.")
        with open(COLLECT_SUB_PATH, 'w', encoding='utf-8') as f:
            f.write("# 节点测速结果 - 无可用节点\n")
        return

    generate_clash_config(proxies)

    clash_process = None
    try:
        clash_process = start_clash()
        results = []
        results.append(f"# 节点测速结果 - {time.strftime('%Y-%m-%d %H:%M:%S')}\n")

        # 添加默认的DIRECT和REJECT组的测试结果（通常无法测速，只是占位）
        # 这些不是实际的代理，而是Clash的特殊组，通常不能直接测速
        results.append("Proxy: DIRECT # 速度: (无法直接测速此Clash内置组)")
        results.append("Proxy: REJECT # 速度: (无法直接测速此Clash内置组)")
        # 兼容旧配置可能存在的组，如果它们是“Select”类型，且被设置为默认值，它们通常会代理流量。
        # 但直接对它们进行测速意义不大，Clash API测速是针对具体的proxies名称。
        results.append("Proxy: COMPATIBLE # 速度: (无法切换到此虚拟组)")
        results.append("Proxy: PASS # 速度: (无法切换到此虚拟组)")
        results.append("Proxy: REJECT-DROP # 速度: (无法切换到此虚拟组)")


        for proxy in proxies:
            result = test_proxy(proxy["name"])
            results.append(result)
            
        with open(COLLECT_SUB_PATH, 'w', encoding='utf-8') as f:
            for line in results:
                f.write(line + "\n")
        print(f"Speed test results saved to {COLLECT_SUB_PATH}")

    finally:
        if clash_process:
            print("Terminating Clash core...")
            clash_process.terminate()
            clash_process.wait(timeout=10) # 等待进程结束
            print("Clash core terminated.")

if __name__ == "__main__":
    main()
