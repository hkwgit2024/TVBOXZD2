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
        "format": "clash-yaml" # 明确指定为 clash-yaml 格式，即使 is_yaml 失败也要尝试
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
    try:
        decoded_bytes = base64.b64decode(s.strip(), validate=True)
        # 尝试解码为UTF-8以避免二进制数据误判
        return decoded_bytes.decode('utf-8') is not None
    except Exception:
        return False

def is_yaml(s):
    """尝试判断字符串是否是YAML格式 (使用 full_load 以支持更多标签)"""
    if not isinstance(s, str) or not s.strip():
        return False
    try:
        # 尝试使用 full_load 处理可能存在的自定义标签
        data = yaml.full_load(s)
        return isinstance(data, dict) or isinstance(data, list)
    except yaml.YAMLError:
        return False
    except Exception:
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
            parts = link[5:].split('@')
            if len(parts) != 2:
                raise ValueError("Invalid SS link format (missing @)")

            user_info_encoded = parts[0]
            try:
                user_info_decoded = base64.b64decode(user_info_encoded + '==').decode('utf-8')
                method, password = user_info_decoded.split(':', 1)
            except Exception:
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
            encoded_data = link[8:]
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
            cipher = vmess_data.get('scy', 'auto')

            proxy_dict = {
                "name": name,
                "type": "vmess",
                "server": server,
                "port": port,
                "uuid": uuid,
                "alterId": alterId,
                "cipher": cipher
            }

            network = vmess_data.get('net', 'tcp')
            proxy_dict['network'] = network

            if network == 'ws':
                ws_opts = {}
                if 'path' in vmess_data:
                    ws_opts['path'] = vmess_data['path']
                if 'host' in vmess_data:
                    ws_opts['headers'] = {'Host': vmess_data['host']}
                if ws_opts:
                    proxy_dict['ws-opts'] = ws_opts
            elif network == 'grpc':
                grpc_opts = {}
                if 'serviceName' in vmess_data:
                    grpc_opts['service-name'] = vmess_data['serviceName']
                if grpc_opts:
                    proxy_dict['grpc-opts'] = grpc_opts
            elif network == 'h2':
                h2_opts = {}
                if 'path' in vmess_data:
                    h2_opts['path'] = vmess_data['path']
                if h2_opts:
                    proxy_dict['h2-opts'] = h2_opts

            if vmess_data.get('tls', '0') == 'tls':
                proxy_dict['tls'] = True
                if 'host' in vmess_data:
                    proxy_dict['servername'] = vmess_data['host']
                if vmess_data.get('allowInsecure', '0') == '1':
                    proxy_dict['skip-cert-verify'] = True
                if 'alpn' in vmess_data and vmess_data['alpn']:
                    proxy_dict['alpn'] = [s.strip() for s in vmess_data['alpn'].split(',')]

            if vmess_data.get('type') == 'http':
                proxy_dict['network'] = 'http'
            elif vmess_data.get('obfs') == 'websocket':
                proxy_dict['network'] = 'ws'
                ws_opts = proxy_dict.get('ws-opts', {})
                if 'obfs-host' in vmess_data:
                    ws_opts['headers'] = {'Host': vmess_data['obfs-host']}
                proxy_dict['ws-opts'] = ws_opts

            return proxy_dict

        elif link.startswith("vless://"):
            parsed_url = urlparse(link)
            userinfo_part = parsed_url.netloc
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

            if 'tls' in params:
                proxy_dict['tls'] = params['tls'][0].lower() == 'true'
            if 'flow' in params:
                proxy_dict['flow'] = params['flow'][0]
            if 'sni' in params:
                proxy_dict['servername'] = params['sni'][0]
            if 'alpn' in params and params['alpn'][0]:
                proxy_dict['alpn'] = [s.strip() for s in params['alpn'][0].split(',')]
            if 'skip-cert-verify' in params:
                proxy_dict['skip-cert-verify'] = params['skip-cert-verify'][0].lower() == 'true'

            network = params.get('type', ['tcp'])[0]
            proxy_dict['network'] = network

            if network == 'ws':
                ws_opts = {}
                if 'path' in params:
                    ws_opts['path'] = params['path'][0]
                if 'host' in params:
                    ws_opts['headers'] = {'Host': params['host'][0]}
                if ws_opts:
                    proxy_dict['ws-opts'] = ws_opts
            elif network == 'grpc':
                grpc_opts = {}
                if 'serviceName' in params:
                    grpc_opts['service-name'] = params['serviceName'][0]
                if grpc_opts:
                    proxy_dict['grpc-opts'] = grpc_opts
            elif network == 'h2':
                h2_opts = {}
                if 'path' in params:
                    h2_opts['path'] = params['path'][0]
                if h2_opts:
                    proxy_dict['h2-opts'] = h2_opts

            return proxy_dict

        elif link.startswith("trojan://"):
            parsed_url = urlparse(link)
            userinfo_part = parsed_url.netloc
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
                "tls": True
            }

            if 'sni' in params:
                proxy_dict['servername'] = params['sni'][0]
            if 'skip-cert-verify' in params:
                proxy_dict['skip-cert-verify'] = params['skip-cert-verify'][0].lower() == 'true'
            if 'alpn' in params and params['alpn'][0]:
                proxy_dict['alpn'] = [s.strip() for s in params['alpn'][0].split(',')]

            network = params.get('type', ['tcp'])[0]
            proxy_dict['network'] = network

            if network == 'ws':
                ws_opts = {}
                if 'path' in params:
                    ws_opts['path'] = params['path'][0]
                if 'host' in params:
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
            parsed_url = urlparse(link)
            userinfo_part = parsed_url.netloc
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
                "password": auth,
                "tls": True,
            }

            if 'insecure' in params:
                proxy_dict['insecure'] = params['insecure'][0].lower() == '1'
            if 'sni' in params:
                proxy_dict['servername'] = params['sni'][0]
            if 'alpn' in params and params['alpn'][0]:
                proxy_dict['alpn'] = [s.strip() for s in params['alpn'][0].split(',')]

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
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            content = response.text

            processed_content = content
            if node_format == "base64-links" or (node_format == "auto" and is_base64(content)):
                try:
                    processed_content = base64.b64decode(content).decode('utf-8')
                    print(f"Successfully decoded content from base64 for {url}")
                except Exception as e:
                    print(f"Warning: Failed to base64 decode {url}. Treating as plain text. Error: {e}")
                    processed_content = content

            # 调整 is_yaml 的判断，避免重复加载 YAML 内容
            is_yaml_content = False
            yaml_data_from_content = None
            if node_format == "clash-yaml" or node_format == "auto":
                # --- 新增：尝试清理 YAML 中的非标准标签 ---
                # 这是一个临时性的清理，旨在处理 pyyaml 无法识别的 !<str> 标签
                # 移除 !<tag> 和其后的空白字符，只保留值
                cleaned_yaml_content = re.sub(r'![a-zA-Z0-9_]+\s*', '', processed_content)
                # ----------------------------------------
                try:
                    # 尝试加载清理后的内容
                    yaml_data_from_content = yaml.full_load(cleaned_yaml_content)
                    if isinstance(yaml_data_from_content, dict) and 'proxies' in yaml_data_from_content and isinstance(yaml_data_from_content['proxies'], list):
                        is_yaml_content = True
                except yaml.YAMLError as e:
                    print(f"Warning: Failed to parse CLEANED YAML from {url}. Error: {e}")
                except Exception as e:
                    print(f"Warning: An unexpected error occurred during CLEANED YAML check for {url}. Error: {e}")
            
            if is_yaml_content:
                print(f"Successfully parsed Clash YAML proxies from {url} (after cleaning tags)")
                for proxy_dict in yaml_data_from_content['proxies']:
                    if isinstance(proxy_dict, dict) and 'name' in proxy_dict and 'type' in proxy_dict:
                        all_parsed_proxies.append(proxy_dict)
                    else:
                        print(f"Warning: Invalid proxy entry in YAML from {url}: {proxy_dict}")
                continue # YAML 格式处理完毕，跳到下一个来源
            elif node_format == "clash-yaml": # 如果明确指定为 clash-yaml 但解析失败
                print(f"Error: Format explicitly set to 'clash-yaml' for {url}, but content is not valid Clash YAML even after cleaning. Skipping.")
                continue


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
        "mode": "rule",
        "log-level": "debug",
        "external-controller": "127.0.0.1:9090",
        "secret": "",
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
    os.makedirs(os.path.dirname(CLASH_LOG_PATH), exist_ok=True) # 确保日志文件目录存在
    with open(CLASH_LOG_PATH, 'w') as log_file: # 每次启动前清空日志
        log_file.write(f"--- Clash Core Log Start ({time.strftime('%Y-%m-%d %H:%M:%S')}) ---\n")
    
    clash_process = subprocess.Popen(
        [CLASH_BIN_PATH, "-f", CLASH_CONFIG_PATH, "-d", "."],
        stdout=subprocess.PIPE, # 捕获 stdout
        stderr=subprocess.PIPE, # 捕获 stderr
        text=True # 以文本模式处理，方便读取
    )

    time.sleep(2) # 初始等待

    api_ready = False
    for i in range(10): # 尝试连接API 10次
        if clash_process.poll() is not None: # 如果进程已退出
            print("Clash process exited prematurely.")
            clash_stdout, clash_stderr = clash_process.communicate(timeout=5)
            with open(CLASH_LOG_PATH, 'a') as log_file:
                log_file.write("\n--- Clash Process STDOUT/STDERR ---\n")
                log_file.write(clash_stdout)
                log_file.write(clash_stderr)
                log_file.write("\n--- End of Clash Process STDOUT/STDERR ---\n")
            raise Exception("Clash core exited prematurely. Check log for details.")

        try:
            response = requests.get(f"{CLASH_API_URL}/configs", timeout=2)
            if response.status_code == 200:
                print("Clash API is reachable.")
                api_ready = True
                break
        except requests.exceptions.ConnectionError:
            pass # API not yet ready
        except Exception as e:
            print(f"Error checking Clash API: {e}")
        time.sleep(2)

    if not api_ready:
        raise Exception("Clash API did not become reachable within expected time.")

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
        response.raise_for_status()

        # 切换代理
        response = requests.put(f"{CLASH_API_URL}/proxies/%E6%B5%8B%E9%80%9F", # '测速' URL 编码
                                 headers=headers, json=payload, timeout=5)
        response.raise_for_status()
        print(f"Switched proxy to: {proxy_name}")
        time.sleep(1) # 等待代理切换生效

        # 进行测速
        start_time = time.time()
        with requests.get(SPEED_TEST_URL, stream=True, timeout=SPEED_TEST_TIMEOUT, proxies={'http': CLASH_PROXY_URL, 'https': CLASH_PROXY_URL}) as r:
            r.raise_for_status() # 检查HTTP响应状态码 (2xx success)
            total_size = 0
            for chunk in r.iter_content(chunk_size=8192):
                total_size += len(chunk)
                if total_size >= 5 * 1024 * 1024: # 如果下载量达到5MB就停止
                    break
            
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
    os.makedirs(os.path.dirname(CLASH_LOG_PATH), exist_ok=True) # 确保日志文件目录存在
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
        results.append("Proxy: DIRECT # 速度: (Clash内置组)")
        results.append("Proxy: REJECT # 速度: (Clash内置组)")
        results.append("Proxy: COMPATIBLE # 速度: (Clash内置组)")
        results.append("Proxy: PASS # 速度: (Clash内置组)")
        results.append("Proxy: REJECT-DROP # 速度: (Clash内置组)")


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
            clash_stdout, clash_stderr = clash_process.communicate(timeout=5)
            with open(CLASH_LOG_PATH, 'a') as log_file:
                log_file.write("\n--- Clash Process STDOUT/STDERR (on exit) ---\n")
                log_file.write(clash_stdout)
                log_file.write(clash_stderr)
                log_file.write("\n--- End of Clash Process STDOUT/STDERR (on exit) ---\n")
            
            clash_process.terminate()
            clash_process.wait(timeout=10)
            print("Clash core terminated.")

if __name__ == "__main__":
    main()
