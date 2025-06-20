import subprocess
import time
import json
import os
import requests
from urllib.parse import urlparse, parse_qs
import base64
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib.parse
import statistics

# 配置常量
SOCKS_PORT = 10808
HTTP_PORT = 8088
TEST_URLS = [
    "http://connectivitycheck.gstatic.com/generate_204",
    "https://www.google.com/generate_204"
]
DOWNLOAD_TEST_URL = "https://speed.cloudflare.com/__down?bytes=10000000"
DOWNLOAD_TEST_SIZE = 10_000_000  # 10MB in bytes
MIN_AVG_SPEED_MBPS = 1.5  # 最低平均速度阈值 (Mbps)
DOWNLOAD_ATTEMPTS = 3  # 每节点下载测试次数
CONFIG_DIR = "configs"
LOG_FILE = "test_results.log"
SUCCESS_FILE = "success_nodes.txt"
FAILED_FILE = "failed_nodes.txt"
TIMEOUT = 15
RETRY_COUNT = 3
MAX_WORKERS = 5  # 控制并行测试数量

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def log_message(level, message):
    """记录日志信息"""
    getattr(logger, level)(message)

def setup_requests_session():
    """配置 requests 会话，支持重试"""
    session = requests.Session()
    retries = Retry(total=RETRY_COUNT, backoff_factor=1, status_forcelist=[500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))
    return session

def parse_node_url(node_url):
    """解析节点 URL，返回配置字典"""
    try:
        parsed = urlparse(node_url)
        scheme = parsed.scheme.lower()
        if scheme not in ['hysteria2', 'vmess', 'trojan', 'ss', 'ssr', 'vless']:
            log_message("error", f"Unsupported protocol: {scheme}")
            return None

        if scheme == 'vless':
            if parsed.port == 'undefined' or not parsed.port:
                log_message("error", f"Invalid port in node: {node_url}")
                return None
            params = parse_qs(parsed.query)
            if 'tls' in params.get('security', ['']) and not params.get('sni'):
                log_message("error", f"Missing sni for TLS node: {node_url}")
                return None
            return {
                'scheme': scheme,
                'uuid': parsed.username,
                'host': parsed.hostname,
                'port': int(parsed.port),
                'params': params,
                'remark': urllib.parse.unquote(parsed.fragment) if parsed.fragment else ''
            }
        elif scheme == 'trojan':
            if not parsed.username:
                log_message("error", f"Missing username in trojan node: {node_url}")
                return None
            params = parse_qs(parsed.query)
            return {
                'scheme': scheme,
                'password': parsed.username,
                'host': parsed.hostname,
                'port': int(parsed.port) if parsed.port else 443,
                'params': params,
                'remark': urllib.parse.unquote(parsed.fragment) if parsed.fragment else ''
            }
        elif scheme == 'ss':
            try:
                auth = base64.b64decode(parsed.netloc.split('@')[0]).decode('utf-8')
                method, password = auth.split(':')
                host, port = parsed.netloc.split('@')[1].split(':')
                return {
                    'scheme': scheme,
                    'method': method,
                    'password': password,
                    'host': host,
                    'port': int(port),
                    'remark': urllib.parse.unquote(parsed.fragment) if parsed.fragment else ''
                }
            except Exception as e:
                log_message("error", f"Failed to parse SS node: {node_url}, error: {str(e)}")
                return None
        elif scheme == 'vmess':
            try:
                config = json.loads(base64.b64decode(parsed.netloc).decode('utf-8'))
                return {
                    'scheme': scheme,
                    'config': config,
                    'remark': urllib.parse.unquote(parsed.fragment) if parsed.fragment else ''
                }
            except Exception as e:
                log_message("error", f"Failed to parse VMess node: {node_url}, error: {str(e)}")
                return None
        elif scheme == 'ssr':
            try:
                decoded = base64.b64decode(parsed.netloc).decode('utf-8')
                parts = decoded.split(':')
                if len(parts) < 6:
                    log_message("error", f"Invalid SSR node format: {node_url}")
                    return None
                host, port, protocol, method, obfs, password = parts[:6]
                password = base64.b64decode(password).decode('utf-8')
                params = parse_qs(parsed.query)
                return {
                    'scheme': scheme,
                    'host': host,
                    'port': int(port),
                    'protocol': protocol,
                    'method': method,
                    'obfs': obfs,
                    'password': password,
                    'params': params,
                    'remark': urllib.parse.unquote(parsed.fragment) if parsed.fragment else ''
                }
            except Exception as e:
                log_message("error", f"Failed to parse SSR node: {node_url}, error: {str(e)}")
                return None
        elif scheme == 'hysteria2':
            params = parse_qs(parsed.query)
            return {
                'scheme': scheme,
                'password': parsed.username,
                'host': parsed.hostname,
                'port': int(parsed.port) if parsed.port else 443,
                'params': params,
                'remark': urllib.parse.unquote(parsed.fragment) if parsed.fragment else ''
            }
    except Exception as e:
        log_message("error", f"Failed to parse node: {node_url}, error: {str(e)}")
        return None

def generate_singbox_config(node, index):
    """生成 sing-box 配置文件"""
    try:
        if node is None:
            return None
        scheme = node['scheme']
        config = {
            "log": {"level": "debug"},
            "inbounds": [
                {
                    "type": "http",
                    "listen": "127.0.0.1",
                    "listen_port": HTTP_PORT
                },
                {
                    "type": "socks",
                    "listen": "127.0.0.1",
                    "listen_port": SOCKS_PORT
                }
            ],
            "outbounds": []
        }
        if scheme == 'vless':
            outbound = {
                "type": "vless",
                "server": node['host'],
                "server_port": node['port'],
                "uuid": node['uuid'],
                "transport": {
                    "type": node['params'].get('type', [''])[0]
                }
            }
            if 'tls' in node['params'].get('security', ['']):
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": node['params'].get('sni', [''])[0],
                    "min_version": "1.2",
                    "max_version": "1.3"
                }
            if node['params'].get('type') == ['ws']:
                outbound["transport"]["path"] = node['params'].get('path', [''])[0]
                outbound["transport"]["headers"] = {"Host": node['params'].get('host', [''])[0]}
            config["outbounds"].append(outbound)
        elif scheme == 'trojan':
            outbound = {
                "type": "trojan",
                "server": node['host'],
                "server_port": node['port'],
                "password": node['password']
            }
            if node['params'].get('sni'):
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": node['params'].get('sni', [''])[0],
                    "min_version": "1.2",
                    "max_version": "1.3"
                }
            config["outbounds"].append(outbound)
        elif scheme == 'ss':
            outbound = {
                "type": "shadowsocks",
                "server": node['host'],
                "server_port": node['port'],
                "method": node['method'],
                "password": node['password']
            }
            config["outbounds"].append(outbound)
        elif scheme == 'vmess':
            config_data = node['config']
            outbound = {
                "type": "vmess",
                "server": config_data['add'],
                "server_port": int(config_data['port']),
                "uuid": config_data['id'],
                "security": config_data.get('scy', 'auto'),
                "transport": {
                    "type": config_data.get('net', '')
                }
            }
            if config_data.get('tls') == 'tls':
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": config_data.get('sni', config_data['add']),
                    "min_version": "1.2",
                    "max_version": "1.3"
                }
            if config_data.get('net') == 'ws':
                outbound["transport"]["path"] = config_data.get('path', '')
                outbound["transport"]["headers"] = {"Host": config_data.get('host', '')}
            config["outbounds"].append(outbound)
        elif scheme == 'ssr':
            outbound = {
                "type": "shadowsocksr",
                "server": node['host'],
                "server_port": node['port'],
                "method": node['method'],
                "password": node['password'],
                "obfs": node['obfs'],
                "protocol": node['protocol']
            }
            config["outbounds"].append(outbound)
        elif scheme == 'hysteria2':
            outbound = {
                "type": "hysteria2",
                "server": node['host'],
                "server_port": node['port'],
                "password": node['password'],
                "obfs": {
                    "type": "salamander",
                    "password": node['params'].get('obfs-password', [''])[0]
                }
            }
            if node['params'].get('sni'):
                outbound["tls"] = {
                    "enabled": True,
                    "server_name": node['params'].get('sni', [''])[0],
                    "min_version": "1.2",
                    "max_version": "1.3"
                }
            config["outbounds"].append(outbound)
        config_path = os.path.join(CONFIG_DIR, f"singbox_config_{index}.json")
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
        return config_path
    except Exception as e:
        log_message("error", f"Failed to generate sing-box config for {node['remark']}: {str(e)}")
        return None

def generate_xray_config(node, index):
    """生成 xray 配置文件"""
    try:
        if node is None:
            return None
        scheme = node['scheme']
        config = {
            "log": {"loglevel": "debug"},
            "inbounds": [
                {
                    "protocol": "http",
                    "listen": "127.0.0.1",
                    "port": HTTP_PORT
                },
                {
                    "protocol": "socks",
                    "listen": "127.0.0.1",
                    "port": SOCKS_PORT
                }
            ],
            "outbounds": []
        }
        if scheme == 'vless':
            outbound = {
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": node['host'],
                        "port": node['port'],
                        "users": [{"id": node['uuid']}]
                    }]
                },
                "streamSettings": {
                    "network": node['params'].get('type', [''])[0]
                }
            }
            if 'tls' in node['params'].get('security', ['']):
                outbound["streamSettings"]["security"] = "tls"
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": node['params'].get('sni', [''])[0],
                    "minVersion": "1.2",
                    "maxVersion": "1.3"
                }
            if node['params'].get('type') == ['ws']:
                outbound["streamSettings"]["wsSettings"] = {
                    "path": node['params'].get('path', [''])[0],
                    "headers": {"Host": node['params'].get('host', [''])[0]}
                }
            config["outbounds"].append(outbound)
        elif scheme == 'trojan':
            outbound = {
                "protocol": "trojan",
                "settings": {
                    "servers": [{
                        "address": node['host'],
                        "port": node['port'],
                        "password": node['password']
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": node['params'].get('sni', [''])[0],
                        "minVersion": "1.2",
                        "maxVersion": "1.3"
                    }
                }
            }
            config["outbounds"].append(outbound)
        elif scheme == 'ss':
            outbound = {
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": node['host'],
                        "port": node['port'],
                        "method": node['method'],
                        "password": node['password']
                    }]
                }
            }
            config["outbounds"].append(outbound)
        elif scheme == 'vmess':
            config_data = node['config']
            outbound = {
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": config_data['add'],
                        "port": int(config_data['port']),
                        "users": [{"id": config_data['id'], "security": config_data.get('scy', 'auto')}]
                    }]
                },
                "streamSettings": {
                    "network": config_data.get('net', '')
                }
            }
            if config_data.get('tls') == 'tls':
                outbound["streamSettings"]["security"] = "tls"
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": config_data.get('sni', config_data['add']),
                    "minVersion": "1.2",
                    "maxVersion": "1.3"
                }
            if config_data.get('net') == 'ws':
                outbound["streamSettings"]["wsSettings"] = {
                    "path": config_data.get('path', ''),
                    "headers": {"Host": config_data.get('host', '')}
                }
            config["outbounds"].append(outbound)
        elif scheme == 'ssr':
            outbound = {
                "protocol": "shadowsocksr",
                "settings": {
                    "servers": [{
                        "address": node['host'],
                        "port": node['port'],
                        "method": node['method'],
                        "password": node['password'],
                        "obfs": node['obfs'],
                        "protocol": node['protocol']
                    }]
                }
            }
            config["outbounds"].append(outbound)
        elif scheme == 'hysteria2':
            return None  # xray 不支持 hysteria2
        config_path = os.path.join(CONFIG_DIR, f"xray_config_{index}.json")
        os.makedirs(CONFIG_DIR, exist_ok=True)
        with open(config_path, "w") as f:
            json.dump(config, f, indent=2)
        return config_path
    except Exception as e:
        log_message("error", f"Failed to generate xray config for {node['remark']}: {str(e)}")
        return None

def run_single_test(core_name, config_path, node_url, index, total):
    """运行单个核心测试"""
    process = None
    connect_latency = None
    download_speeds = []
    test_success = False
    error_message = None
    try:
        log_message("debug", f"Starting {core_name} for node {index}/{total}: {node_url}")
        cmd = ["sing-box", "run", "-c", config_path] if core_name == "sing-box" else ["xray", "-c", config_path]
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        time.sleep(5)  # 等待核心启动
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            error_message = f"{core_name} exited prematurely: {stderr}"
            log_message("error", error_message)
            return None, None, error_message

        proxies = {
            "http": f"http://127.0.0.1:{HTTP_PORT}",
            "https": f"http://127.0.0.1:{HTTP_PORT}",
            "socks": f"socks5://127.0.0.1:{SOCKS_PORT}"
        }
        session = setup_requests_session()

        # 测试连通性和延迟
        for test_url in TEST_URLS:
            try:
                start_time = time.time()
                response = session.get(test_url, proxies=proxies, timeout=TIMEOUT, verify=False)
                if response.status_code in [200, 204]:
                    connect_latency = (time.time() - start_time) * 1000  # ms
                    test_success = True
                    break
                else:
                    log_message("debug", f"Test failed for {test_url}: Status code {response.status_code}")
            except requests.exceptions.RequestException as e:
                log_message("debug", f"Test failed for {test_url}: {str(e)}")

        if not test_success:
            error_message = "Connection test failed"
            return None, None, error_message

        # 下载速度测试
        for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
            try:
                start_time = time.time()
                response = session.get(DOWNLOAD_TEST_URL, proxies=proxies, timeout=TIMEOUT * 2, verify=False)
                if response.status_code == 200:
                    elapsed_time = time.time() - start_time
                    speed_mbps = (DOWNLOAD_TEST_SIZE * 8 / 1_000_000) / elapsed_time  # Mbps
                    download_speeds.append(speed_mbps)
                    log_message("info", f"Download test {attempt}/{DOWNLOAD_ATTEMPTS} for node {index}/{total}: {speed_mbps:.2f} Mbps")
                else:
                    log_message("debug", f"Download test {attempt} failed: Status code {response.status_code}")
            except requests.exceptions.RequestException as e:
                log_message("debug", f"Download test {attempt} failed: {str(e)}")
                download_speeds.append(0)

        return connect_latency, download_speeds, None
    except Exception as e:
        error_message = f"Error in {core_name}: {str(e)}"
        log_message("error", error_message)
        return None, None, error_message
    finally:
        if process:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

def process_node(node_url, index, total):
    """处理单个节点"""
    log_message("info", f"Processing node {index}/{total}: {node_url}")
    node = parse_node_url(node_url)
    if node is None:
        with open(FAILED_FILE, "a") as f:
            f.write(f"{node_url} | Failed: Invalid node format\n")
        return

    singbox_config = generate_singbox_config(node, index)
    xray_config = generate_xray_config(node, index)
    if singbox_config is None and xray_config is None:
        log_message("error", f"Skipping node {index}/{total}: Failed to generate configs")
        with open(FAILED_FILE, "a") as f:
            f.write(f"{node_url} | Failed: Config generation failed\n")
        return

    cores = []
    if singbox_config:
        cores.append(("sing-box", singbox_config))
    if xray_config and node['scheme'] != 'hysteria2':
        cores.append(("xray", xray_config))

    best_latency = float('inf')
    best_speeds = []
    best_core = None
    error_message = "No successful tests"

    for core_name, config_path in cores:
        latency, speeds, error = run_single_test(core_name, config_path, node_url, index, total)
        if latency is not None and speeds and any(s > 0 for s in speeds):
            avg_speed = statistics.mean([s for s in speeds if s > 0])
            if avg_speed >= MIN_AVG_SPEED_MBPS and latency < best_latency:
                best_latency = latency
                best_speeds = speeds
                best_core = core_name
                error_message = None

    if error_message:
        log_message("error", f"Node {index}/{total} failed: {error_message}")
        with open(FAILED_FILE, "a") as f:
            f.write(f"{node_url} | Failed: {error_message}\n")
    else:
        avg_speed = statistics.mean([s for s in best_speeds if s > 0])
        log_message("info", f"Node {index}/{total} succeeded: Latency={best_latency:.2f}ms, Avg Speed={avg_speed:.2f}Mbps, Core={best_core}")
        with open(SUCCESS_FILE, "a") as f:
            f.write(f"{node_url} | Latency={best_latency:.2f}ms | Avg Speed={avg_speed:.2f}Mbps | Core={best_core}\n")

def main():
    """主函数"""
    if not os.path.exists("all_nodes.txt"):
        log_message("error", "Input file all_nodes.txt not found")
        return

    with open("all_nodes.txt", "r") as f:
        nodes = [line.strip() for line in f if line.strip()]

    os.makedirs(CONFIG_DIR, exist_ok=True)
    open(SUCCESS_FILE, "w").close()
    open(FAILED_FILE, "w").close()

    for index, node_url in enumerate(nodes, 1):
        process_node(node_url, index, len(nodes))

if __name__ == "__main__":
    main()
