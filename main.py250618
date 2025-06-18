import base64
import json
import os
import re
import subprocess
import time
import urllib.parse
import requests
import socket
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 常量定义
SINGBOX_BIN_PATH = "./clash_bin/sing-box"
SINGBOX_CONFIG_PATH = "sing-box-config.json"
SINGBOX_LOG_PATH = os.getenv("SINGBOX_LOG_PATH", "data/sing-box.log")
GEOIP_DB_PATH = "data/geoip.db"
OUTPUT_SUB_FILE = "data/collectSub.txt"
NODES_SOURCES = [
    {
        "url": "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.txt",
        "type": "plain",
    },
]
MAX_PROXIES = 1000
TEST_URLS = ["https://www.google.com", "http://www.example.com", "https://www.cloudflare.com"]
TIMEOUT_SECONDS = 10
PROXY_PORT = 1080

# 确保输出目录存在
for path in [OUTPUT_SUB_FILE, SINGBOX_LOG_PATH, GEOIP_DB_PATH]:
    dirname = os.path.dirname(path)
    if dirname:
        os.makedirs(dirname, exist_ok=True)

def is_valid_ipv6(addr):
    """验证 IPv6 地址格式"""
    try:
        addr = addr.strip("[]")
        socket.inet_pton(socket.AF_INET6, addr)
        return True
    except (socket.error, ValueError):
        return False

def get_proxies():
    """从节点源获取代理列表"""
    all_proxies = []
    for source in NODES_SOURCES:
        url = source["url"]
        source_type = source["type"]
        logging.info(f"Fetching proxies from {url} (type: {source_type})...")
        try:
            response = requests.get(url, timeout=TIMEOUT_SECONDS)
            response.raise_for_status() # 检查HTTP请求是否成功

            content = response.text
            if source_type == "base64": # 如果有Base64编码的订阅
                try:
                    content = base64.b64decode(content).decode('utf-8')
                except Exception as e:
                    logging.error(f"Failed to decode Base64 content from {url}: {e}")
                    continue

            # 按行分割代理链接，并过滤空行
            lines = [line.strip() for line in content.splitlines() if line.strip()]
            all_proxies.extend(lines)
            logging.info(f"Successfully fetched {len(lines)} proxies from {url}.")

        except requests.exceptions.RequestException as e:
            logging.error(f"Failed to fetch proxies from {url}: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred while processing {url}: {e}")

    # 限制代理数量以避免过多的测试
    return all_proxies[:MAX_PROXIES]


def decode_proxy(proxy_url):
    """解码代理 URL 并转换为 sing-box 配置格式"""
    try:
        parsed = urllib.parse.urlparse(proxy_url)
        scheme = parsed.scheme

        if scheme == "vmess":
            vmess_data = json.loads(base64.b64decode(parsed.netloc).decode())
            transport_type = vmess_data.get("net", "tcp")
            transport_config = {
                "type": transport_type,
                "path": vmess_data.get("path", ""),
            }
            if transport_type == "ws":
                transport_config["headers"] = {"Host": vmess_data.get("host", "")}
            return {
                "type": "vmess",
                "tag": vmess_data.get("ps", "vmess-node"),
                "server": vmess_data.get("add"),
                "server_port": int(vmess_data.get("port")),
                "uuid": vmess_data.get("id"),
                "security": vmess_data.get("scy", "auto"),
                "alter_id": int(vmess_data.get("aid", 0)),
                "transport": transport_config,
            }

        elif scheme == "trojan":
            if "@" not in parsed.netloc:
                logging.error(f"Invalid Trojan URL format, missing '@': {proxy_url}")
                return None
            password, addr = parsed.netloc.split("@", 1)
            # 修正 IPv6 地址解析逻辑
            hostname_port = addr.split("?", 1)[0] # 分离出 hostname:port 部分
            if hostname_port.startswith("[") and "]" in hostname_port:
                # 这是一个 IPv6 地址，提取地址和端口
                match = re.match(r'^\[([0-9a-fA-F:]+)\](?::(\d+))?$', hostname_port)
                if not match:
                    logging.error(f"Invalid IPv6 address format in Trojan URL: {proxy_url}")
                    return None
                hostname = match.group(1)
                port = int(match.group(2)) if match.group(2) else 443
                if not is_valid_ipv6(hostname): # 再次验证 IPv6
                    logging.error(f"Decoded IPv6 is not valid in Trojan URL: {proxy_url}")
                    return None
                hostname = f"[{hostname}]" # 重新添加方括号以匹配 sing-box 期望
            else:
                # 可能是 IPv4 或域名
                parts = hostname_port.split(":")
                hostname = parts[0]
                port = int(parts[1]) if len(parts) > 1 else 443

            query = urllib.parse.parse_qs(parsed.query)
            return {
                "type": "trojan",
                "tag": urllib.parse.unquote(query.get("name", ["trojan-node"])[0]) or "trojan-node", # 解码tag中的URL编码字符
                "server": hostname,
                "server_port": int(port),
                "password": password,
                "tls": {
                    "enabled": True,
                    "server_name": query.get("sni", [""])[0] or hostname.strip("[]"), # SNI不应该包含方括号
                    "insecure": query.get("allowInsecure", ["0"])[0] == "1",
                },
                "transport": { # 针对Trojan WS 添加 transport
                    "type": query.get("type", [""])[0],
                    "path": query.get("path", [""])[0],
                    "headers": {
                        "Host": query.get("host", [""])[0]
                    }
                } if query.get("type", [""])[0] == "ws" else None # 只有当type是ws时才添加transport
            }

        elif scheme == "ss":
            if "@" in parsed.netloc:
                auth, addr = parsed.netloc.split("@")
                method, password = base64.b64decode(auth).decode().split(":")
                hostname, port = addr.split(":")
            else:
                method_password = base64.b64decode(parsed.netloc).decode()
                method, password = method_password.split(":")
                hostname, port = parsed.path.lstrip("/").split(":")
            return {
                "type": "shadowsocks",
                "tag": urllib.parse.unquote(parsed.fragment) or "ss-node", # 解码tag中的URL编码字符
                "server": hostname,
                "server_port": int(port),
                "method": method,
                "password": password,
            }

        elif scheme == "hy2":
            if "@" not in parsed.netloc:
                logging.error(f"Invalid Hysteria2 URL format, missing '@': {proxy_url}")
                return None
            password, addr = parsed.netloc.split("@", 1)
            hostname_port = addr.split("?", 1)[0]
            if hostname_port.startswith("[") and "]" in hostname_port:
                match = re.match(r'^\[([0-9a-fA-F:]+)\](?::(\d+))?$', hostname_port)
                if not match:
                    logging.error(f"Invalid IPv6 address format in Hysteria2 URL: {proxy_url}")
                    return None
                hostname = match.group(1)
                port = int(match.group(2)) if match.group(2) else 443
                if not is_valid_ipv6(hostname):
                    logging.error(f"Decoded IPv6 is not valid in Hysteria2 URL: {proxy_url}")
                    return None
                hostname = f"[{hostname}]"
            else:
                parts = hostname_port.split(":")
                hostname = parts[0]
                port = int(parts[1]) if len(parts) > 1 else 443

            query = urllib.parse.parse_qs(parsed.query)
            obfs = query.get("obfs", [""])[0]
            obfs_password = query.get("obfs-password", [""])[0]
            config = {
                "type": "hysteria2",
                "tag": urllib.parse.unquote(query.get("name", ["hy2-node"])[0]) or "hy2-node", # 解码tag中的URL编码字符
                "server": hostname,
                "server_port": int(port),
                "password": password,
                "tls": {
                    "enabled": True,
                    "server_name": query.get("sni", [""])[0] or hostname.strip("[]"),
                    "insecure": query.get("insecure", ["0"])[0] == "1",
                },
            }
            if obfs and obfs_password:
                config["obfs"] = {
                    "type": obfs,
                    "password": obfs_password,
                }
            return config

        else:
            logging.warning(f"Unsupported scheme: {scheme}")
            return None

    except Exception as e:
        logging.error(f"Failed to decode proxy {proxy_url}: {e}")
        return None

def generate_singbox_config(proxy):
    """生成 sing-box 配置文件"""
    # 移除可能存在的 transport 为 None 的情况，否则会写入 null
    if "transport" in proxy and proxy["transport"] is None:
        del proxy["transport"]

    config = {
        "log": {
            "level": "debug",
            "output": SINGBOX_LOG_PATH,
        },
        "inbounds": [
            {
                "type": "http",
                "tag": "http-in",
                "listen": "127.0.0.1",
                "listen_port": PROXY_PORT,
            },
        ],
        "outbounds": [
            proxy,
            {
                "type": "direct",
                "tag": "direct",
            },
        ],
        "route": {
            "geoip": {
                "path": GEOIP_DB_PATH,
                "download_url": "https://github.com/SagerNet/sing-box/releases/latest/download/geoip.db", # 注意这里是sing-box，不是sing-geoip
                "download_detour": "direct",
            },
            "rules": [
                {
                    "domain": ["www.google.com", "www.example.com", "www.cloudflare.com"],
                    "outbound": proxy["tag"],
                },
                {
                    "geoip": ["cn"],
                    "outbound": "direct",
                },
            ],
        },
    }
    with open(SINGBOX_CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=2)
    return SINGBOX_CONFIG_PATH

def wait_for_port(host, port, timeout=30, interval=1):
    """等待端口变得可用"""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(interval)
            s.connect((host, port))
            s.close()
            logging.info(f"Port {port} is open!")
            return True
        except (socket.error, ConnectionRefusedError):
            logging.info(f"Waiting for port {port}...")
            time.sleep(interval)
    logging.error(f"Port {port} did not open within {timeout} seconds.")
    return False

def test_proxy(proxy):
    """测试代理节点速度"""
    process = None
    try:
        config_path = generate_singbox_config(proxy)
        result = subprocess.run([SINGBOX_BIN_PATH, "check", "-c", config_path], capture_output=True, text=True)
        if result.returncode != 0:
            logging.error(f"Invalid sing-box config for {proxy['tag']}: {result.stderr}")
            return None

        # 确保 sing-box 启动命令是正确的，并能捕获日志
        process = subprocess.Popen(
            [SINGBOX_BIN_PATH, "run", "-c", config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, # 将 stderr 合并到 stdout 以便统一捕获
            text=True,
            bufsize=1, # 行缓冲
            universal_newlines=True,
        )

        # 启动一个线程来读取 sing-box 的输出
        def log_singbox_output():
            for line in iter(process.stdout.readline, ''):
                # 写入到 sing-box.log 文件
                with open(SINGBOX_LOG_PATH, "a") as log_f:
                    log_f.write(line)
                # 也可以选择打印到控制台，但通常日志文件足够
                # logging.debug(f"sing-box: {line.strip()}")

        import threading
        log_thread = threading.Thread(target=log_singbox_output)
        log_thread.daemon = True # 设置为守护线程，主程序退出时自动终止
        log_thread.start()

        # 等待 sing-box 启动并监听端口
        if not wait_for_port('127.0.0.1', PROXY_PORT, timeout=30): # 增加等待时间
            if process.poll() is not None:
                logging.error(f"sing-box process exited prematurely for {proxy['tag']}.")
            else:
                logging.error(f"sing-box did not become ready for {proxy['tag']}.")
            return None

        for test_url in TEST_URLS:
            try:
                start_time = time.time()
                response = requests.get(
                    test_url,
                    proxies={"http": f"http://127.0.0.1:{PROXY_PORT}", "https": f"http://127.0.0.1:{PROXY_PORT}"},
                    timeout=TIMEOUT_SECONDS, # 保持这个超时不变，它指的是HTTP请求超时
                )
                latency = (time.time() - start_time) * 1000
                if response.status_code == 200:
                    logging.info(f"Proxy {proxy['tag']} succeeded with {test_url}, latency {latency:.2f}ms")
                    return {"proxy": proxy, "latency": latency}
                else:
                    logging.warning(f"Proxy {proxy['tag']} failed with {test_url}, status {response.status_code}")
            except requests.RequestException as e:
                logging.error(f"Proxy {proxy['tag']} test failed with {test_url}: {e}")
        return None

    except subprocess.SubprocessError as e:
        logging.error(f"Proxy {proxy.get('tag', 'unknown')} test failed: {e}")
        return None
    finally:
        if process:
            # 尝试优雅终止 sing-box 进程
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logging.warning(f"Failed to terminate sing-box process for {proxy.get('tag', 'unknown')}, killing it.")
                process.kill()
                process.wait(timeout=5) # 等待被杀死

        # 清理配置文件
        if os.path.exists(SINGBOX_CONFIG_PATH):
            os.remove(SINGBOX_CONFIG_PATH)

def main():
    """主函数：获取、测试代理并保存结果"""
    proxies = get_proxies()
    if not proxies:
        logging.error("No proxies found.")
        return

    results = []
    for proxy_url in proxies:
        proxy = decode_proxy(proxy_url)
        if proxy:
            # 打印正在测试的代理，方便调试
            logging.info(f"Testing proxy: {proxy.get('tag', 'unknown_tag')} - {proxy_url}")
            result = test_proxy(proxy)
            if result:
                results.append(result)

    results.sort(key=lambda x: x["latency"])
    with open(OUTPUT_SUB_FILE, "w") as f:
        for result in results:
            # 这里需要找到原始的代理URL，如果tag不唯一可能会有问题，需要更精确匹配
            # 暂时用proxy['tag']来查找原始URL，但可能需要优化
            original_proxy_url = "N/A"
            for url in proxies:
                if result['proxy']['tag'] in url: # 简单的包含判断，可能不准确
                    original_proxy_url = url
                    break
            f.write(f"{original_proxy_url}#{result['latency']:.2f}ms\n")

    logging.info(f"Saved {len(results)} valid proxies to {OUTPUT_SUB_FILE}")

if __name__ == "__main__":
    main()
