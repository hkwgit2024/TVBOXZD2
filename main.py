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
GEOIP_DB_PATH = "data/geoip.db"  # 本地 geoip.db 路径
OUTPUT_SUB_FILE = "data/collectSub.txt"
NODES_SOURCES = [
    {
        "url": "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt",
        "type": "plain",
    },
]
MAX_PROXIES = 1000
TEST_URL = "http://www.cloudflare.com"
TIMEOUT_SECONDS = 5
PROXY_PORT = 1080

# 确保输出目录存在
for path in [OUTPUT_SUB_FILE, SINGBOX_LOG_PATH, GEOIP_DB_PATH]:
    dirname = os.path.dirname(path)
    if dirname:
        os.makedirs(dirname, exist_ok=True)

def is_valid_ipv6(addr):
    """验证 IPv6 地址格式"""
    try:
        socket.inet_pton(socket.AF_INET6, addr.strip("[]"))
        return True
    except (socket.error, ValueError):
        return False

def get_proxies():
    """从节点源获取代理列表"""
    proxies = []
    for source in NODES_SOURCES:
        try:
            response = requests.get(source["url"], timeout=10)
            response.raise_for_status()
            if source["type"] == "plain":
                lines = response.text.strip().split("\n")
                for line in lines:
                    if line.startswith(("vmess://", "trojan://", "ss://")):
                        proxies.append(line)
        except requests.RequestException as e:
            logging.error(f"Failed to fetch {source['url']}: {e}")
    return proxies[:MAX_PROXIES]

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
            hostname = parsed.hostname
            if hostname and hostname.startswith("[") and not is_valid_ipv6(hostname):
                raise ValueError(f"Invalid IPv6 address: {hostname}")
            query = urllib.parse.parse_qs(parsed.query)
            return {
                "type": "trojan",
                "tag": query.get("name", ["trojan-node"])[0] or "trojan-node",
                "server": hostname,
                "server_port": int(parsed.port or 443),
                "password": parsed.netloc.split("@")[0],
                "tls": {
                    "enabled": True,
                    "server_name": query.get("sni", [""])[0],
                    "insecure": query.get("allowInsecure", ["0"])[0] == "1",
                },
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
                "tag": parsed.fragment or "ss-node",
                "server": hostname,
                "server_port": int(port),
                "method": method,
                "password": password,
            }

        else:
            logging.warning(f"Unsupported scheme: {scheme}")
            return None

    except Exception as e:
        logging.error(f"Failed to decode proxy {proxy_url}: {e}")
        return None

def generate_singbox_config(proxy):
    """生成 sing-box 配置文件"""
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
                "path": GEOIP_DB_PATH,  # 指定本地 geoip.db
                "download_url": "https://github.com/SagerNet/sing-geoip/releases/download/2025.05.20/geoip.db",
                "download_detour": "direct",
            },
            "rules": [
                {
                    "domain": ["www.cloudflare.com"],
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

def test_proxy(proxy):
    """测试代理节点速度"""
    try:
        config_path = generate_singbox_config(proxy)
        # 验证配置
        result = subprocess.run([SINGBOX_BIN_PATH, "check", "-c", config_path], capture_output=True, text=True)
        if result.returncode != 0:
            logging.error(f"Invalid sing-box config: {result.stderr}")
            return None

        process = subprocess.Popen(
            [SINGBOX_BIN_PATH, "run", "-c", config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        time.sleep(5)  # 增加等待时间

        # 检查 sing-box 是否运行
        if process.poll() is not None:
            stderr = process.stderr.read()
            logging.error(f"sing-box failed to start: {stderr}")
            return None

        start_time = time.time()
        response = requests.get(
            TEST_URL,
            proxies={"http": f"http://127.0.0.1:{PROXY_PORT}", "https": f"http://127.0.0.1:{PROXY_PORT}"},
            timeout=TIMEOUT_SECONDS,
        )
        latency = (time.time() - start_time) * 1000  # 毫秒
        process.terminate()
        process.wait(timeout=5)

        if response.status_code == 200:
            return {"proxy": proxy, "latency": latency}
        else:
            logging.warning(f"Proxy {proxy['tag']} failed with status {response.status_code}")
            return None

    except (requests.RequestException, subprocess.SubprocessError) as e:
        logging.error(f"Proxy {proxy.get('tag', 'unknown')} test failed: {e}")
        return None
    finally:
        try:
            process.terminate()
            process.wait(timeout=5)
        except:
            pass

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
            result = test_proxy(proxy)
            if result:
                results.append(result)

    # 按延迟排序并保存结果
    results.sort(key=lambda x: x["latency"])
    with open(OUTPUT_SUB_FILE, "w") as f:
        for result in results:
            proxy_tag = result["proxy"]["tag"]
            proxy_url = next((url for url in proxies if proxy_tag in url), proxy_tag)
            f.write(f"{proxy_url}#{result['latency']:.2f}ms\n")

    logging.info(f"Saved {len(results)} valid proxies to {OUTPUT_SUB_FILE}")

if __name__ == "__main__":
    main()
