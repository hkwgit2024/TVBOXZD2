#!/usr/bin/env python3

import requests
import base64
import os
import json
import subprocess
import time
import logging
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import speedtest
from typing import List, Dict

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('node_speed_test.log')
    ]
)
logger = logging.getLogger(__name__)

# 节点来源
SOURCES = [
    "https://sub.freesub.me/link/6b5d6b6b5b5f4b4f",
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
]

# 拉取节点
def fetch_nodes_from_url(url: str) -> List[str]:
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        # 尝试 Base64 解码
        try:
            data = base64.b64decode(response.text).decode('utf-8')
        except:
            data = response.text
        nodes = [node.strip() for node in data.splitlines() if node.strip()]
        logger.info(f"Fetched {len(nodes)} nodes from {url}")
        return nodes
    except Exception as e:
        logger.error(f"Error fetching from {url}: {e}")
        return []

def fetch_all_nodes() -> List[str]:
    all_nodes = []
    for source in SOURCES:
        nodes = fetch_nodes_from_url(source)
        all_nodes.extend(nodes)
    return list(set(all_nodes))  # 去重

# 解析节点
def parse_vless_uri(uri: str) -> Dict:
    parsed = urlparse(uri)
    uuid = parsed.username
    host = parsed.hostname
    port = parsed.port
    params = parse_qs(parsed.query)
    return {
        "outbounds": [{
            "protocol": "vless",
            "settings": {
                "vnext": [{"address": host, "port": int(port), "users": [{"id": uuid}]}]
            },
            "streamSettings": {
                "network": params.get("type", ["tcp"])[0],
                "security": params.get("security", ["none"])[0],
            }
        }]
    }

def parse_vmess_uri(uri: str) -> Dict:
    try:
        data = json.loads(base64.b64decode(uri[8:]).decode('utf-8'))
        return {
            "outbounds": [{
                "protocol": "vmess",
                "settings": {
                    "vnext": [{
                        "address": data["add"],
                        "port": int(data["port"]),
                        "users": [{"id": data["id"]}]
                    }]
                },
                "streamSettings": {
                    "network": data.get("net", "tcp"),
                    "security": data.get("tls", "none"),
                }
            }]
        }
    except Exception as e:
        logger.error(f"Error parsing VMess URI: {e}")
        return None

def parse_ss_uri(uri: str) -> Dict:
    try:
        # ss://method:password@host:port#name
        auth = base64.b64decode(uri[5:].split('#')[0]).decode('utf-8')
        method, rest = auth.split(':')
        password, server = rest.split('@')
        host, port = server.split(':')
        return {
            "outbounds": [{
                "protocol": "shadowsocks",
                "settings": {
                    "servers": [{
                        "address": host,
                        "port": int(port),
                        "method": method,
                        "password": password
                    }]
                }
            }]
        }
    except Exception as e:
        logger.error(f"Error parsing SS URI: {e}")
        return None

def parse_node(uri: str) -> Dict:
    if uri.startswith("vless://"):
        return parse_vless_uri(uri)
    elif uri.startswith("vmess://"):
        return parse_vmess_uri(uri)
    elif uri.startswith("ss://"):
        return parse_ss_uri(uri)
    return None

# 运行 speedtest（复用 mullvad_speed_test.py 逻辑）
def run_speedtest() -> Dict:
    try:
        logger.info("Running speedtest...")
        s = speedtest.Speedtest()
        s.get_best_server()
        download_speed = s.download() / 1_000_000  # Mbps
        upload_speed = s.upload() / 1_000_000      # Mbps
        results = s.results.dict()
        return {
            "download_speed": download_speed,
            "upload_speed": upload_speed,
            "ping": results.get('ping', 0),
            "jitter": results.get('jitter', 0),
            "packet_loss": results.get('packetLoss', 0)
        }
    except Exception as e:
        logger.error(f"Error running speedtest: {e}")
        return {
            "download_speed": 0,
            "upload_speed": 0,
            "ping": 0,
            "jitter": 0,
            "packet_loss": 100
        }

# 主测试逻辑
def run_speed_test():
    nodes = fetch_all_nodes()
    if not nodes:
        logger.error("No nodes fetched")
        return
    
    results = []
    for node in nodes[:10]:  # 限制 10 个节点
        try:
            config = parse_node(node)
            if not config:
                results.append({"node": node, "speed_mbps": 0, "status": "Unsupported protocol"})
                continue
            
            config_file = "temp_config.json"
            with open(config_file, "w") as f:
                json.dump(config, f)
            
            xray_process = subprocess.Popen(["xray", "-c", config_file])
            time.sleep(5)  # 等待连接
            
            speed_result = run_speedtest()
            results.append({
                "node": node,
                "speed_mbps": speed_result["download_speed"],
                "upload_mbps": speed_result["upload_speed"],
                "ping_ms": speed_result["ping"],
                "status": "OK"
            })
            
            xray_process.terminate()
            os.remove(config_file)
        except Exception as e:
            results.append({"node": node, "speed_mbps": 0, "status": f"Failed: {str(e)}"})
    
    # 保存结果
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    with open(f"results_{timestamp}.json", "w") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    
    with open(f"results_{timestamp}.md", "w") as f:
        f.write("| Node | Download (Mbps) | Upload (Mbps) | Ping (ms) | Status |\n")
        f.write("|------|-----------------|---------------|-----------|--------|\n")
        for result in results:
            node_name = result["node"][:50] + "..." if len(result["node"]) > 50 else result["node"]
            f.write(f"| {node_name} | {result['speed_mbps']:.2f} | {result['upload_mbps']:.2f} | {result['ping_ms']:.2f} | {result['status']} |\n")

if __name__ == "__main__":
    run_speed_test()
