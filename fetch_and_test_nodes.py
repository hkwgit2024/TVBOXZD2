import requests
import base64
import os
import json
import subprocess
import time
from urllib.parse import urlparse, parse_qs

# 节点来源
SOURCES = [
    "https://sub.freesub.me/link/6b5d6b6b5b5f4b4f",
    "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
]

# 拉取节点
def fetch_nodes_from_url(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        # 尝试 Base64 解码
        try:
            data = base64.b64decode(response.text).decode('utf-8')
        except:
            data = response.text
        nodes = [node.strip() for node in data.splitlines() if node.strip()]
        return nodes
    except Exception as e:
        print(f"Error fetching from {url}: {e}")
        return []

def fetch_all_nodes():
    all_nodes = []
    for source in SOURCES:
        nodes = fetch_nodes_from_url(source)
        all_nodes.extend(nodes)
    return list(set(all_nodes))  # 去重

# 解析节点
def parse_vless_uri(uri):
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

def parse_vmess_uri(uri):
    # 简化示例，需完善
    return {
        "outbounds": [{
            "protocol": "vmess",
            "settings": {
                "vnext": [{"address": "example.com", "port": 443, "users": [{"id": "uuid"}]}]
            }
        }]
    }

def parse_ss_uri(uri):
    # 简化示例，需完善
    return {
        "outbounds": [{
            "protocol": "shadowsocks",
            "settings": {
                "servers": [{"address": "example.com", "port": 8388, "method": "aes-256-gcm", "password": "password"}]
            }
        }]
    }

def parse_node(uri):
    if uri.startswith("vless://"):
        return parse_vless_uri(uri)
    elif uri.startswith("vmess://"):
        return parse_vmess_uri(uri)
    elif uri.startswith("ss://"):
        return parse_ss_uri(uri)
    return None

# 测试下载速度（复用 mullvad_speed_test.py 逻辑）
def test_download_speed(url="http://speedtest.tele2.net/100MB.zip"):
    start_time = time.time()
    try:
        response = requests.get(url, stream=True, timeout=30)
        total_size = 0
        with open("testfile", "wb") as f:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    f.write(chunk)
                    total_size += len(chunk)
        end_time = time.time()
        os.remove("testfile")
        duration = end_time - start_time
        speed_mbps = (total_size * 8 / 1024 / 1024) / duration
        return speed_mbps
    except:
        return 0

# 主逻辑
def run_speed_test():
    nodes = fetch_all_nodes()
    if not nodes:
        print("No nodes fetched")
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
            time.sleep(5)
            
            speed = test_download_speed()
            results.append({"node": node, "speed_mbps": speed, "status": "OK"})
            
            xray_process.terminate()
            os.remove(config_file)
        except Exception as e:
            results.append({"node": node, "speed_mbps": 0, "status": f"Failed: {str(e)}"})
    
    # 保存结果
    with open("results.json", "w") as f:
        json.dump(results, f, ensure_ascii=False, indent=2)
    
    with open("results.md", "w") as f:
        f.write("| Node | Speed (Mbps) | Status |\n")
        f.write("|------|--------------|--------|\n")
        for result in results:
            node_name = result["node"][:50] + "..." if len(result["node"]) > 50 else result["node"]
            f.write(f"| {node_name} | {result['speed_mbps']:.2f} | {result['status']} |\n")

if __name__ == "__main__":
    run_speed_test()
