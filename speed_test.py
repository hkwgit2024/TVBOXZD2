import subprocess
import urllib.parse
import logging
import random
import time
import requests
import json
import os
from urllib.parse import urlparse, parse_qs

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('test_results.log'),
        logging.StreamHandler()
    ]
)

DOWNLOAD_TEST_URL = "https://testfile.org/10MB"
DOWNLOAD_TEST_SIZE = 10_000_000
SAMPLE_SIZE = 63
TIMEOUT = 20
SPEED_THRESHOLD = 1.5  # Mbps

def log_message(level, message):
    getattr(logging, level.lower())(message)

def parse_node_url(node_url):
    try:
        parsed = urlparse(node_url)
        scheme = parsed.scheme.lower()
        if scheme not in ['hysteria2', 'vless', 'trojan', 'vmess']:
            log_message("error", f"Unsupported protocol: {scheme}")
            return None

        if scheme == 'hysteria2':
            params = parse_qs(parsed.query)
            return {
                'protocol': 'hysteria2',
                'host': parsed.hostname,
                'port': int(parsed.port or 443),
                'password': parsed.username,
                'sni': params.get('sni', [''])[0],
                'insecure': params.get('insecure', ['0'])[0] == '1'
            }
        elif scheme == 'vless':
            params = parse_qs(parsed.query)
            return {
                'protocol': 'vless',
                'uuid': parsed.username,
                'host': parsed.hostname,
                'port': int(parsed.port or 443),
                'security': params.get('security', ['none'])[0],
                'sni': params.get('sni', [''])[0],
                'allowInsecure': params.get('allowInsecure', ['0'])[0] == '1',
                'fp': params.get('fp', [''])[0],
                'pbk': params.get('pbk', [''])[0],
                'sid': params.get('sid', [''])[0],
                'type': params.get('type', ['tcp'])[0],
                'flow': params.get('flow', [''])[0],
                'encryption': params.get('encryption', ['none'])[0]
            }
        # 保留原有 trojan 和 vmess 解析逻辑
        # ...
    except Exception as e:
        log_message("error", f"Failed to parse node URL {node_url}: {e}")
        return None

def generate_singbox_config(node, index):
    config = {
        "outbounds": [{
            "type": node['protocol'],
            "tag": "proxy"
        }]
    }
    if node['protocol'] == 'hysteria2':
        config['outbounds'][0].update({
            "server": node['host'],
            "server_port": node['port'],
            "password": node['password'],
            "tls": {
                "enabled": True,
                "server_name": node['sni'],
                "insecure": node['insecure']
            }
        })
    elif node['protocol'] == 'vless':
        config['outbounds'][0].update({
            "server": node['host'],
            "server_port": node['port'],
            "uuid": node['uuid'],
            "tls": {
                "enabled": node['security'] != 'none',
                "server_name": node['sni'],
                "insecure": node['allowInsecure'],
                "reality": {
                    "enabled": node['security'] == 'reality',
                    "public_key": node['pbk'],
                    "short_id": node['sid']
                } if node['security'] == 'reality' else None
            },
            "transport": {
                "type": node['type']
            },
            "flow": node['flow'] if node['flow'] else None
        })
    # 保留原有 trojan 和 vmess 配置生成
    # ...
    config_path = f"configs/singbox_config_{index}.json"
    with open(config_path, 'w') as f:
        json.dump(config, f, indent=2)
    return config_path

def test_download_speed(proxy_url, core_name):
    try:
        proxies = {"http": proxy_url, "https": proxy_url}
        start_time = time.time()
        response = requests.get(
            DOWNLOAD_TEST_URL,
            proxies=proxies,
            timeout=TIMEOUT,
            stream=True
        )
        response.raise_for_status()
        total_downloaded = 0
        for chunk in response.iter_content(chunk_size=8192):
            total_downloaded += len(chunk)
        elapsed = time.time() - start_time
        speed_mbps = (total_downloaded * 8 / 1024 / 1024) / elapsed
        return speed_mbps
    except Exception as e:
        log_message("debug", f"Download test failed: {str(e)}")
        return 0

def test_node(node, index, core_name, core_path):
    config_path = generate_singbox_config(node, index) if core_name == "sing-box" else generate_xray_config(node, index)
    process = None
    try:
        cmd = [core_path, "run", "-c", config_path]
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        time.sleep(2)  # 等待核心启动
        proxy_url = "http://127.0.0.1:8089"
        response = requests.get(proxy_url, timeout=5)
        if response.status_code != 400:  # 400 表明代理正常
            log_message("debug", f"Local proxy test for {core_name}: Status code {response.status_code}")
            return None

        speeds = []
        for i in range(3):
            speed = test_download_speed(proxy_url, core_name)
            if speed > 0:
                speeds.append(speed)
                log_message("info", f"Download test {i+1}/3 for node {index}: {speed:.2f} Mbps")
            else:
                log_message("debug", f"Download test {i+1} failed")
                break
        if speeds:
            avg_speed = sum(speeds) / len(speeds)
            if avg_speed >= SPEED_THRESHOLD:
                return {"latency": 1500, "speed": avg_speed}  # 模拟延迟
    except Exception as e:
        log_message("error", f"{core_name} test failed: {str(e)}")
    finally:
        if process:
            process.terminate()
            process.wait()
            stdout, stderr = process.communicate()
            if stderr:
                log_message("error", f"{core_name} exited with stderr: {stderr}")
    return None

def main():
    os.makedirs("configs", exist_ok=True)
    with open("all_nodes.txt", "r") as f:
        nodes = [line.strip() for line in f if line.strip()]
    sampled_nodes = random.sample(nodes, min(SAMPLE_SIZE, len(nodes)))
    
    success_nodes = []
    failed_nodes = []
    
    for i, node_url in enumerate(sampled_nodes, 1):
        log_message("info", f"Processing node {i}/{len(sampled_nodes)}: {node_url}")
        node = parse_node_url(node_url)
        if not node:
            failed_nodes.append(f"{node_url} | Failed: invalid node format")
            continue
            
        for core, path in [("sing-box", "/usr/local/bin/sing-box"), ("xray", "/usr/local/bin/xray")]:
            result = test_node(node, i, path)
            if result:
                success_nodes.append(f"{node_url} | Latency={result['latency']:.2f}ms | Avg Speed={result['speed']:.2f}Mbps | Core={core}")
                break
            else:
                failed_nodes.append(f"{node_url} | Failed: {core} test failed")
                
    with open("success_nodes.txt", "w") as f:
        f.write("\n".join(success_nodes))
    with open("failed_nodes.txt", "w") as f:
        f.write("\n".join(failed_nodes))

if __name__ == "__main__":
    main()
