import yaml
import csv
import time
import requests
import socket
import subprocess
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import multiprocessing

# 配置日志
logging.basicConfig(filename='node_test.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# 二进制文件路径（可通过环境变量覆盖）
BINARY_PATHS = {
    'ss-local': os.getenv('SS_LOCAL_PATH', './bin/ss-local'),
    'xray': os.getenv('XRAY_PATH', './bin/xray'),
    'trojan-go': os.getenv('TROJAN_GO_PATH', './bin/trojan-go'),
    'hysteria': os.getenv('HYSTERIA_PATH', './bin/hysteria')
}

# 检查二进制文件是否存在
def check_binary(binary_name):
    path = BINARY_PATHS.get(binary_name)
    if path and os.path.isfile(path) and os.access(path, os.X_OK):
        return path
    logging.warning(f"{binary_name} 二进制文件不可用，尝试 PATH 或跳过")
    return shutil.which(binary_name)  # 查找 PATH 中的二进制

# 读取 link.yaml
def load_nodes(file_path='link.yaml'):
    with open(file_path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    return data.get('proxies', [])

# 通用延迟测试函数
def test_latency_with_proxy(proxy_config, target_url='https://1.1.1.1', timeout=5, retries=3):
    latencies = []
    status = 'error'
    for _ in range(retries):
        try:
            if 'proxies' in proxy_config:  # 使用 requests 的代理
                response = requests.get(target_url, proxies=proxy_config['proxies'], timeout=timeout)
                if response.status_code in (200, 204):
                    latency = (time.time() - response.request.start) * 1000  # ms
                    latencies.append(latency)
                    status = 'available'
                    break
            elif 'binary' in proxy_config:  # 使用 subprocess
                latency = subprocess_test(proxy_config)
                if latency != float('inf'):
                    latencies.append(latency)
                    status = 'available'
                    break
        except requests.exceptions.Timeout:
            status = 'timeout'
        except Exception as e:
            status = f'error: {str(e)}'
            logging.error(f"测试失败: {proxy_config.get('name', 'unknown')}, 错误: {str(e)}")
    return min(latencies) if latencies else float('inf'), status

# subprocess 测试（v2ray/trojan/hysteria）
def subprocess_test(proxy_config):
    binary = proxy_config['binary']
    config_file = proxy_config['config_file']
    try:
        # 启动代理客户端（示例，需根据实际客户端调整命令）
        proc = subprocess.Popen([binary, '-c', config_file], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        time.sleep(1)  # 等待代理启动
        response = requests.get('https://1.1.1.1', proxies={'http': 'socks5://127.0.0.1:1080', 'https': 'socks5://127.0.0.1:1080'}, timeout=5)
        latency = (time.time() - response.request.start) * 1000
        proc.terminate()
        return latency
    except:
        proc.terminate()
        return float('inf')

# Fallback: ping 测试
def ping_test(server):
    try:
        result = subprocess.run(['ping', '-c', '1', server], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            latency = float(result.stdout.split('time=')[-1].split(' ms')[0])
            return latency
        return float('inf')
    except:
        return float('inf')

# 生成代理配置
def get_proxy_config(node):
    node_type = node.get('type', '').lower()
    server = node.get('server')
    port = node.get('port')
    name = node.get('name', 'unknown')

    if node_type == 'direct':
        return {'name': name, 'latency': 0, 'status': 'direct'}

    elif node_type == 'ss':
        # Shadowsocks
        try:
            import socks  # 需要 pip install pysocks
            proxy_url = f"socks5://{node.get('password')}@{server}:{port}"
            return {'name': name, 'proxies': {'http': proxy_url, 'https': proxy_url}}
        except ImportError:
            logging.warning(f"{name}: pysocks 未安装，使用 ping 测试")
            return {'name': name, 'binary': 'ping', 'server': server}

    elif node_type in ('vmess', 'vless'):
        # VMess/VLESS 使用 Xray
        xray_path = check_binary('xray')
        if not xray_path:
            logging.warning(f"{name}: Xray 未安装，使用 ping 测试")
            return {'name': name, 'binary': 'ping', 'server': server}
        config = {
            "inbounds": [{"port": 1080, "protocol": "socks", "listen": "127.0.0.1"}],
            "outbounds": [{
                "protocol": node_type,
                "settings": {
                    "vnext": [{
                        "address": server,
                        "port": port,
                        "users": [{"id": node.get('uuid'), "security": node.get('cipher', 'auto')}]
                    }]
                },
                "streamSettings": {
                    "network": node.get('network', 'tcp'),
                    "security": 'tls' if node.get('tls') else 'none',
                    "wsSettings": node.get('ws-opts', {}),
                    "realitySettings": node.get('reality-opts', {})
                }
            }]
        }
        config_file = f"temp_{name}_xray.json"
        with open(config_file, 'w') as f:
            yaml.dump(config, f)
        return {'name': name, 'binary': xray_path, 'config_file': config_file}

    elif node_type == 'trojan':
        # Trojan 使用 trojan-go
        trojan_path = check_binary('trojan-go')
        if not trojan_path:
            logging.warning(f"{name}: trojan-go 未安装，使用 ping 测试")
            return {'name': name, 'binary': 'ping', 'server': server}
        config = {
            "run_type": "client",
            "local_addr": "127.0.0.1",
            "local_port": 1080,
            "remote_addr": server,
            "remote_port": port,
            "password": [node.get('password')],
            "ssl": {"sni": node.get('sni', server)}
        }
        config_file = f"temp_{name}_trojan.json"
        with open(config_file, 'w') as f:
            yaml.dump(config, f)
        return {'name': name, 'binary': trojan_path, 'config_file': config_file}

    elif node_type == 'hysteria2':
        # Hysteria2
        hysteria_path = check_binary('hysteria')
        if not hysteria_path:
            logging.warning(f"{name}: hysteria 未安装，使用 ping 测试")
            return {'name': name, 'binary': 'ping', 'server': server}
        config = {
            "server": f"{server}:{port}",
            "auth": node.get('password'),
            "socks5": {"listen": "127.0.0.1:1080"}
        }
        config_file = f"temp_{name}_hysteria.yaml"
        with open(config_file, 'w') as f:
            yaml.dump(config, f)
        return {'name': name, 'binary': hysteria_path, 'config_file': config_file}

    else:
        logging.warning(f"未知协议: {node_type} for {name}")
        return {'name': name, 'binary': 'ping', 'server': server}

# 并发测试
def test_nodes_concurrently(nodes, max_workers=min(10, multiprocessing.cpu_count() * 2)):
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_node = {}
        for node in nodes:
            proxy_config = get_proxy_config(node)
            if proxy_config:
                if proxy_config.get('status') == 'direct':
                    node['latency'] = 0
                    node['status'] = 'direct'
                    results.append(node)
                elif proxy_config.get('binary') == 'ping':
                    future = executor.submit(ping_test, proxy_config['server'])
                    future_to_node[future] = (node, proxy_config['name'])
                else:
                    future = executor.submit(test_latency_with_proxy, proxy_config)
                    future_to_node[future] = (node, proxy_config['name'])
        
        for future in tqdm(as_completed(future_to_node), total=len(future_to_node), desc="测试节点"):
            node, name = future_to_node[future]
            latency, status = future.result() if future_to_node[future][1] != 'direct' else (0, 'direct')
            node['latency'] = latency
            node['status'] = status
            results.append(node)
    
    # 过滤不可用节点
    filtered = [n for n in results if n['status'] == 'available' and n['latency'] < 2000]
    return filtered, results

# 保存结果
def save_results(filtered_nodes, all_results):
    with open('node_test_results.yaml', 'w', encoding='utf-8') as f:
        yaml.dump({'proxies': filtered_nodes}, f, allow_unicode=True)
    logging.info("过滤后节点保存到 node_test_results.yaml")
    
    with open('node_test_results.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Name', 'Type', 'Latency (ms)', 'Status'])
        for node in all_results:
            writer.writerow([node.get('name'), node.get('type'), node.get('latency', 'N/A'), node.get('status', 'N/A')])
    logging.info("统计保存到 node_test_results.csv")

# 清理临时文件
def cleanup_temp_files(nodes):
    for node in nodes:
        name = node.get('name', 'unknown')
        for ext in ['json', 'yaml']:
            temp_file = f"temp_{name}_{ext}"
            if os.path.exists(temp_file):
                os.remove(temp_file)

def main():
    nodes = load_nodes()
    logging.info(f"加载 {len(nodes)} 个节点")
    filtered_nodes, all_results = test_nodes_concurrently(nodes)
    save_results(filtered_nodes, all_results)
    cleanup_temp_files(nodes)
    logging.info("测试完成，临时文件已清理")

if __name__ == "__main__":
    main()
