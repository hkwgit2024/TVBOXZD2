import yaml
import csv
import time
import requests
import socket
import subprocess
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import multiprocessing

# 配置日志
logging.basicConfig(filename='node_test.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# 读取 link.yaml
def load_nodes(file_path='link.yaml'):
    with open(file_path, 'r', encoding='utf-8') as f:
        data = yaml.safe_load(f)
    return data.get('proxies', [])

# 通用延迟测试函数：通过代理访问目标 URL
def test_latency_with_proxy(proxy_config, target_url='https://1.1.1.1', timeout=5, retries=3):
    latencies = []
    status = 'error'
    for _ in range(retries):
        try:
            start = time.time()
            if 'proxies' in proxy_config:  # 对于支持 proxies 的库
                response = requests.get(target_url, proxies=proxy_config['proxies'], timeout=timeout)
                if response.status_code == 200:
                    latency = (time.time() - start) * 1000  # ms
                    latencies.append(latency)
                    status = 'available'
                    break
            else:  # 对于 subprocess 调用
                # 模拟运行代理客户端并测试
                latency = subprocess_test(proxy_config)
                latencies.append(latency)
                status = 'available'
                break
        except requests.exceptions.Timeout:
            status = 'timeout'
        except Exception as e:
            status = f'error: {str(e)}'
            logging.error(f"测试失败: {proxy_config.get('name')}, 错误: {str(e)}")
    return min(latencies) if latencies else float('inf'), status

# subprocess 测试 fallback（对于 v2ray/trojan/hysteria）
def subprocess_test(node):
    # 示例：假设已安装 v2ray/trojan-go/hysteria 客户端
    # 这里用 ping 作为 fallback（不准确，但演示）
    try:
        result = subprocess.run(['ping', '-c', '1', node['server']], capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            latency = float(result.stdout.split('time=')[-1].split(' ms')[0])
            return latency
        return float('inf')
    except:
        return float('inf')

# 根据协议配置代理
def get_proxy_config(node):
    node_type = node.get('type', '').lower()
    server = node.get('server')
    port = node.get('port')
    
    if node_type == 'direct':
        return {'latency': 0, 'status': 'direct'}  # 不测试
    
    elif node_type == 'ss':
        # Shadowsocks: 使用 socks5
        import socks  # 需要 pip install pysocks
        proxy_url = f"socks5://{node.get('password')}@{server}:{port}"
        return {'proxies': {'http': proxy_url, 'https': proxy_url}}
    
    elif node_type == 'vmess' or node_type == 'vless':
        # VMess/VLESS: 使用 v2ray 配置（假设 v2ray 已安装）
        # 生成临时 config.json 并运行 v2ray
        config = {
            "inbounds": [{"port": 1080, "protocol": "socks", "listen": "127.0.0.1"}],
            "outbounds": [{"protocol": node_type, "settings": {"vnext": [{"address": server, "port": port, "users": [{"id": node.get('uuid')}]}]}}]
        }
        with open('temp_v2ray_config.json', 'w') as f:
            yaml.dump(config, f)
        # subprocess.run(['v2ray', 'run', '-c', 'temp_v2ray_config.json'])  # 后台运行
        return {'proxies': {'http': 'socks5://127.0.0.1:1080', 'https': 'socks5://127.0.0.1:1080'}}
    
    elif node_type == 'trojan':
        # Trojan: 类似，使用 trojan-go
        config = {"run_type": "client", "local_addr": "127.0.0.1", "local_port": 1080, "remote_addr": server, "remote_port": port, "password": [node.get('password')]}
        with open('temp_trojan_config.json', 'w') as f:
            yaml.dump(config, f)
        # subprocess.run(['trojan-go', '-config', 'temp_trojan_config.json'])  # 后台
        return {'proxies': {'http': 'socks5://127.0.0.1:1080', 'https': 'socks5://127.0.0.1:1080'}}
    
    elif node_type == 'hysteria2':
        # Hysteria2: 使用 hysteria 客户端
        config = {"server": f"{server}:{port}", "auth": node.get('password'), "socks5": {"listen": "127.0.0.1:1080"}}
        with open('temp_hysteria_config.yaml', 'w') as f:
            yaml.dump(config, f)
        # subprocess.run(['hysteria', '-c', 'temp_hysteria_config.yaml', 'client'])  # 后台
        return {'proxies': {'http': 'socks5://127.0.0.1:1080', 'https': 'socks5://127.0.0.1:1080'}}
    
    else:
        logging.warning(f"未知协议: {node_type}")
        return None

# 并发测试节点
def test_nodes_concurrently(nodes, max_workers=min(10, multiprocessing.cpu_count() * 2)):
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_node = {}
        for node in nodes:
            proxy_config = get_proxy_config(node)
            if proxy_config:
                future = executor.submit(test_latency_with_proxy, proxy_config)
                future_to_node[future] = node
        
        for future in tqdm(as_completed(future_to_node), total=len(future_to_node), desc="测试节点"):
            node = future_to_node[future]
            latency, status = future.result()
            node['latency'] = latency
            node['status'] = status
            results.append(node)
    
    # 过滤不可用节点 (latency > 2000ms 或 error/timeout)
    filtered = [n for n in results if n['status'] == 'available' and n['latency'] < 2000]
    return filtered, results  # 返回过滤后和所有结果

# 保存结果
def save_results(filtered_nodes, all_results):
    # YAML: 更新节点列表
    with open('node_test_results.yaml', 'w', encoding='utf-8') as f:
        yaml.dump({'proxies': filtered_nodes}, f, allow_unicode=True)
    logging.info("过滤后节点保存到 node_test_results.yaml")
    
    # CSV: 统计
    with open('node_test_results.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['Name', 'Type', 'Latency (ms)', 'Status'])
        for node in all_results:
            writer.writerow([node.get('name'), node.get('type'), node.get('latency', 'N/A'), node.get('status', 'N/A')])
    logging.info("统计保存到 node_test_results.csv")

def main():
    nodes = load_nodes()
    logging.info(f"加载 {len(nodes)} 个节点")
    filtered_nodes, all_results = test_nodes_concurrently(nodes)
    save_results(filtered_nodes, all_results)

if __name__ == "__main__":
    main()
