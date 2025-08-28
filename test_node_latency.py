import yaml
import requests
import subprocess
import time
import os
import base64
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

def load_yaml(url):
    print(f"开始加载 YAML 文件: {url}")
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        print("YAML 文件加载成功")
        
        nodes = []
        for line in response.text.splitlines():
            line = line.strip()
            if line.startswith('vmess://'):
                try:
                    # 去除前缀并进行 base64 解码
                    vmess_data = base64.b64decode(line[8:]).decode('utf-8')
                    node_dict = json.loads(vmess_data)
                    
                    # 转换 vmess 格式为 mihomo/clash 兼容的 YAML 格式
                    clash_node = {
                        'name': node_dict.get('ps', f"Node_{len(nodes) + 1}"),
                        'type': 'vmess',
                        'server': node_dict.get('add'),
                        'port': int(node_dict.get('port')),
                        'uuid': node_dict.get('id'),
                        'alterId': int(node_dict.get('aid', 0)),
                        'cipher': node_dict.get('scy', 'auto'),
                        'network': node_dict.get('net'),
                        'tls': True if node_dict.get('tls') == 'tls' else False,
                        'udp': True,
                    }
                    if 'host' in node_dict:
                        clash_node['servername'] = node_dict.get('host')
                    if 'path' in node_dict:
                        clash_node['ws-path'] = node_dict.get('path')
                    
                    nodes.append(clash_node)
                    print(f"成功解析节点: {clash_node['name']}")
                    
                except Exception as e:
                    print(f"跳过无效节点配置 (解码失败): {line} - {e}")
            else:
                print(f"跳过无效节点配置 (非 vmess 协议): {line}")

        return {'proxies': nodes}

    except Exception as e:
        print(f"加载 YAML 文件失败: {e}")
        return None

def test_node_latency(node, mihomo_path):
    print(f"开始测试节点: {node['name']}")
    try:
        temp_config = {
            'port': 7890,
            'proxies': [node],
            'proxy-groups': [{
                'name': 'auto',
                'type': 'select',
                'proxies': [node['name']]
            }],
            'rules': ['MATCH,auto']
        }
        
        temp_file = f"temp_config_{node['name']}.yaml"
        with open(temp_file, 'w', encoding='utf-8') as f:
            yaml.safe_dump(temp_config, f, allow_unicode=True)
        
        process = subprocess.Popen(
            [mihomo_path, '-f', temp_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        time.sleep(5)
        
        start_time = time.time()
        response = requests.get('http://www.google.com', proxies={
            'http': 'http://localhost:7890',
            'https': 'http://localhost:7890'
        }, timeout=5)
        latency = (time.time() - start_time) * 1000
        
        stdout, stderr = process.communicate(timeout=5)
        if stderr:
            print(f"节点 {node['name']} mihomo 错误: {stderr}")
        process.terminate()
        os.remove(temp_file)
        
        print(f"节点 {node['name']} 测试完成，延迟: {latency:.2f}ms")
        return {'node': node, 'latency': latency}
    except Exception as e:
        print(f"测试节点 {node['name']} 失败: {e}")
        return {'node': node, 'latency': float('inf')}

def main():
    mihomo_path = './mihomo/mihomo-linux-amd64-compatible-v1.19.13'
    yaml_url = 'https://raw.githubusercontent.com/qjlxg/HA/raw/refs/heads/main/all_unique_nodes.txt'
    
    print("检查 mihomo 可执行文件")
    if not os.path.exists(mihomo_path):
        print(f"错误: mihomo 可执行文件 {mihomo_path} 不存在")
        return
    
    config = load_yaml(yaml_url)
    if not config or 'proxies' not in config:
        print("无法加载节点列表或节点列表为空")
        return
    
    nodes = config['proxies']
    results = []
    
    # 限制只测试前 100 个节点
    nodes_to_test = nodes[:100]
    print(f"开始测试 {len(nodes_to_test)} 个节点的延迟")
    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = [executor.submit(test_node_latency, node, mihomo_path) for node in nodes_to_test]
        for future in futures:
            results.append(future.result())
    
    valid_results = [r for r in results if r['latency'] != float('inf')]
    sorted_results = sorted(valid_results, key=lambda x: x['latency'])[:100]
    
    output_config = {
        'port': 7890,
        'socks-port': 7891,
        'allow-lan': True,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'proxies': [r['node'] for r in sorted_results],
        'proxy-groups': [
            {
                'name': 'auto',
                'type': 'select',
                'proxies': [r['node']['name'] for r in sorted_results]
            }
        ],
        'rules': ['MATCH,auto']
    }
    
    with open('clash_config.yaml', 'w', encoding='utf-8') as f:
        yaml.safe_dump(output_config, f, allow_unicode=True)
    
    print(f"已生成 clash_config.yaml，包含 {len(sorted_results)} 个节点")

if __name__ == "__main__":
    main()
