```python
import yaml
import requests
import subprocess
import time
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

def load_yaml(url):
    """从指定 URL 加载 YAML 文件"""
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return yaml.safe_load(response.text)
    except Exception as e:
        print(f"加载 YAML 文件失败: {e}")
        return None

def test_node_latency(node, mihomo_path):
    """测试单个节点的延迟"""
    try:
        # 创建临时配置文件
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
        
        # 启动 mihomo
        process = subprocess.Popen(
            [mihomo_path, '-f', temp_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # 等待 mihomo 启动
        time.sleep(2)
        
        # 测试延迟
        start_time = time.time()
        response = requests.get('http://www.google.com', proxies={
            'http': 'http://localhost:7890',
            'https': 'http://localhost:7890'
        }, timeout=5)
        latency = (time.time() - start_time) * 1000  # 转换为毫秒
        
        # 清理
        process.terminate()
        os.remove(temp_file)
        
        return {'node': node, 'latency': latency}
    except Exception as e:
        print(f"测试节点 {node['name']} 失败: {e}")
        return {'node': node, 'latency': float('inf')}

def main():
    mihomo_path = './mihomo/mihomo-linux-amd64-compatible-v1.19.13'
    yaml_url = 'https://raw.githubusercontent.com/qjlxg/VT/refs/heads/main/link.yaml'
    
    # 加载 YAML 文件
    config = load_yaml(yaml_url)
    if not config or 'proxies' not in config:
        print("无法加载节点列表或节点列表为空")
        return
    
    nodes = config['proxies']
    results = []
    
    # 使用线程池并行测试延迟
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(test_node_latency, node, mihomo_path) for node in nodes]
        for future in futures:
            result = future.result()
            results.append(result)
    
    # 按延迟排序，过滤掉无效节点
    valid_results = [r for r in results if r['latency'] != float('inf')]
    sorted_results = sorted(valid_results, key=lambda x: x['latency'])[:100]
    
    # 生成输出配置文件
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
    
    # 保存到 clash_config.yaml
    with open('clash_config.yaml', 'w', encoding='utf-8') as f:
        yaml.safe_dump(output_config, f, allow_unicode=True)
    
    print(f"已生成 clash_config.yaml，包含 {len(sorted_results)} 个节点")

if __name__ == "__main__":
    main()
```
