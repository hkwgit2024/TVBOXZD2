import yaml
import requests
import subprocess
import time
import os
import base64
import json
import urllib.parse
import re
import maxminddb
import socket
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict

def sanitize_filename(name):
    """移除或替换文件名中的非法字符"""
    sanitized = re.sub(r'[\\/:*?"<>| ]', '_', name)
    # 限制文件名长度，避免系统限制
    return sanitized[:100]

def get_country_name(ip):
    """根据 IP 地址获取国家名称"""
    try:
        with maxminddb.open_database('./GeoLite2-Country.mmdb') as reader:
            match = reader.get(ip)
            if match and 'country' in match and 'names' in match['country'] and 'zh-CN' in match['country']['names']:
                return match['country']['names']['zh-CN']
            elif match and 'country' in match and 'names' in match['country'] and 'en' in match['country']['names']:
                return match['country']['names']['en']
    except Exception as e:
        print(f"GeoLite2 数据库查询失败: {e}")
    return "Unknown"

def load_yaml(url):
    print(f"开始加载 YAML 文件: {url}")
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        content = response.text
        print("YAML 文件加载成功")
        
        nodes = []
        
        # 尝试作为完整的YAML文件解析
        try:
            full_config = yaml.safe_load(content)
            if full_config and 'proxies' in full_config:
                print("成功解析为完整的 Clash YAML 格式")
                return {'proxies': full_config['proxies']}
        except yaml.YAMLError:
            print("无法作为完整的 YAML 文件解析，尝试逐行解析")
        
        # 如果不是完整的YAML文件，则尝试逐行解析订阅链接
        for line in content.splitlines():
            line = line.strip()
            if not line:
                continue

            try:
                if line.startswith('vmess://'):
                    # 处理 VMess
                    vmess_data = base64.b64decode(line[8:]).decode('utf-8')
                    node_dict = json.loads(vmess_data)
                    
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
                    print(f"成功解析 VMess 节点: {clash_node['name']}")
                
                elif line.startswith('ss://'):
                    # 处理 Shadowsocks
                    parsed_url = urllib.parse.urlparse(line)
                    if not parsed_url.fragment:
                        print(f"跳过无效 SS 节点 (缺少名称): {line}")
                        continue
                    
                    base64_data = parsed_url.netloc
                    
                    try:
                        decoded_data = base64.b64decode(base64_data + '=' * (-len(base64_data) % 4)).decode('utf-8')
                        method, password_and_server = decoded_data.split(':', 1)
                        password, server_and_port = password_and_server.split('@', 1)
                    except:
                        password_and_server = base64_data
                        method = 'auto'
                        password, server_and_port = password_and_server.split('@', 1)
                    
                    server, port = server_and_port.split(':', 1)

                    clash_node = {
                        'name': urllib.parse.unquote(parsed_url.fragment),
                        'type': 'ss',
                        'server': server,
                        'port': int(port),
                        'password': password,
                        'cipher': method,
                        'udp': True,
                    }
                    nodes.append(clash_node)
                    print(f"成功解析 SS 节点: {clash_node['name']}")
                    
                elif line.startswith('hy2://'):
                    # 处理 Hysteria 2
                    parsed_url = urllib.parse.urlparse(line)
                    if not parsed_url.fragment:
                        print(f"跳过无效 HY2 节点 (缺少名称): {line}")
                        continue
                        
                    server, port = parsed_url.netloc.split(':', 1)
                    
                    clash_node = {
                        'name': urllib.parse.unquote(parsed_url.fragment),
                        'type': 'hysteria2',
                        'server': server,
                        'port': int(port),
                        'auth': parsed_url.username,
                        'udp': True,
                    }
                    
                    query_params = urllib.parse.parse_qs(parsed_url.query)
                    if 'obfs' in query_params:
                        clash_node['obfs'] = query_params['obfs'][0]
                    if 'obfs-password' in query_params:
                        clash_node['obfs-password'] = query_params['obfs-password'][0]
                    if 'sni' in query_params:
                        clash_node['tls'] = True
                        clash_node['sni'] = query_params['sni'][0]
                    
                    nodes.append(clash_node)
                    print(f"成功解析 HY2 节点: {clash_node['name']}")

                elif line.startswith('trojan://'):
                    # 处理 Trojan
                    parsed_url = urllib.parse.urlparse(line)
                    if not parsed_url.fragment:
                        print(f"跳过无效 Trojan 节点 (缺少名称): {line}")
                        continue
                    
                    clash_node = {
                        'name': urllib.parse.unquote(parsed_url.fragment),
                        'type': 'trojan',
                        'server': parsed_url.hostname,
                        'port': parsed_url.port,
                        'password': parsed_url.username,
                        'udp': True,
                    }
                    
                    query_params = urllib.parse.parse_qs(parsed_url.query)
                    if 'sni' in query_params:
                        clash_node['sni'] = query_params['sni'][0]
                    if 'alpn' in query_params:
                        clash_node['alpn'] = query_params['alpn'][0]
                    if 'allowInsecure' in query_params:
                        clash_node['skip-cert-verify'] = True
                    
                    nodes.append(clash_node)
                    print(f"成功解析 Trojan 节点: {clash_node['name']}")
                    
                elif line.startswith('vless://'):
                    # 处理 VLESS
                    parsed_url = urllib.parse.urlparse(line)
                    if not parsed_url.fragment:
                        print(f"跳过无效 VLESS 节点 (缺少名称): {line}")
                        continue
                    
                    clash_node = {
                        'name': urllib.parse.unquote(parsed_url.fragment),
                        'type': 'vless',
                        'server': parsed_url.hostname,
                        'port': parsed_url.port,
                        'uuid': parsed_url.username,
                        'udp': True,
                    }
                    
                    query_params = urllib.parse.parse_qs(parsed_url.query)
                    if 'encryption' in query_params:
                        clash_node['cipher'] = query_params['encryption'][0]
                    if 'security' in query_params and query_params['security'][0] == 'tls':
                        clash_node['tls'] = True
                    if 'sni' in query_params:
                        clash_node['servername'] = query_params['sni'][0]
                    if 'flow' in query_params:
                        clash_node['flow'] = query_params['flow'][0]
                    if 'network' in query_params:
                        clash_node['network'] = query_params['network'][0]
                        if clash_node['network'] == 'ws':
                            if 'path' in query_params:
                                clash_node['ws-path'] = query_params['path'][0]
                            if 'host' in query_params:
                                clash_node['ws-headers'] = {'Host': query_params['host'][0]}

                    nodes.append(clash_node)
                    print(f"成功解析 VLESS 节点: {clash_node['name']}")
                    
                else:
                    print(f"跳过无效节点配置 (协议不支持): {line}")

            except Exception as e:
                print(f"解析节点失败: {line} - {e}")
                
        return {'proxies': nodes}

    except Exception as e:
        print(f"加载 YAML 文件失败: {e}")
        return None

def test_node_latency(node, mihomo_path):
    print(f"开始测试节点: {node['name']}")
    process = None
    temp_file = None
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
        
        sanitized_name = sanitize_filename(node['name'])
        temp_file = f"temp_config_{sanitized_name}.yaml"
        
        with open(temp_file, 'w', encoding='utf-8') as f:
            yaml.safe_dump(temp_config, f, allow_unicode=True)
        
        process = subprocess.Popen(
            [mihomo_path, '-f', temp_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        time.sleep(10)
        
        start_time = time.time()
        response = requests.get('http://www.google.com', proxies={
            'http': 'http://localhost:7890',
            'https': 'http://localhost:7890'
        }, timeout=5)
        latency = (time.time() - start_time) * 1000
        
        stdout, stderr = process.communicate(timeout=5)
        if stderr:
            print(f"节点 {node['name']} mihomo 错误: {stderr}")
        
        print(f"节点 {node['name']} 测试完成，延迟: {latency:.2f}ms")
        return {'node': node, 'latency': latency}
    except Exception as e:
        print(f"测试节点 {node['name']} 失败: {e}")
        return {'node': node, 'latency': float('inf')}
    finally:
        if process and process.poll() is None:
            print(f"正在终止进程: {process.pid}")
            process.terminate()
            time.sleep(1)
            if process.poll() is None:
                print(f"强制杀死进程: {process.pid}")
                process.kill()
        if temp_file and os.path.exists(temp_file):
            os.remove(temp_file)

def main():
    mihomo_path = './mihomo/mihomo-linux-amd64-compatible-v1.19.13'
    yaml_url = 'https://raw.githubusercontent.com/qjlxg/HA/refs/heads/main/link.yaml'
    
    print("检查 mihomo 可执行文件")
    if not os.path.exists(mihomo_path):
        print(f"错误: mihomo 可执行文件 {mihomo_path} 不存在")
        return
    
    if not os.path.exists('./GeoLite2-Country.mmdb'):
        print("错误: GeoLite2-Country.mmdb 文件不存在。请将其放在脚本的同一目录下。")
        return

    config = load_yaml(yaml_url)
    if not config or 'proxies' not in config:
        print("无法加载节点列表或节点列表为空")
        return
    
    nodes = config['proxies']
    
    country_counts = defaultdict(int)
    for node in nodes:
        server = node.get('server')
        if server and isinstance(server, str):
            # 尝试解析域名
            try:
                ip_address = socket.gethostbyname(server)
                country = get_country_name(ip_address)
            except (socket.gaierror, UnicodeError):
                country = "Unknown"
        else:
            country = "Unknown"
            
        country_counts[country] += 1
        node['name'] = f"{country}-{country_counts[country]}"
        print(f"节点已重命名为: {node['name']}")

    results = []
    nodes_to_test = nodes[:3505]
    print(f"开始测试 {len(nodes_to_test)} 个节点的延迟")
    
    with ThreadPoolExecutor(max_workers=10) as executor:
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
