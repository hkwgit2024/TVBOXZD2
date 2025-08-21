import requests
import yaml
import base64
import io
import os
import csv
from urllib.parse import urlparse

def is_valid_node(line):
    """
    检查一个字符串是否是有效的节点链接。
    """
    valid_protocols = ('vmess://', 'vless://', 'ss://', 'trojan://', 'ssr://')
    return isinstance(line, str) and line.strip().startswith(valid_protocols)

def get_nodes_from_url(url):
    """
    从给定的URL获取并解析节点信息，并处理HTTPS/HTTP回退。
    返回一个元组：(节点列表, 节点数量)
    """
    schemes = ['https://', 'http://']
    
    for scheme in schemes:
        full_url = url
        if not full_url.startswith(('http://', 'https://')):
            full_url = f"{scheme}{url}"
        
        try:
            print(f"正在从 {full_url} 获取数据...")
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(full_url, headers=headers, timeout=15)
            response.raise_for_status()

            nodes = []
            content = response.text
            
            # 尝试解析为YAML
            try:
                config = yaml.safe_load(content)
                if isinstance(config, dict) and 'proxies' in config:
                    yaml_nodes = config['proxies']
                    valid_yaml_nodes = [node for node in yaml_nodes if isinstance(node, dict)]
                    nodes.extend(valid_yaml_nodes)
                    print(f"从 {full_url} 解析了 {len(valid_yaml_nodes)} 个YAML节点。")
                    return nodes, len(nodes)
            except yaml.YAMLError:
                pass

            # 尝试解析为纯文本或Base64编码的行
            lines = content.splitlines()
            for line in lines:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # 尝试Base64解码
                try:
                    decoded_line = base64.b64decode(line.strip().encode('utf-8')).decode('utf-8')
                    if is_valid_node(decoded_line):
                        nodes.append(decoded_line)
                    else:
                        # 如果解码后不是有效节点，尝试直接添加原始行
                        if is_valid_node(line):
                            nodes.append(line)
                except (base64.binascii.Error, UnicodeDecodeError, ValueError):
                    # 如果Base64解码失败，直接检查原始行
                    if is_valid_node(line):
                        nodes.append(line)
            
            print(f"从 {full_url} 解析了 {len(nodes)} 个纯文本/Base64行节点。")
            return nodes, len(nodes)

        except requests.exceptions.RequestException as e:
            print(f"无法从 {full_url} 获取数据: {e}")
            continue
    
    print(f"所有协议都无法从 {url} 获取数据。")
    return [], 0

def get_links_from_local_file(filename="link.txt"):
    """
    从本地文件读取链接列表，并过滤空行和注释行。
    """
    links = []
    if os.path.exists(filename):
        print(f"正在从本地文件 {filename} 读取链接...")
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        links.append(line)
            print(f"从 {filename} 读取了 {len(links)} 个链接。")
        except IOError as e:
            print(f"无法读取文件 {filename}: {e}")
    else:
        print(f"文件 {filename} 不存在。请创建一个包含链接的 {filename} 文件。")
    return links

def save_to_yaml(data, filename='link.yaml'):
    """
    将数据保存到YAML文件。
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            # 使用 `default_flow_style=False` 使输出更易读
            yaml.dump(data, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        print(f"成功将数据保存到 {filename}")
    except IOError as e:
        print(f"无法保存文件 {filename}: {e}")

def save_summary_to_csv(summary_data, filename='link.csv'):
    """
    将节点数量汇总数据保存到CSV文件。
    """
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['link', 'node_count']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for row in summary_data:
                writer.writerow(row)
        print(f"成功将节点数量汇总保存到 {filename}")
    except IOError as e:
        print(f"无法保存文件 {filename}: {e}")

if __name__ == "__main__":
    links = get_links_from_local_file()
    all_nodes = []
    nodes_summary = []

    for link in links:
        nodes, count = get_nodes_from_url(link)
        all_nodes.extend(nodes)
        nodes_summary.append({'link': link, 'node_count': count})
    
    # 对获取到的节点进行去重
    seen_nodes = set()
    unique_nodes = []
    for node in all_nodes:
        if isinstance(node, dict):
            # 将字典转换为字符串进行去重
            node_key = str(yaml.dump(node, sort_keys=True))
        else:
            node_key = node
        
        if node_key not in seen_nodes:
            seen_nodes.add(node_key)
            unique_nodes.append(node)

    # 将去重后的节点保存到YAML
    if unique_nodes:
        save_to_yaml({'proxies': unique_nodes})
    else:
        print("未找到任何有效节点。")

    # 将汇总数据保存到CSV
    if nodes_summary:
        save_summary_to_csv(nodes_summary)
