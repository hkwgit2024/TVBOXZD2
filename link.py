import requests
import yaml
import base64
import io
import os
import csv
from urllib.parse import urlparse

def get_nodes_from_url(url):
    """
    从给定的URL获取并解析节点信息，并处理HTTPS/HTTP回退。
    返回一个元组：(节点列表, 节点数量)
    """
    schemes = ['https://', 'http://']
    
    for scheme in schemes:
        full_url = url
        # 确保URL以正确的协议开头
        if not full_url.startswith(scheme):
            full_url = f"{scheme}{url}"
        
        try:
            print(f"正在从 {full_url} 获取数据...")
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(full_url, headers=headers, timeout=10)
            response.raise_for_status()  # 检查请求是否成功

            nodes = []
            content = response.text
            
            # 尝试解析为YAML
            try:
                config = yaml.safe_load(content)
                if isinstance(config, dict) and 'proxies' in config:
                    nodes.extend(config['proxies'])
                    print(f"从 {full_url} 解析了 {len(config['proxies'])} 个YAML节点。")
                    return nodes, len(nodes)
            except yaml.YAMLError:
                pass

            # 尝试解析为纯文本，每行一个base64编码的节点
            try:
                decoded_content = base64.b64decode(content.strip().replace('-', '+').replace('_', '/')).decode('utf-8', errors='ignore')
                for line in decoded_content.splitlines():
                    if line.strip():
                        nodes.append(line.strip())
                print(f"从 {full_url} 解析了 {len(nodes)} 个Base64编码的节点。")
                return nodes, len(nodes)
            except (base64.binascii.Error, UnicodeDecodeError, ValueError):
                pass
                
            # 尝试将纯文本作为base64编码的行
            lines = content.splitlines()
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                
                if line.startswith(('vmess://', 'vless://', 'ss://', 'trojan://', 'ssr://')):
                    nodes.append(line)
                else:
                    try:
                        decoded_line = base64.b64decode(line).decode('utf-8')
                        if decoded_line.startswith(('vmess://', 'vless://', 'ss://', 'trojan://', 'ssr://')):
                            nodes.append(decoded_line)
                    except (base64.binascii.Error, UnicodeDecodeError, ValueError):
                        pass
            print(f"从 {full_url} 解析了 {len(nodes)} 个纯文本/Base64行节点。")
            return nodes, len(nodes)

        except requests.exceptions.RequestException as e:
            print(f"无法从 {full_url} 获取数据: {e}")
            continue # 继续尝试下一个协议
    
    # 如果两个协议都失败，返回空列表和0
    print(f"所有协议都无法从 {url} 获取数据。")
    return [], 0


def get_links_from_local_file(filename="link.txt"):
    """
    从本地文件读取链接列表。
    """
    links = []
    if os.path.exists(filename):
        print(f"正在从本地文件 {filename} 读取链接...")
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
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
            yaml.dump(data, f, allow_unicode=True, sort_keys=False)
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
    domains = []
    nodes_summary = []

    for link in links:
        # 检查链接是否是完整的URL（包含协议头）
        parsed_url = urlparse(link)
        if parsed_url.scheme and parsed_url.netloc:
            # 如果是完整的URL，直接处理
            nodes, count = get_nodes_from_url(link)
            all_nodes.extend(nodes)
            nodes_summary.append({'link': link, 'node_count': count})
        else:
            # 如果不包含协议头，则尝试HTTPS/HTTP回退
            nodes, count = get_nodes_from_url(link)
            if count > 0:
                # 如果找到节点，将其添加到列表中
                all_nodes.extend(nodes)
                nodes_summary.append({'link': link, 'node_count': count})
            else:
                # 如果没有找到节点，将其视为纯域名
                domains.append(link)
                nodes_summary.append({'link': link, 'node_count': 0})
    
    # 步骤1：对获取到的节点进行去重
    seen = set()
    unique_nodes = []
    for node in all_nodes:
        if isinstance(node, dict):
            node_key = str(yaml.dump(node, sort_keys=True))
        else:
            node_key = str(node)

        if node_key not in seen:
            seen.add(node_key)
            unique_nodes.append(node)
    
    # 步骤2：对域名列表进行去重
    unique_domains = list(set(domains))

    # 步骤3：将所有数据组织到一个字典中并保存到YAML
    final_data = {}
    if unique_nodes:
        final_data['proxies'] = unique_nodes
    if unique_domains:
        final_data['domains'] = unique_domains
    
    if final_data:
        save_to_yaml(final_data)
    else:
        print("未找到任何节点或域名。")

    # 步骤4：将汇总数据保存到CSV
    if nodes_summary:
        save_summary_to_csv(nodes_summary)
