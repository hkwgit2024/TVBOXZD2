import requests
import yaml
import base64
import io
import os
from urllib.parse import urlparse

def get_nodes_from_url(url):
    """
    从给定的URL获取并解析节点信息。
    """
    try:
        print(f"正在从 {url} 获取数据...")
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # 检查请求是否成功

        nodes = []
        content = response.text
        
        # 尝试解析为YAML
        try:
            config = yaml.safe_load(content)
            if isinstance(config, dict) and 'proxies' in config:
                nodes.extend(config['proxies'])
                print(f"从 {url} 解析了 {len(config['proxies'])} 个YAML节点。")
                return nodes
        except yaml.YAMLError:
            pass

        # 尝试解析为纯文本，每行一个base64编码的节点
        try:
            decoded_content = base64.b64decode(content.strip().replace('-', '+').replace('_', '/')).decode('utf-8')
            for line in decoded_content.splitlines():
                if line.strip():
                    nodes.append(line.strip())
            print(f"从 {url} 解析了 {len(nodes)} 个Base64编码的节点。")
            return nodes
        except (base64.binascii.Error, UnicodeDecodeError):
            pass
            
        # 尝试将纯文本作为base64编码的行
        lines = content.splitlines()
        for line in lines:
            if line.strip().startswith(('vmess://', 'vless://', 'ss://', 'trojan://', 'ssr://')):
                nodes.append(line.strip())
            else:
                try:
                    decoded_line = base64.b64decode(line.strip()).decode('utf-8')
                    if decoded_line.strip().startswith(('vmess://', 'vless://', 'ss://', 'trojan://', 'ssr://')):
                        nodes.append(decoded_line.strip())
                except (base64.binascii.Error, UnicodeDecodeError):
                    pass
        print(f"从 {url} 解析了 {len(nodes)} 个纯文本/Base64行节点。")
        return nodes

    except requests.exceptions.RequestException as e:
        print(f"无法从 {url} 获取数据: {e}")
        return []

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

if __name__ == "__main__":
    links = get_links_from_local_file()

    all_nodes = []
    domains = []

    for link in links:
        # 检查链接是否是完整的URL
        parsed_url = urlparse(link)
        if parsed_url.scheme and parsed_url.netloc:
            # 如果是URL，则尝试获取节点
            all_nodes.extend(get_nodes_from_url(link))
        else:
            # 如果不是URL，则认为是域名
            domains.append(link)

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
