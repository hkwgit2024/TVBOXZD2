import os
import requests
import yaml
import csv
import re
from functools import reduce
from ip_geolocation import GeoLite2Country

# 定义文件路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LINKS_FILE = os.path.join(BASE_DIR, 'link.txt')
OUTPUT_YAML = os.path.join(BASE_DIR, 'link.yaml')
OUTPUT_CSV = os.path.join(BASE_DIR, 'link.csv')
GEOLITE_DB = os.path.join(BASE_DIR, 'GeoLite2-Country.mmdb')

# 定义需要尝试的 YAML 文件名
CONFIG_NAMES = ['config.yaml', 'clash_proxies.yaml', 'all.yaml', 'mihomo.yaml']

# 初始化 IP 地理位置解析器
try:
    geolocator = GeoLite2Country(GEOLITE_DB)
except FileNotFoundError:
    print(f"错误: 无法找到地理位置数据库文件 {GEOLITE_DB}。请确保文件已上传到仓库根目录。")
    exit(1)

def get_node_from_url(url, protocol):
    """尝试用指定协议和URL获取节点内容"""
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            print(f"成功连接: {url}")
            return response.text
    except requests.exceptions.RequestException as e:
        print(f"连接失败: {url} ({protocol.upper()}) - {e}")
    return None

def process_links():
    """主函数，处理所有链接并生成最终文件"""
    all_nodes = []
    node_counts = []
    
    with open(LINKS_FILE, 'r') as f:
        links = [line.strip() for line in f if line.strip()]

    for link in links:
        link = link.replace('http://', '').replace('https://', '')
        
        # 尝试 HTTP 连接
        base_url = f"http://{link}"
        node_content = None
        for config in CONFIG_NAMES:
            node_content = get_node_from_url(f"{base_url}/{config}", "http")
            if node_content:
                break
        
        # 如果 HTTP 失败，尝试 HTTPS
        if not node_content:
            base_url = f"https://{link}"
            for config in CONFIG_NAMES:
                node_content = get_node_from_url(f"{base_url}/{config}", "https")
                if node_content:
                    break

        if node_content:
            try:
                # 解析 YAML 内容
                data = yaml.safe_load(node_content)
                nodes = data.get('proxies', [])
                
                # 统计节点数量
                node_counts.append({'url': base_url, 'count': len(nodes)})
                
                # 处理每个节点
                for node in nodes:
                    # 获取 IP 地址
                    ip = re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', node.get('server', ''))
                    
                    if ip:
                        ip = ip.group(0)
                        # 获取地理位置并重命名节点
                        country_code, country_name = geolocator.get_location(ip)
                        if country_name:
                            node['name'] = country_name
                
                all_nodes.extend(nodes)
                
            except yaml.YAMLError as e:
                print(f"解析YAML失败: {base_url} - {e}")
    
    # 根据名称去重并按顺序标记
    unique_nodes = []
    names_count = {}
    for node in all_nodes:
        name = node.get('name')
        if name:
            if name in names_count:
                names_count[name] += 1
                node['name'] = f"{name}_{names_count[name]:02d}"
            else:
                names_count[name] = 1
                
        # 简单去重
        if node not in unique_nodes:
            unique_nodes.append(node)
    
    # 保存去重后的节点到link.yaml
    final_data = {'proxies': unique_nodes}
    with open(OUTPUT_YAML, 'w') as f:
        yaml.dump(final_data, f, allow_unicode=True)
    
    # 保存节点数量到link.csv
    with open(OUTPUT_CSV, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['URL', 'Node Count'])
        for item in node_counts:
            writer.writerow([item['url'], item['count']])

if __name__ == "__main__":
    process_links()
