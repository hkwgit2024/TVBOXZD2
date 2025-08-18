import os
import requests
import yaml
import csv
import re
import random
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import reduce
from ip_geolocation import GeoLite2Country
from tqdm import tqdm

# 定义文件路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LINKS_FILE = os.path.join(BASE_DIR, 'link.txt')
OUTPUT_YAML = os.path.join(BASE_DIR, 'link.yaml')
OUTPUT_CSV = os.path.join(BASE_DIR, 'link.csv')
GEOLITE_DB = os.path.join(BASE_DIR, 'GeoLite2-Country.mmdb')

# 定义需要尝试的 YAML 文件名
CONFIG_NAMES = ['config.yaml', 'clash_proxies.yaml', 'all.yaml', 'mihomo.yaml']

# 浏览器User-Agent列表，用于伪装请求头
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/61.0.3163.100 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/62.0.3202.94 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36',
]

# 初始化 IP 地理位置解析器
try:
    geolocator = GeoLite2Country(GEOLITE_DB)
    print("GeoLite2-Country 数据库加载成功。")
except FileNotFoundError:
    print(f"错误: 无法找到地理位置数据库文件 {GEOLITE_DB}。请确保文件已上传到仓库根目录。")
    exit(1)

def get_headers():
    return {'User-Agent': random.choice(USER_AGENTS)}

def test_connection(link):
    """预测试一个链接的连通性"""
    link = link.replace('http://', '').replace('https://', '')
    
    # 尝试 HTTP
    try:
        requests.head(f"http://{link}", headers=get_headers(), timeout=5)
        return link
    except requests.exceptions.RequestException:
        pass
    
    # 如果 HTTP 失败，尝试 HTTPS
    try:
        requests.head(f"https://{link}", headers=get_headers(), timeout=5)
        return link
    except requests.exceptions.RequestException:
        pass
        
    return None

def pre_test_links(links):
    """并发预测试所有链接，返回可用的链接列表"""
    working_links = []
    with ThreadPoolExecutor(max_workers=30) as executor:
        future_to_link = {executor.submit(test_connection, link): link for link in links}
        for future in tqdm(as_completed(future_to_link), total=len(links), desc="预测试链接"):
            result = future.result()
            if result:
                working_links.append(result)
    return working_links

def get_node_from_url(link, config_name):
    """尝试用指定协议和URL获取节点内容"""
    headers = get_headers()
    url_with_config = f"{link}/{config_name}"
    
    # 尝试 HTTP
    try:
        response = requests.get(f"http://{url_with_config}", headers=headers, timeout=5)
        if response.status_code == 200:
            return response.text, f"http://{url_with_config}"
    except requests.exceptions.RequestException:
        pass

    # 如果 HTTP 失败，尝试 HTTPS
    try:
        response = requests.get(f"https://{url_with_config}", headers=headers, timeout=5)
        if response.status_code == 200:
            return response.text, f"https://{url_with_config}"
    except requests.exceptions.RequestException:
        pass

    return None, None

def process_links(links):
    """第二阶段：处理可用的链接"""
    all_nodes = []
    node_counts = []
    
    with ThreadPoolExecutor(max_workers=20) as executor:
        # 提交所有任务
        future_to_link = {executor.submit(get_node_from_url, link, config): (link, config) for link in links for config in CONFIG_NAMES}
        
        # 使用 tqdm 封装 as_completed
        for future in tqdm(as_completed(future_to_link), total=len(links) * len(CONFIG_NAMES), desc="获取节点内容"):
            nodes_text, successful_url = future.result()
            if nodes_text:
                try:
                    data = yaml.safe_load(nodes_text)
                    nodes = data.get('proxies', [])
                    
                    # 处理每个节点，添加地理位置信息
                    for node in nodes:
                        ip = re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', node.get('server', ''))
                        if ip:
                            ip = ip.group(0)
                            country_code, country_name = geolocator.get_location(ip)
                            if country_name:
                                node['name'] = country_name
                    
                    all_nodes.extend(nodes)
                    node_counts.append({'url': successful_url, 'count': len(nodes)})
                except yaml.YAMLError:
                    pass
    
    return all_nodes, node_counts

def main():
    print("脚本开始运行...")
    
    with open(LINKS_FILE, 'r') as f:
        links_to_test = [line.strip() for line in f if line.strip()]

    # 第一阶段：预测试
    print("第一阶段：预测试所有链接...")
    working_links = pre_test_links(links_to_test)
    print(f"预测试完成，发现 {len(working_links)} 个可用链接。")
    
    # 第二阶段：处理可用的链接
    print("第二阶段：开始处理可用链接...")
    all_nodes, node_counts = process_links(working_links)
    
    # 统计和去重
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
        
        if node not in unique_nodes:
            unique_nodes.append(node)
    
    # 保存结果
    print("所有链接处理完毕，开始保存文件。")
    final_data = {'proxies': unique_nodes}
    with open(OUTPUT_YAML, 'w', encoding='utf-8') as f:
        yaml.dump(final_data, f, allow_unicode=True)
    print(f"节点已保存到 {OUTPUT_YAML}")
    
    with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(['URL', 'Node Count'])
        for item in node_counts:
            writer.writerow([item['url'], item['count']])
    print(f"统计信息已保存到 {OUTPUT_CSV}")
    print("脚本运行结束。")

if __name__ == "__main__":
    main()
