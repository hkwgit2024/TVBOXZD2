import os
import requests
import yaml
import csv
import re
import random
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import reduce
from ip_geolocation import GeoLite2Country
from tqdm import tqdm
from bs4 import BeautifulSoup

# 定义文件路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# 将文件名从 'link.txt' 更改为 'found_links.txt'
LINKS_FILE = os.path.join(BASE_DIR, 'found_links.txt')
OUTPUT_YAML = os.path.join(BASE_DIR, 'link.yaml')
OUTPUT_CSV = os.path.join(BASE_DIR, 'link.csv')
GEOLITE_DB = os.path.join(BASE_DIR, 'GeoLite2-Country.mmdb')

# 定义需要尝试的 YAML 文件名
CONFIG_NAMES = ['config.yaml', 'clash_proxies.yaml', 'all.yaml', 'mihomo.yaml']

# 浏览器User-Agent列表，用于伪装请求头
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36'
]

# 辅助函数：根据URL判断是否为有效代理链接
def is_valid_proxy_url(url):
    """根据URL特征判断是否为有效的代理链接"""
    if not url:
        return False
    # 简单的规则，可以根据需要扩展
    return any(name in url.lower() for name in CONFIG_NAMES + ['/subscription', '/sub', '.yaml', '.yml'])

# 辅助函数：尝试下载URL内容，优先使用HTTPS
def fetch_url(url, timeout=10):
    """尝试通过HTTP和HTTPS下载URL内容"""
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    schemes = ['https', 'http']
    for scheme in schemes:
        try:
            full_url = url.replace('http://', f'{scheme}://').replace('https://', f'{scheme}://')
            response = requests.get(full_url, headers=headers, timeout=timeout)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException:
            continue
    return None

def pre_test_links(links):
    """预测试链接，返回可访问的链接"""
    working_links = []
    # 使用线程池来加快预测试速度
    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {executor.submit(fetch_url, link): link for link in links if is_valid_proxy_url(link)}
        for future in tqdm(as_completed(futures), total=len(futures), desc="预测试链接"):
            response = future.result()
            if response:
                working_links.append(response.url)
    return working_links

def fetch_and_parse_yaml(url):
    """从URL下载YAML内容并解析代理节点"""
    nodes = []
    try:
        response = requests.get(url, headers={'User-Agent': random.choice(USER_AGENTS)}, timeout=15)
        response.raise_for_status()
        
        try:
            data = yaml.safe_load(response.text)
            if isinstance(data, dict) and 'proxies' in data:
                nodes.extend(data['proxies'])
        except yaml.YAMLError:
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                # 递归查找子链接
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    full_url = urljoin(url, href)
                    if any(name in full_url for name in CONFIG_NAMES):
                        nodes.extend(fetch_and_parse_yaml(full_url))
            else:
                pass
    except requests.exceptions.RequestException as e:
        # print(f"处理 {url} 失败: {e}")
        pass
    return nodes

def process_links(links):
    """处理链接并提取代理节点"""
    all_nodes = []
    node_counts = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_and_parse_yaml, link): link for link in links}
        for future in tqdm(as_completed(futures), total=len(futures), desc="处理链接"):
            try:
                nodes = future.result()
                if nodes:
                    all_nodes.extend(nodes)
            except Exception as e:
                # print(f"处理链接失败: {e}")
                pass
    
    return all_nodes, node_counts

def main():
    print("脚本开始运行...")
    
    with open(LINKS_FILE, 'r') as f:
        links_to_test = [line.strip() for line in f if line.strip()]

    print("第一阶段：预测试所有链接，优先尝试 HTTPS...")
    working_links = pre_test_links(links_to_test)
    print(f"预测试完成，发现 {len(working_links)} 个可用链接。")
    
    if not working_links:
        print("未发现任何可用的代理链接，脚本结束。")
        return

    print("第二阶段：开始处理可用链接...")
    all_nodes, node_counts = process_links(working_links)
    
    # 统计和去重
    unique_nodes = []
    names_count = {}
    for node in all_nodes:
        # 确保node是字典且包含server和port
        if not isinstance(node, dict) or 'server' not in node or 'port' not in node:
            continue
        
        # 使用GeoLite2进行地理位置命名
        with GeoLite2Country(GEOLITE_DB) as geo:
            try:
                country = geo.get_country_by_ip(node['server'])
                if country:
                    name_prefix = f"{country}_{node.get('type', 'unknown')}"
                    if name_prefix in names_count:
                        names_count[name_prefix] += 1
                        node['name'] = f"{name_prefix}_{names_count[name_prefix]:02d}"
                    else:
                        names_count[name_prefix] = 1
                        node['name'] = name_prefix
            except Exception as e:
                # print(f"地理位置解析失败: {e}")
                pass
        
        # 检查是否已存在
        if node not in unique_nodes:
            unique_nodes.append(node)
    
    # 保存结果
    print("所有链接处理完毕，开始保存文件。")
    final_data = {'proxies': unique_nodes}
    with open(OUTPUT_YAML, 'w', encoding='utf-8') as f:
        yaml.dump(final_data, f, allow_unicode=True)
    print(f"节点已保存到 {OUTPUT_YAML}")
    print(f"共发现 {len(unique_nodes)} 个唯一代理节点。")

if __name__ == "__main__":
    main()
