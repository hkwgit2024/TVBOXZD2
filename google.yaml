import os
import sys
import yaml
import requests
import time
import random
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor
from ip_geolocation import GeoLite2Country

# 定义文件路径和常量
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_YAML = os.path.join(BASE_DIR, 'google.yaml')
GEOLITE_DB = os.path.join(BASE_DIR, 'GeoLite2-Country.mmdb')

# 浏览器User-Agent列表，用于伪装请求头
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0'
]

# 确保 googlesearch-python 已安装
try:
    from googlesearch import search as google_search_lib
except ImportError:
    print("需要安装 'googlesearch-python' 库。请运行 'pip install googlesearch-python'。")
    sys.exit(1)

def perform_google_search(queries, num_results=20, pause_time=2.0):
    """使用谷歌搜索执行查询，并提取结果中的URL。"""
    found_links = set()
    for query in queries:
        print(f"正在执行搜索查询: {query}")
        try:
            for url in google_search_lib(query, num_results=num_results, stop=num_results, pause=pause_time):
                if 'github.com' not in url and 'gitlab.com' not in url and not url.startswith('http://webcache.'):
                    found_links.add(url)
        except Exception as e:
            print(f"搜索查询 '{query}' 失败: {e}")
    return list(found_links)

def fetch_and_parse_yaml(url):
    """
    尝试从URL下载YAML内容，并进行解析。
    如果URL是目录，则解析HTML寻找YAML链接。
    """
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    nodes = []

    try:
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        
        # 尝试直接解析为 YAML
        try:
            data = yaml.safe_load(response.text)
            if isinstance(data, dict) and 'proxies' in data:
                nodes.extend(data['proxies'])
        except yaml.YAMLError:
            # 如果不是 YAML，尝试解析为 HTML
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                # 寻找以 .yaml 或 .yml 结尾的链接
                for a_tag in soup.find_all('a', href=True):
                    href = a_tag['href']
                    if href.endswith(('.yaml', '.yml')):
                        full_url = urljoin(url, href)
                        nodes.extend(fetch_and_parse_yaml(full_url))
            else:
                pass
    except requests.exceptions.RequestException as e:
        print(f"处理 {url} 失败: {e}")
    
    return nodes

def process_links(links):
    """使用多线程处理所有链接，获取代理节点。"""
    all_nodes = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(fetch_and_parse_yaml, link): link for link in links}
        for future in futures:
            try:
                nodes = future.result()
                if nodes:
                    all_nodes.extend(nodes)
            except Exception as e:
                print(f"处理链接失败: {e}")
    
    return all_nodes

def geo_process_nodes(nodes):
    """对节点进行去重和地理位置命名。"""
    unique_nodes = []
    names_count = {}
    
    with GeoLite2Country(GEOLITE_DB) as geo:
        for node in nodes:
            try:
                if 'server' in node:
                    country = geo.get_country_by_ip(node['server'])
                    if country:
                        # 使用国家和节点类型命名
                        name = f"{country}_{node.get('type')}"
                        if name in names_count:
                            names_count[name] += 1
                            node['name'] = f"{name}_{names_count[name]:02d}"
                        else:
                            names_count[name] = 1
                            node['name'] = name
            except Exception as e:
                print(f"地理位置解析失败: {e}")
            
            if node not in unique_nodes:
                unique_nodes.append(node)
                
    return unique_nodes

def save_to_yaml(nodes, filename):
    """将节点保存到YAML文件。"""
    final_data = {'proxies': nodes}
    with open(filename, 'w', encoding='utf-8') as f:
        yaml.dump(final_data, f, allow_unicode=True, default_flow_style=False)
    print(f"已将 {len(nodes)} 个唯一节点保存到 {filename}")

if __name__ == "__main__":
    search_queries = [
        'intitle:"Index of /" "config.yaml" -github -gitlab',
        'inurl:clash "all.yaml" intext:"proxies" -github -gitlab'
    ]
    
    # 1. 执行搜索，获取潜在的URL
    discovered_links = perform_google_search(search_queries, num_results=50)
    
    if discovered_links:
        # 2. 处理所有发现的链接，提取代理节点
        all_nodes = process_links(discovered_links)
        
        if all_nodes:
            # 3. 对节点进行地理位置处理和去重
            unique_nodes = geo_process_nodes(all_nodes)
            
            # 4. 保存到 google.yaml
            save_to_yaml(unique_nodes, OUTPUT_YAML)
        else:
            print("未从发现的链接中找到任何代理节点。")
    else:
        print("未发现任何潜在链接。")
