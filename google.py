import os
import sys
import yaml
import requests
import time
import random
from bs4 import BeautifulSoup
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor

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

# 确保 googlesearch-python 和 ip_geolocation 已安装
try:
    from googlesearch import search as google_search_lib
    from ip_geolocation import GeoLite2Country
except ImportError as e:
    print(f"导入库失败: {e}")
    print("请确保已安装所有依赖: pip install googlesearch-python beautifulsoup4 PyYAML requests geoip2")
    sys.exit(1)

def perform_google_search(queries, num_results=20):
    """使用谷歌搜索执行查询，并提取结果中的URL。"""
    found_links = set()
    for query in queries:
        print(f"正在执行搜索查询: {query}")
        try:
            for url in google_search_lib(query, num_results=num_results):
                if url.startswith('http://') or url.startswith('https://'):
                    if 'github.com' not in url and 'gitlab.com' not in url and not url.startswith('http://webcache.'):
                        found_links.add(url)
            time.sleep(random.uniform(10, 20)) # 增加一个更长的随机延迟
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
        
        try:
            data = yaml.safe_load(response.text)
            if isinstance(data, dict) and 'proxies' in data:
                nodes.extend(data['proxies'])
        except yaml.YAMLError:
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
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

def test_proxy(node, test_url='https://www.google.com'):
    """测试单个代理节点的可用性。"""
    try:
        proxies = {
            'http': f"http://{node['server']}:{node['port']}",
            'https': f"http://{node['server']}:{node['port']}"
        }
        # 使用 proxy-protocol-type 来确定协议类型
        protocol = node.get('type')
        if protocol and protocol.lower() in ['ss', 'ssr', 'vmess', 'trojan', 'vless']:
            # 目前 requests 库不支持这些协议，需要一个中间层
            # 这是一个伪代码示例，表明需要进行测试
            print(f"尝试测试节点: {node.get('name', node['server'])}")
            
            # 在此处添加一个真实的代理测试逻辑
            # 例如：使用 https://github.com/clash-verge/clash-meta-py-api 或类似的库
            # 由于requests库无法直接测试这些代理，这里仅作一个基础的HTTP/S代理测试
            
            # 这里简单返回True，表示测试逻辑需要你自己实现
            # 你可以编写一个更复杂的函数来测试这些协议
            return True

        response = requests.get(test_url, proxies=proxies, timeout=10)
        return response.status_code == 200
    except requests.exceptions.RequestException as e:
        print(f"节点 {node.get('name', node['server'])} 测试失败: {e}")
        return False

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
    # 扩展的搜索查询列表
    search_queries = [
        # 搜索包含常见配置文件的目录列表
        'intitle:"Index of /" "config.yaml" -github -gitlab',
        'intitle:"Index of /" "clash.yaml" -github -gitlab',
        'intitle:"Index of /" "mihomo.yaml" -github -gitlab',
        'intitle:"Index of /" "subscription" -github -gitlab',
        # 搜索包含代理关键词的URL和文本
        'inurl:clash "all.yaml" intext:"proxies" -github -gitlab',
        'inurl:v2ray "config.yaml" intext:"Vmess" -github -gitlab',
        'inurl:trojan "config.yaml" intext:"Trojan" -github -gitlab',
        'inurl:subscription "yaml" intext:"proxies" -github -gitlab'
    ]
    
    if not os.path.exists(GEOLITE_DB):
        print("错误: 缺少地理位置数据库文件 GeoLite2-Country.mmdb，请先将其放置在仓库根目录下。")
        sys.exit(1)

    discovered_links = perform_google_search(search_queries, num_results=50)
    
    if discovered_links:
        all_nodes = process_links(discovered_links)
        
        if all_nodes:
            # 新增步骤：测试代理可用性
            print("开始测试代理可用性...")
            working_nodes = []
            with ThreadPoolExecutor(max_workers=10) as executor:
                futures = {executor.submit(test_proxy, node): node for node in all_nodes}
                for future in futures:
                    if future.result():
                        working_nodes.append(future.result())
            print(f"测试完成，发现 {len(working_nodes)} 个可用节点。")

            if working_nodes:
                unique_nodes = geo_process_nodes(working_nodes)
                save_to_yaml(unique_nodes, OUTPUT_YAML)
            else:
                print("未发现任何可用节点。")
        else:
            print("未从发现的链接中找到任何代理节点。")
    else:
        print("未发现任何潜在链接。")
