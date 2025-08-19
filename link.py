import os
import requests
import yaml
import csv
import re
import random
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from retrying import retry
from ip_geolocation import GeoLite2Country
from tqdm import tqdm
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 检查依赖
try:
    import requests, yaml, bs4, tqdm, retrying, maxminddb
except ImportError as e:
    logging.error(f"缺失依赖: {e}. 请运行 `pip install requests pyyaml beautifulsoup4 tqdm retrying maxminddb`")
    exit(1)

# 定义文件路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
OUTPUT_YAML = os.path.join(BASE_DIR, 'link.yaml')
OUTPUT_CSV = os.path.join(BASE_DIR, 'link.csv')
GEOLITE_DB = os.path.join(BASE_DIR, 'GeoLite2-Country.mmdb')

# 定义需要尝试的配置文件名
CONFIG_NAMES = ['config.yaml', 'clash_proxies.yaml', 'all.yaml', 'mihomo.yaml', 'clash.yml', 'proxies.yaml', 'nodes.txt', 'proxies.txt']

# 浏览器User-Agent列表
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
]

# 初始化地理位置解析器
try:
    geolocator = GeoLite2Country(GEOLITE_DB)
    logging.info("GeoLite2-Country 数据库加载成功。")
except FileNotFoundError:
    logging.error(f"无法找到地理位置数据库文件 {GEOLITE_DB}。请确保 GeoLite2-Country.mmdb 存在于脚本根目录。")
    exit(1)

def get_headers():
    return {'User-Agent': random.choice(USER_AGENTS)}

@retry(stop_max_attempt_number=3, wait_fixed=3000)
def test_connection_and_get_protocol(link):
    """
    测试链接连通性，优先HTTPS，返回协议和链接。
    排除GitHub相关链接。
    """
    if 'github' in link.lower():
        logging.debug(f"跳过GitHub链接: {link}")
        return None, None
    link = link.replace('http://', '').replace('https://', '')
    time.sleep(random.uniform(0.5, 3))  # 随机延迟
    
    try:
        response = requests.head(f"https://{link}", headers=get_headers(), timeout=5)
        logging.debug(f"HTTPS成功: {link}")
        return link, "https"
    except requests.exceptions.RequestException as e:
        logging.debug(f"HTTPS失败: {link}, 错误: {e}")
        try:
            response = requests.head(f"http://{link}", headers=get_headers(), timeout=5)
            logging.debug(f"HTTP成功: {link}")
            return link, "http"
        except requests.exceptions.RequestException as e:
            logging.debug(f"HTTP失败: {link}, 错误: {e}")
            return None, None

@retry(stop_max_attempt_number=3, wait_fixed=3000)
def test_node_latency(node):
    """
    测试节点延迟，返回延迟（ms）或None（不可用）。
    """
    server = node.get('server')
    port = node.get('port')
    if not server or not port:
        logging.debug(f"无效节点: {node.get('name', 'Unknown')}, 无server或port")
        return None
    try:
        # 使用1.1.1.1测试，兼容性更高
        response = requests.get('https://1.1.1.1', proxies={
            'http': f"{node.get('type', 'http')}://{server}:{port}",
            'https': f"{node.get('type', 'http')}://{server}:{port}"
        }, timeout=5)
        latency = response.elapsed.total_seconds() * 1000
        logging.debug(f"节点 {node.get('name', 'Unknown')} 延迟: {latency}ms")
        return latency
    except requests.exceptions.RequestException as e:
        logging.debug(f"节点 {node.get('name', 'Unknown')} 测试失败: {e}")
        return None

def fetch_proxy_links():
    """
    从公开代理池网站和论坛爬取Clash代理链接，排除GitHub。
    """
    proxy_sources = [
        'https://proxypool.link/clash',
        'https://nodefree.org/',
        'https://freefq.com/',
        'https://free-proxy-list.net/',
        'https://www.proxy-list.download/',
        'https://www.sslproxies.org/',
        'https://hidemy.name/en/proxy-list/',
        'https://spys.one/en/free-proxy-list/',
        'https://proxyservers.pro/free/',
        'https://www.blackhatworld.com/forum/proxies/',
        'https://v2ex.com/?tab=tech',
    ]
    links = []
    
    for source in proxy_sources:
        try:
            response = requests.get(source, headers=get_headers(), timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                for a in soup.find_all('a'):
                    href = a.get('href')
                    if href and ('http' in href) and 'github' not in href.lower():
                        clean_url = re.search(r'(https?://[^\s&]+)', href)
                        if clean_url:
                            links.append(clean_url.group(1))
                # 提取潜在的YAML/TXT链接
                for tag in soup.find_all(['script', 'pre']):
                    content = tag.string
                    if content and ('.yaml' in content or '.yml' in content or '.txt' in content or 'proxies.txt' in content):
                        matches = re.findall(r'(https?://[^\s&]+\.(?:ya?ml|txt|proxies\.txt))', content)
                        links.extend([m for m in matches if 'github' not in m.lower()])
            logging.info(f"从 {source} 爬取到 {len(links)} 个链接（未去重）。")
        except requests.exceptions.RequestException as e:
            logging.warning(f"爬取 {source} 失败: {e}")
            continue
    
    unique_links = list(set(links))[:40]  # 限制数量
    logging.info(f"从所有来源爬取到 {len(unique_links)} 个唯一链接。")
    return unique_links

@retry(stop_max_attempt_number=3, wait_fixed=3000)
def parse_and_fetch_yaml(url):
    """
    解析和获取YAML内容，支持HTML页面和TXT格式。
    """
    headers = get_headers()
    
    # 尝试直接下载YAML或TXT
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200 and 'text/html' not in response.headers.get('content-type', '').lower():
            content_type = response.headers.get('content-type', '').lower()
            if 'yaml' in content_type or url.endswith(('.yaml', '.yml')):
                logging.debug(f"直接获取YAML: {url}")
                return response.text, url
            elif 'text/plain' in content_type or url.endswith('.txt'):
                text = response.text
                if 'vmess://' in text or 'ss://' in text or 'trojan://' in text:
                    nodes = []
                    for line in text.splitlines():
                        if line.startswith(('vmess://', 'ss://', 'trojan://')):
                            nodes.append({'type': line.split('://')[0], 'raw': line})
                    if nodes:
                        logging.debug(f"解析TXT节点: {url}")
                        return yaml.dump({'proxies': nodes}), url
    except requests.exceptions.RequestException as e:
        logging.debug(f"直接下载失败: {url}, 错误: {e}")
    
    # 解析HTML页面
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200 and 'text/html' in response.headers.get('content-type', '').lower():
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # 策略1: 寻找.yaml/.yml/.txt链接
            for link in soup.find_all('a'):
                href = link.get('href')
                if href and href.lower().endswith(('.yaml', '.yml', '.txt')) and 'github' not in href.lower():
                    full_url = urljoin(url, href)
                    try:
                        yaml_response = requests.get(full_url, headers=headers, timeout=10)
                        if yaml_response.status_code == 200:
                            logging.debug(f"从HTML获取文件: {full_url}")
                            return yaml_response.text, full_url
                    except requests.exceptions.RequestException as e:
                        logging.debug(f"HTML链接下载失败: {full_url}, 错误: {e}")
            
            # 策略2: 从<script>或<pre>标签提取
            for tag in soup.find_all(['script', 'pre']):
                content = tag.string
                if content:
                    if 'proxies' in content:
                        try:
                            data = yaml.safe_load(content)
                            if isinstance(data, dict) and 'proxies' in data:
                                logging.debug(f"从HTML标签提取YAML: {url}")
                                return yaml.dump({'proxies': data['proxies']}), url
                        except yaml.YAMLError as e:
                            logging.debug(f"YAML解析失败: {url}, 错误: {e}")
                    matches = re.findall(r'(vmess://|ss://|trojan://)[^\s]+', content)
                    if matches:
                        nodes = [{'type': m.split('://')[0], 'raw': m} for m in matches]
                        logging.debug(f"从HTML标签提取原始节点: {url}")
                        return yaml.dump({'proxies': nodes}), url
    except requests.exceptions.RequestException as e:
        logging.debug(f"HTML解析失败: {url}, 错误: {e}")
    
    return None, None

def process_links(working_links):
    """
    处理可用链接，提取和测试节点。
    """
    all_nodes = []
    node_counts = []
    
    urls_to_process = []
    for link, protocol in working_links.items():
        for config_name in CONFIG_NAMES:
            urls_to_process.append(f"{protocol}://{link}/{config_name}")
        urls_to_process.append(f"{protocol}://{link}/")
    
    urls_to_process = list(set(urls_to_process))
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(parse_and_fetch_yaml, url): url for url in urls_to_process}
        for future in tqdm(as_completed(future_to_url), total=len(future_to_url), desc="获取节点内容"):
            nodes_text, successful_url = future.result()
            if nodes_text:
                try:
                    data = yaml.safe_load(nodes_text)
                    if isinstance(data, dict):
                        nodes = data.get('proxies', [])
                        for node in nodes:
                            ip = re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', node.get('server', ''))
                            if ip:
                                ip = ip.group(0)
                                country_code, country_name = geolocator.get_location(ip)
                                if country_name:
                                    node['name'] = country_name
                                else:
                                    node['name'] = f"Node_{random.randint(1000, 9999)}"
                            else:
                                node['name'] = node.get('name', f"Node_{random.randint(1000, 9999)}")
                            # 测试节点延迟
                            latency = test_node_latency(node)
                            if latency and latency < 300:  # 放宽到300ms
                                node['latency'] = latency
                                all_nodes.append(node)
                        node_counts.append({'url': successful_url, 'count': len(nodes)})
                except yaml.YAMLError as e:
                    logging.warning(f"YAML解析错误: {successful_url}, 错误: {e}")
    
    return all_nodes, node_counts

def pre_test_links(links):
    """并发预测试链接"""
    working_links = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_link = {executor.submit(test_connection_and_get_protocol, link): link for link in links}
        for future in tqdm(as_completed(future_to_link), total=len(links), desc="预测试链接"):
            result_link, result_protocol = future.result()
            if result_link:
                working_links[result_link] = result_protocol
    return working_links

def main():
    logging.info("脚本开始运行...")

    # 动态爬取链接
    logging.info("爬取公开代理池和论坛的Clash代理链接...")
    proxy_links = fetch_proxy_links()
    links_to_test = [link for link in proxy_links if 'github' not in link.lower()]
    links_to_test = list(set(links_to_test))
    logging.info(f"共收集到 {len(links_to_test)} 个待测试链接。")
    
    # 预测试链接
    logging.info("第一阶段：预测试所有链接，优先尝试 HTTPS...")
    working_links = pre_test_links(links_to_test)
    logging.info(f"预测试完成，发现 {len(working_links)} 个可用链接。")
    
    # 处理可用链接
    logging.info("第二阶段：开始处理可用链接...")
    all_nodes, node_counts = process_links(working_links)
    
    # 去重和重命名
    unique_nodes = []
    names_count = {}
    node_keys = set()
    for node in all_nodes:
        key = (node.get('server', ''), node.get('port', ''))
        if key not in node_keys:
            node_keys.add(key)
            name = node.get('name', 'Unknown')
            if name in names_count:
                names_count[name] += 1
                node['name'] = f"{name}_{names_count[name]:02d}"
            else:
                names_count[name] = 1
            unique_nodes.append(node)
    
    # 保存结果
    logging.info("所有链接处理完毕，开始保存文件。")
    final_data = {'proxies': unique_nodes}
    try:
        with open(OUTPUT_YAML, 'w', encoding='utf-8') as f:
            yaml.dump(final_data, f, allow_unicode=True)
        logging.info(f"节点已保存到 {OUTPUT_YAML}")
    except Exception as e:
        logging.error(f"保存 {OUTPUT_YAML} 失败: {e}")
    
    try:
        with open(OUTPUT_CSV, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(['URL', 'Node Count'])
            for item in node_counts:
                writer.writerow([item['url'], item['count']])
        logging.info(f"统计信息已保存到 {OUTPUT_CSV}")
    except Exception as e:
        logging.error(f"保存 {OUTPUT_CSV} 失败: {e}")
    
    logging.info(f"总计获取 {len(unique_nodes)} 个唯一节点。")
    logging.info("脚本运行结束。")

if __name__ == "__main__":
    main()
