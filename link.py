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
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin
from base64 import b64decode

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
    """
    link = link.replace('http://', '').replace('https://', '')
    time.sleep(random.uniform(0.5, 3))
    
    try:
        response = requests.head(f"https://{link}", headers=get_headers(), timeout=5)
        logging.debug(f"HTTPS成功: {link}")
        return link, "https"
    except requests.exceptions.RequestException:
        logging.debug(f"HTTPS失败: {link}")
        try:
            response = requests.head(f"http://{link}", headers=get_headers(), timeout=5)
            logging.debug(f"HTTP成功: {link}")
            return link, "http"
        except requests.exceptions.RequestException:
            logging.debug(f"HTTP失败: {link}")
            return None, None

def find_raw_nodes(soup_content):
    """
    在网页内容中查找并提取原始的节点链接。
    """
    nodes = []
    # 查找所有可能包含节点链接的标签
    tags_to_search = soup_content.find_all(['code', 'samp', 'div', 'p', 'textarea', 'pre'])
    # 额外搜索HTML注释
    comments = soup_content.find_all(string=lambda text: isinstance(text, Comment))

    # 更新后的正则表达式，仅匹配指定的协议
    regex = r'(vmess://|ss://|trojan://|vless://|hy2://)[^\s]+'
    
    for element in tags_to_search + comments:
        content = element.string
        if content:
            matches = re.findall(regex, content)
            if matches:
                nodes.extend([{'type': m.split('://')[0], 'raw': m} for m in matches])
    
    return nodes

def is_base64(s):
    """检查字符串是否为有效的 Base64 编码"""
    return re.match(r'^[A-Za-z0-9+/=]*$', s)

def decode_and_find_nodes(b64_string):
    """解码 Base64 字符串并从中提取节点"""
    try:
        decoded_string = b64decode(b64_string).decode('utf-8')
        # 尝试将解码后的字符串解析为YAML
        if 'proxies' in decoded_string.lower():
            try:
                data = yaml.safe_load(decoded_string)
                if isinstance(data, dict) and 'proxies' in data:
                    return data['proxies']
            except yaml.YAMLError:
                pass
        
        # 否则，尝试逐行解析节点
        nodes = []
        for line in decoded_string.split('\n'):
            line = line.strip()
            # 仅匹配我们需要的协议
            if line.startswith(('vmess://', 'vless://', 'trojan://', 'hy2://')):
                nodes.append({'raw': line, 'type': line.split('://')[0]})
        return nodes
    except Exception as e:
        logging.debug(f"Base64解码或解析失败: {e}")
        return []

@retry(stop_max_attempt_number=3, wait_fixed=3000)
def parse_and_fetch(url):
    """
    解析和获取链接内容，根据类型智能处理。
    """
    headers = get_headers()
    try:
        response = requests.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            content_type = response.headers.get('content-type', '').lower()
            
            # 策略1: 优先尝试作为文件直链下载
            if 'yaml' in content_type or 'text' in content_type:
                return response.text, url
            
            # 策略2: 如果是Base64编码，尝试解码
            elif is_base64(response.text.strip()):
                nodes = decode_and_find_nodes(response.text.strip())
                if nodes:
                    logging.info(f"成功解码Base64内容并找到 {len(nodes)} 个节点: {url}")
                    return yaml.dump({'proxies': nodes}), url
            
            # 策略3: 如果是网页，尝试从HTML中爬取
            elif 'text/html' in content_type:
                soup = BeautifulSoup(response.text, 'html.parser')
                # 从网页中寻找潜在的.yaml/.yml/.txt链接
                for link in soup.find_all('a'):
                    href = link.get('href')
                    if href and href.lower().endswith(tuple(['.yaml', '.yml', '.txt'])):
                        full_url = urljoin(url, href)
                        # 递归调用以处理找到的子链接
                        content, source = parse_and_fetch(full_url)
                        if content:
                            return content, source

                # 从<script>, <pre>等标签或注释中提取原始节点
                raw_nodes = find_raw_nodes(soup)
                if raw_nodes:
                    logging.debug(f"从网页中提取到原始节点: {url}")
                    return yaml.dump({'proxies': raw_nodes}), url
    
    except requests.exceptions.RequestException:
        logging.debug(f"请求失败: {url}")
    
    return None, None

def fetch_proxy_links():
    """
    从公开代理池网站和论坛爬取Clash代理链接，排除GitHub。
    并加入新的高成功率来源。
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
        'https://www.v2rayfree.eu.org/',
        'https://www.get-proxy.com/clash-nodes',
        'https://www.freev2ray.com/clash-links',
        'https://freenode.info/clash-links',
        # 新增来源，提高成功率
        'https://gfw.press/clash-proxy.html',
        'https://www.proxyhub.info/proxies.html',
        'https://free.v2ray.io/',
        'https://freeclash.xyz/'
    ]
    links = []
    
    for source in proxy_sources:
        try:
            response = requests.get(source, headers=get_headers(), timeout=10)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # 寻找网页中的所有链接
                for a in soup.find_all('a'):
                    href = a.get('href')
                    if href and ('http' in href):
                        clean_url = re.search(r'(https?://[^\s&]+)', href)
                        if clean_url:
                            links.append(clean_url.group(1))

                # 提取潜在的YAML/TXT链接
                for tag in soup.find_all(['script', 'pre', 'code']):
                    content = tag.string
                    if content and ('.yaml' in content or '.yml' in content or '.txt' in content or 'proxies.txt' in content):
                        matches = re.findall(r'(https?://[^\s&]+\.(?:ya?ml|txt|proxies\.txt))', content)
                        links.extend(matches)
            logging.info(f"从 {source} 爬取到 {len(links)} 个链接（未去重）。")
        except requests.exceptions.RequestException as e:
            logging.warning(f"爬取 {source} 失败: {e}")
            continue
    
    unique_links = list(set(links))[:40]
    logging.info(f"从所有来源爬取到 {len(unique_links)} 个唯一链接。")
    return unique_links

def pre_test_links(links):
    """并发预测试链接"""
    working_links = {}
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_link = {executor.submit(test_connection_and_get_protocol, link): link for link in links}
        for future in tqdm.tqdm(as_completed(future_to_link), total=len(links), desc="预测试链接"):
            result_link, result_protocol = future.result()
            if result_link:
                working_links[result_link] = result_protocol
    return working_links

def process_links(working_links):
    """
    处理可用链接，提取和保存节点。
    """
    all_nodes = []
    node_counts = []
    
    urls_to_process = list(working_links.keys())
    
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_url = {executor.submit(parse_and_fetch, url): url for url in urls_to_process}
        for future in tqdm.tqdm(as_completed(future_to_url), total=len(future_to_url), desc="获取节点内容"):
            nodes_text, successful_url = future.result()
            if nodes_text:
                try:
                    data = yaml.safe_load(nodes_text)
                    if isinstance(data, dict):
                        nodes = data.get('proxies', [])
                        logging.info(f"从 {successful_url} 中找到 {len(nodes)} 个原始节点。")
                        for node in nodes:
                            if not isinstance(node, dict):
                                logging.warning(f"跳过无效节点格式: {node}")
                                continue
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
                            all_nodes.append(node)
                        node_counts.append({'url': successful_url, 'count': len(nodes)})
                except yaml.YAMLError as e:
                    logging.warning(f"YAML解析错误: {successful_url}, 错误: {e}")
    
    return all_nodes, node_counts

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
        # 跳过格式不正确的节点
        if 'server' not in node or 'port' not in node:
            continue
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
