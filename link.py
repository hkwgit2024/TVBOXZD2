import os
import requests
import yaml
import csv
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
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
    print("GeoLite2-Country 数据库加载成功。")
except FileNotFoundError:
    print(f"错误: 无法找到地理位置数据库文件 {GEOLITE_DB}。请确保文件已上传到仓库根目录。")
    exit(1)

def get_node_from_url(url):
    """尝试用 HTTP/HTTPS 和 URL 获取节点内容"""
    try:
        response = requests.get(f"http://{url}", timeout=10)
        if response.status_code == 200:
            print(f"成功连接 (HTTP): {url}")
            return response.text, f"http://{url}"
    except requests.exceptions.RequestException:
        print(f"HTTP连接失败，尝试HTTPS: {url}")
        pass

    try:
        response = requests.get(f"https://{url}", timeout=10)
        if response.status_code == 200:
            print(f"成功连接 (HTTPS): {url}")
            return response.text, f"https://{url}"
    except requests.exceptions.RequestException:
        print(f"HTTPS连接失败: {url}")
        pass

    return None, None

def process_link(link):
    """处理单个链接，返回节点数据和统计信息"""
    print(f"开始处理链接: {link}")
    link = link.replace('http://', '').replace('https://', '')
    
    for config in CONFIG_NAMES:
        url_with_config = f"{link}/{config}"
        node_content, successful_url = get_node_from_url(url_with_config)
        
        if node_content:
            try:
                data = yaml.safe_load(node_content)
                nodes = data.get('proxies', [])
                
                # 处理每个节点，添加地理位置信息
                for node in nodes:
                    ip = re.search(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', node.get('server', ''))
                    if ip:
                        ip = ip.group(0)
                        country_code, country_name = geolocator.get_location(ip)
                        if country_name:
                            node['name'] = country_name
                
                print(f"处理完成: {successful_url}，找到 {len(nodes)} 个节点。")
                return nodes, {'url': successful_url, 'count': len(nodes)}
            except yaml.YAMLError as e:
                print(f"解析YAML失败: {successful_url} - {e}")
                
    print(f"未能连接并获取内容: {link}")
    return [], {'url': link, 'count': 0}

def main():
    """主函数，使用线程池处理所有链接"""
    print("脚本开始运行...")
    all_nodes = []
    node_counts = []
    
    with open(LINKS_FILE, 'r') as f:
        links = [line.strip() for line in f if link.strip()]

    # 使用线程池并发处理，max_workers 决定并发数量
    with ThreadPoolExecutor(max_workers=10) as executor:
        # 提交所有任务
        future_to_link = {executor.submit(process_link, link): link for link in links}
        
        # 实时获取结果
        for future in as_completed(future_to_link):
            nodes, count_info = future.result()
            all_nodes.extend(nodes)
            node_counts.append(count_info)
    
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
