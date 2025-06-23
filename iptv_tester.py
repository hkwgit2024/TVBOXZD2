import requests
import re
import os
from datetime import datetime
import yaml
import urllib3
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def load_config():
    """加载分类配置文件"""
    config_path = 'categories.yaml'
    if not os.path.exists(config_path):
        print("未找到 categories.yaml 文件，使用默认配置")
        return {
            '新闻': ['ABCNews', 'CBNNews', 'CCTV1', '非凡新闻', '香港Now新闻CH332', '香港卫视'],
            '电影': ['12.周星驰电影', '16.豆瓣高分', '19.宇哥电影', 'AXN电影', '湖南电影', '美亚电影', '龙华电影', '龙祥电影'],
            '卡通': ['金鹰卡通', '靖天卡通', '龙华卡通'],
            '综艺': ['澳视综艺', '澳视资讯', '澳门莲花'],
            '其他': []
        }
    
    with open(config_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def test_url(url, timeout=10):
    """测试URL是否可连接"""
    try:
        response = requests.head(url, timeout=timeout, verify=False, allow_redirects=True)
        if response.status_code == 200:
            print(f"成功: {url}")
            return True
        else:
            print(f"失败: {url} (状态码: {response.status_code})")
            return False
    except requests.RequestException as e:
        print(f"失败: {url} (错误: {e})")
        return False

def test_urls(urls, timeout=10, max_workers=10):
    """并行测试多个URL"""
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(lambda url: (url, test_url(url, timeout)), urls))
    return [url for url, is_valid in results if is_valid]

def parse_iptv_list(file_path):
    """解析IPTV列表文件"""
    channels = {}
    current_channel = None
    
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('更新时间') or line == '#genre#':
                continue
                
            if not line.startswith('http'):
                current_channel = line
                channels[current_channel] = []
            else:
                if current_channel:
                    channels[current_channel].append(line)
    
    return channels

def generate_category_template(channels, config_file='categories.yaml'):
    """生成分类配置文件模板"""
    if not os.path.exists(config_file):
        default_config = {
            '新闻': [],
            '电影': [],
            '卡通': [],
            '综艺': [],
            '其他': list(channels.keys())
        }
        with open(config_file, 'w', encoding='utf-8') as f:
            yaml.dump(default_config, f, allow_unicode=True, sort_keys=False)
        print(f"已生成分类模板: {config_file}")

def categorize_channels(channels, config):
    """根据配置文件对频道进行分类"""
    categorized = {category: [] for category in config.keys()}
    
    for channel, urls in channels.items():
        assigned = False
        for category, channel_list in config.items():
            if channel in channel_list:
                categorized[category].append((channel, urls))
                assigned = True
                break
        if not assigned:
            categorized['其他'].append((channel, urls))
    
    return categorized

def save_valid_channels(categorized_channels, output_file):
    """保存有效频道到输出文件，并记录错误日志"""
    with open(output_file, 'w', encoding='utf-8') as f, open('test_errors.log', 'w', encoding='utf-8') as log:
        f.write(f'# IPTV List - Generated at {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
        f.write('#genre#\n')
        
        for category, channels in categorized_channels.items():
            if channels:  # 只写入非空的分类
                f.write(f'\n{category},#genre#\n')
                for channel, urls in channels:
                    valid_urls = test_urls(urls)
                    if valid_urls:
                        f.write(f'{channel}\n')
                        for url in valid_urls:
                            f.write(f'{url}\n')
                    for url in urls:
                        if url not in valid_urls:
                            log.write(f"{channel}: {url} - 失败\n")

def main():
    input_file = 'iptv_list.txt'
    output_file = 'tv_list.txt'
    
    if not os.path.exists(input_file):
        print(f"错误：未找到 {input_file}")
        return
    
    channels = parse_iptv_list(input_file)
    generate_category_template(channels)
    config = load_config()
    categorized_channels = categorize_channels(channels, config)
    save_valid_channels(categorized_channels, output_file)
    print(f"已生成有效频道列表：{output_file}")
    if os.path.exists('test_errors.log'):
        print(f"测试错误日志已保存至：test_errors.log")

if __name__ == '__main__':
    main()
