import requests
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
        print("未找到 categories.yaml 文件，使用默认配置", flush=True)
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
    print(f"开始测试: {url}", flush=True)
    try:
        response = requests.head(url, timeout=timeout, verify=False, allow_redirects=True)
        if response.status_code == 200:
            print(f"成功: {url} (状态码: 200)", flush=True)
            return True
        else:
            print(f"失败: {url} (状态码: {response.status_code})", flush=True)
            return False
    except requests.RequestException as e:
        print(f"失败: {url} (错误: {e})", flush=True)
        return False

def test_urls(urls, timeout=10, max_workers=3):
    """并行测试多个URL"""
    if not urls:
        print("警告: 没有URL需要测试", flush=True)
        return []
    print(f"测试URL列表: {urls}", flush=True)
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(lambda url: (url, test_url(url, timeout)), urls))
    valid_urls = [url for url, is_valid in results if is_valid]
    print(f"有效URL: {valid_urls}", flush=True)
    return valid_urls

def parse_iptv_list(url):
    """从远程URL解析IPTV列表"""
    channels = {}
    current_channel = None
    
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            print(f"错误: 无法访问 {url} (状态码: {response.status_code})", flush=True)
            return channels
        
        lines = response.text.strip().splitlines()
        if not lines:
            print(f"错误: {url} 内容为空", flush=True)
            return channels
            
        for line in lines:
            line = line.strip()
            print(f"解析行: '{line}'", flush=True)
            if not line or line.startswith('更新时间') or line == '#genre#':
                print(f"跳过无效行: '{line}'", flush=True)
                continue
                
            # 处理制表符分隔的行
            parts = line.split('\t')
            if len(parts) >= 2 and parts[1].startswith('http'):
                channel = parts[0].strip()
                url = parts[1].strip()
                channels[channel] = channels.get(channel, []) + [url]
                print(f"发现频道: '{channel}', URL: '{url}'", flush=True)
            elif len(parts) == 1 and parts[0].startswith('http'):
                if current_channel:
                    channels[current_channel].append(parts[0])
                    print(f"添加URL: '{parts[0]}'", flush=True)
                else:
                    print(f"警告: 发现URL '{parts[0]}' 但没有关联的频道", flush=True)
            elif len(parts) == 1 and not parts[0].startswith('http'):
                current_channel = parts[0].strip()
                channels[current_channel] = []
                print(f"发现频道: '{current_channel}'", flush=True)
    
    except requests.RequestException as e:
        print(f"错误: 无法访问 {url} (错误: {e})", flush=True)
        return channels
    
    print(f"解析结果: {channels}", flush=True)
    return channels

def generate_category_template(channels, config_file='categories.yaml'):
    """生成分类配置文件"""
    if not os.path.exists(config_file):
        default_config = {
            '新闻': [],
            '电影': [],
            '卡通': [],
            '综艺': [],
            '其他': list(channels.keys())
        }
        with open(config_file, 'w', encoding='utf-8') as f:
            yaml.safe_dump(default_config, f, allow_unicode=True, sort_keys=False)
        print(f"生成分类模板: '{config_file}'", flush=True)

def categorize_channels(channels, config):
    """根据配置文件分类频道"""
    categorized = {c: [] for c in config.keys()}
    for channel, urls in channels.items():
        assigned = False
        for category, channel_list in config.items():
            if channel in channel_list:
                categorized[category].append((channel, urls))
                assigned = True
                break
        if not assigned:
            categorized['其他'].append((channel, urls))
    print(f"分类结果: {categorized}", flush=True)
    return categorized

def save_valid_channels(categorized_channels, output_file):
    """保存有效频道到输出文件，并记录错误日志"""
    error_log = []
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(f'# IPTV List - Generated at {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
        f.write('#genre#\n')
        
        for category, channels in categorized_channels.items():
            if channels:
                f.write(f'\n{category},#genre#\n')
                for channel, urls in channels:
                    valid_urls = test_urls(urls)
                    if valid_urls:
                        f.write(f'{channel}\n')
                        for url in valid_urls:
                            f.write(f'{url}\n')
                    for url in urls:
                        if url not in valid_urls:
                            error_log.append(f"{channel}: {url} - 失败")
    
    if error_log:
        with open('test_errors.log', 'w', encoding='utf-8') as log:
            log.write('\n'.join(error_log) + '\n')
        print(f"错误日志已生成: test_errors.log", flush=True)
    else:
        print("没有测试失败的链接", flush=True)

def main():
    input_file = 'https://raw.githubusercontent.com/qjlxg/vt/main/iptv_list.txt'
    output_file = 'tv_list.txt'
    
    channels = parse_iptv_list(input_file)
    if not channels:
        print(f"错误: 没有解析到任何频道或URL，检查 {input_file}", flush=True)
        return
    
    generate_category_template(channels)
    config = load_config()
    categorized_channels = categorize_channels(channels, config)
    save_valid_channels(categorized_channels, output_file)
    print(f"已生成有效频道列表: {output_file}", flush=True)
    if os.path.exists('test_errors.log'):
        print(f"测试错误日志已保存至: test_errors.log", flush=True)

if __name__ == '__main__':
    main()
