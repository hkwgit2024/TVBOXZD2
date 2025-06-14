import re
import os
import json
import logging
import requests
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import uuid

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('tvbox/process_iptv.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

def load_config(config_file):
    """加载配置文件"""
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"加载配置文件 {config_file} 失败: {e}")
        return {
            "categories": {},
            "exclude_keywords": [],
            "validate_urls": True,
            "output_formats": ["txt", "m3u"],
            "max_threads": 10,
            "timeout": 5
        }

def is_valid_url(url, timeout):
    """检查 URL 是否有效"""
    try:
        response = requests.head(url, timeout=timeout, allow_redirects=True)
        return response.status_code < 400
    except requests.RequestException:
        logging.warning(f"URL 不可访问: {url}")
        return False

def validate_urls(entries, timeout, max_threads):
    """使用多线程验证 URL"""
    valid_entries = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_entry = {executor.submit(is_valid_url, url, timeout): (name, url) for name, url in entries}
        for future in as_completed(future_to_entry):
            name, url = future_to_entry[future]
            try:
                if future.result():
                    valid_entries.append((name, url))
                else:
                    logging.info(f"URL 不可访问，跳过: {url}")
            except Exception as e:
                logging.warning(f"验证 URL {url} 失败: {e}")
    return valid_entries

def categorize_entry(name, categories):
    """根据名称分类条目"""
    for category, pattern in categories.items():
        if re.search(pattern, name, re.IGNORECASE):
            return category
    return '其他'

def should_exclude(name, exclude_keywords):
    """检查是否应排除条目"""
    return any(keyword.lower() in name.lower() for keyword in exclude_keywords)

def parse_iptv_file(input_file, config):
    """解析 IPTV 文件并分类"""
    categorized = defaultdict(list)
    categories = config.get('categories', {})
    exclude_keywords = config.get('exclude_keywords', [])
    validate_urls = config.get('validate_urls', True)
    max_threads = config.get('max_threads', 10)
    timeout = config.get('timeout', 5)

    try:
        entries = []
        with open(input_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                parts = line.split('\t')
                if len(parts) < 2:
                    logging.warning(f"无效行格式: {line}")
                    continue
                name, url = parts[0], parts[-1]
                if not url.startswith(('http://', 'https://')):
                    logging.warning(f"无效 URL 格式: {url}")
                    continue
                if should_exclude(name, exclude_keywords):
                    logging.info(f"排除条目: {name}")
                    continue
                entries.append((name, url))

        # URL 验证
        if validate_urls:
            entries = validate_urls(entries, timeout, max_threads)

        # 分类
        for name, url in entries:
            category = categorize_entry(name, categories)
            categorized[category].append((name, url))
    except Exception as e:
        logging.error(f"解析文件 {input_file} 失败: {e}")
    return categorized

def write_output_files(categorized, output_dir, output_formats):
    """生成分类后的文件，支持 txt 和 m3u 格式"""
    os.makedirs(output_dir, exist_ok=True)
    for category, entries in categorized.items():
        if "txt" in output_formats:
            output_file = os.path.join(output_dir, f'{category}.txt')
            with open(output_file, 'w', encoding='utf-8') as f:
                for name, url in entries:
                    f.write(f'{name}\t{url}\n')
            logging.info(f"生成 TXT 文件: {output_file}，条目数: {len(entries)}")
        
        if "m3u" in output_formats:
            output_file = os.path.join(output_dir, f'{category}.m3u')
            m3u_content = '#EXTM3U\n'
            for name, url in entries:
                m3u_content += f'#EXTINF:-1,{name}\n{url}\n'
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(m3u_content)
            logging.info(f"生成 M3U 文件: {output_file}，条目数: {len(entries)}")

def main():
    tvbox_dir = 'tvbox'
    input_file = os.path.join(tvbox_dir, 'iptv_list.txt')
    config_file = os.path.join(tvbox_dir, 'config.json')
    output_dir = tvbox_dir
    
    if not os.path.exists(input_file):
        logging.error(f"输入文件 {input_file} 不存在")
        return
    
    config = load_config(config_file)
    categorized = parse_iptv_file(input_file, config)
    write_output_files(categorized, output_dir, config.get('output_formats', ['txt', 'm3u']))
    logging.info("处理完成")

if __name__ == '__main__':
    main()
