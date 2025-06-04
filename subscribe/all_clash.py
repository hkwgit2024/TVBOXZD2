# -*- coding: utf-8 -*-
import os
import requests
from urllib.parse import urlparse
import base64
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import argparse
import math

# 配置日志
logging.basicConfig(filename='error.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# 请求头
headers = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/91.0.4472.124 Safari/537.36'
    ),
    'Accept-Encoding': 'gzip, deflate'
}

# 命令行参数
parser = argparse.ArgumentParser(description="URL内容获取脚本，支持多个URL来源")
parser.add_argument('--max_success', type=int, default=99999, help="目标成功数量")
parser.add_argument('--timeout', type=int, default=60, help="请求超时时间（秒）")
parser.add_argument('--output', type=str, default='data/all_clash.txt', help="输出文件路径")
parser.add_argument('--max_size', type=int, default=1024*1024*1024, help="单个文件最大大小（字节）")
args = parser.parse_args()

MAX_SUCCESS = args.max_success
TIMEOUT = args.timeout
OUTPUT_FILE = args.output
MAX_FILE_SIZE = args.max_size  # 1GB

def is_valid_url(url):
    """验证URL格式是否合法"""
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except Exception:
        return False

def get_url_list(url_source):
    """从给定的公开网址获取 URL 列表"""
    try:
        response = requests.get(url_source, headers=headers, timeout=10)
        response.raise_for_status()
        text_content = response.text.strip()
        raw_urls = [line.strip() for line in text_content.splitlines() if line.strip()]
        print(f"从 {url_source} 获取到 {len(raw_urls)} 个URL")
        return raw_urls
    except Exception as e:
        logging.error(f"获取URL列表失败: {url_source} - {e}")
        return []

def fetch_url(url):
    """获取并处理单个URL的内容"""
    try:
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status()
        content = resp.text.strip()
        if len(content) < 10 or any(x in content for x in ["DOMAIN", "port", "proxies", "[]", "{}"]):
            return None, url, False
        try:
            decoded_content = base64.b64decode(content).decode('utf-8')
            return decoded_content, url, True
        except Exception:
            return content if len(content) > 10 else None, url, content is not None
    except Exception as e:
        logging.error(f"处理失败: {url} - {e}")
        return None, url, False

# 从环境变量中读取 URL_SOURCE 并调试
URL_SOURCE = os.environ.get("URL_SOURCE")
print(f"调试信息 - 读取到的 URL_SOURCE 值: {URL_SOURCE}")
if not URL_SOURCE:
    print("错误：环境变量 'URL_SOURCE' 未设置。请设置环境变量并重试。")
    exit(1)

# URL 来源列表
url_sources = [URL_SOURCE]

# 获取所有URL来源的URL列表
all_raw_urls = []
for source in url_sources:
    raw_urls = get_url_list(source)
    all_raw_urls.extend(raw_urls)

# 去重并验证URL格式
unique_urls = list({url.strip() for url in all_raw_urls if url.strip()})
valid_urls = [url for url in unique_urls if is_valid_url(url)]
print(f"合并后唯一URL数量：{len(unique_urls)}")
print(f"经过格式验证的有效URL数量：{len(valid_urls)}")

# 确保输出目录存在
output_dir = os.path.dirname(OUTPUT_FILE)
os.makedirs(output_dir, exist_ok=True)

# 初始化成功和失败URL列表
successful_urls = []
failed_urls = []

# 处理URL内容
success_count = 0
file_index = 1
current_file_size = 0
base_output_file = os.path.splitext(OUTPUT_FILE)[0]
extension = os.path.splitext(OUTPUT_FILE)[1]
out_file = open(f"{base_output_file}_{file_index}{extension}", 'w', encoding='utf-8')

with ThreadPoolExecutor(max_workers=16) as executor:
    future_to_url = {executor.submit(fetch_url, url): url for url in valid_urls}
    for future in tqdm(as_completed(future_to_url), total=len(valid_urls), desc="处理URL"):
        result, url, success = future.result()
        if result and success_count < MAX_SUCCESS:
            result_bytes = (result.strip() + '\n').encode('utf-8')
            # 检查是否需要创建新文件
            if current_file_size + len(result_bytes) > MAX_FILE_SIZE:
                out_file.close()
                file_index += 1
                current_file_size = 0
                out_file = open(f"{base_output_file}_{file_index}{extension}", 'w', encoding='utf-8')
            out_file.write(result.strip() + '\n')
            current_file_size += len(result_bytes)
            success_count += 1
            successful_urls.append(url)
        if success:
            successful_urls.append(url)
        else:
            failed_urls.append(url)

out_file.close()

# 记录成功和失败的URL
with open(os.path.join(output_dir, 'successful_urls.txt'), 'w', encoding='utf-8') as f:
    f.write('\n'.join(successful_urls))
with open(os.path.join(output_dir, 'failed_urls.txt'), 'w', encoding='utf-8') as f:
    f.write('\n'.join(failed_urls))

# 最终结果报告
print("\n" + "=" * 50)
print("最终结果：")
print(f"处理URL总数：{len(valid_urls)}")
print(f"成功获取内容数：{success_count}")
print(f"输出文件数量：{file_index}")
if len(valid_urls) > 0:
    print(f"有效内容率：{success_count/len(valid_urls):.1%}")
if success_count < MAX_SUCCESS:
    print("警告：未能达到目标数量，原始列表可能有效URL不足")
print(f"结果文件已保存至：{base_output_file}_[1-{file_index}]{extension}")
print(f"成功URL记录至：{os.path.join(output_dir, 'successful_urls.txt')}")
print(f"失败URL记录至：{os.path.join(output_dir, 'failed_urls.txt')}")
