# -*- coding: utf-8 -*-
import os
import requests
from urllib.parse import urlparse
import base64
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import argparse

# 配置日志
logging.basicConfig(filename='error.log', level=logging.INFO,
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
args = parser.parse_args()

MAX_SUCCESS = args.max_success
TIMEOUT = args.timeout
OUTPUT_FILE = args.output
MAX_FILE_SIZE = 90 * 1024 * 1024  # 90 MB
MAX_CONTENT_SIZE = 5 * 1024 * 1024  # 单个 URL 内容最大 5 MB
MAX_FILES = 50  # 最大文件数量

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
        logging.info(f"从 {url_source} 获取到 {len(raw_urls)} 个URL")
        return raw_urls
    except Exception as e:
        logging.error(f"获取URL列表失败: {url_source} - {e}")
        return []

def fetch_url(url, success_file, failed_file):
    """获取并处理单个URL的内容，同时记录成功/失败状态"""
    try:
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status()
        content = resp.text.strip()
        if len(content) < 10 or any(x in content for x in ["DOMAIN", "port", "proxies", "[]", "{}"]):
            logging.info(f"跳过无效内容: {url}")
            with open(failed_file, 'a', encoding='utf-8') as f:
                f.write(url + '\n')
            return None
        try:
            decoded_content = base64.b64decode(content).decode('utf-8')
            content_size = len(decoded_content.encode('utf-8'))
            if content_size > MAX_CONTENT_SIZE:
                logging.warning(f"内容过大，跳过: {url} ({content_size} bytes)")
                with open(failed_file, 'a', encoding='utf-8') as f:
                    f.write(url + '\n')
                return None
            logging.info(f"成功处理 (Base64): {url}, 内容长度: {content_size} bytes")
            with open(success_file, 'a', encoding='utf-8') as f:
                f.write(url + '\n')
            return decoded_content
        except Exception:
            content_size = len(content.encode('utf-8'))
            if content_size > MAX_CONTENT_SIZE:
                logging.warning(f"内容过大，跳过: {url} ({content_size} bytes)")
                with open(failed_file, 'a', encoding='utf-8') as f:
                    f.write(url + '\n')
                return None
            logging.info(f"成功处理 (非Base64): {url}, 内容长度: {content_size} bytes")
            with open(success_file, 'a', encoding='utf-8') as f:
                f.write(url + '\n')
            return content if len(content) > 10 else None
    except Exception as e:
        logging.error(f"处理失败: {url} - {e}")
        with open(failed_file, 'a', encoding='utf-8') as f:
            f.write(url + '\n')
        return None

# 从环境变量中读取 URL_SOURCE 并调试
URL_SOURCE = os.environ.get("URL_SOURCE")
print(f"调试信息 - 读取到的 URL_SOURCE 值: {URL_SOURCE}")
if not URL_SOURCE:
    print("错误：环境变量 'URL_SOURCE' 未设置。请设置环境变量并重试。")
    exit(1)

# 初始化成功和失败 URL 文件
success_urls_file = 'data/success_urls.txt'
failed_urls_file = 'data/failed_urls.txt'
open(success_urls_file, 'w', encoding='utf-8').close()  # 清空文件
open(failed_urls_file, 'w', encoding='utf-8').close()  # 清空文件

# 获取 URL 列表
success_urls_file = 'data/success_urls.txt'
if os.path.exists(success_urls_file):
    with open(success_urls_file, 'r', encoding='utf-8') as f:
        valid_urls = [line.strip() for line in f if line.strip()]
    print(f"从 {success_urls_file} 读取到 {len(valid_urls)} 个成功 URL")
else:
    # 从 URL_SOURCE 获取 URL
    url_sources = [URL_SOURCE]
    all_raw_urls = []
    for source in url_sources:
        raw_urls = get_url_list(source)
        all_raw_urls.extend(raw_urls)
    unique_urls = list({url.strip() for url in all_raw_urls if url.strip()})
    valid_urls = [url for url in unique_urls if is_valid_url(url)]
    print(f"合并后唯一URL数量：{len(unique_urls)}")
    print(f"经过格式验证的有效URL数量：{len(valid_urls)}")

# 限制 URL 数量以控制输出
valid_urls = valid_urls[:5000]  # 限制为 5000 个 URL
print(f"限制处理 URL 数量为：{len(valid_urls)}")

# 确保输出目录存在
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

# 处理URL内容并分割输出文件
success_count = 0
file_index = 1
current_size = 0
out_file = open(f"{OUTPUT_FILE}.{file_index}", 'w', encoding='utf-8')

try:
    with ThreadPoolExecutor(max_workers=8) as executor:
        future_to_url = {executor.submit(fetch_url, url, success_urls_file, failed_urls_file): url for url in valid_urls}
        for future in tqdm(as_completed(future_to_url), total=len(valid_urls), desc="处理URL"):
            if file_index > MAX_FILES:
                logging.warning(f"达到最大文件数量 {MAX_FILES}，停止写入")
                break
            result = future.result()
            if result and success_count < MAX_SUCCESS:
                result_size = len(result.encode('utf-8'))
                if result_size > MAX_FILE_SIZE:
                    logging.warning(f"单条内容过大，跳过: {future_to_url[future]} ({result_size} bytes)")
                    with open(failed_urls_file, 'a', encoding='utf-8') as f:
                        f.write(future_to_url[future] + '\n')
                    continue
                if current_size + result_size > MAX_FILE_SIZE:
                    out_file.close()
                    logging.info(f"关闭文件 {OUTPUT_FILE}.{file_index}, 大小: {current_size} bytes")
                    file_index += 1
                    out_file = open(f"{OUTPUT_FILE}.{file_index}", 'w', encoding='utf-8')
                    current_size = 0
                out_file.write(result.strip() + '\n')
                current_size += result_size
                success_count += 1
finally:
    out_file.close()
    logging.info(f"关闭文件 {OUTPUT_FILE}.{file_index}, 大小: {current_size} bytes")

# 最终结果报告
print("\n" + "=" * 50)
print("最终结果：")
print(f"处理URL总数：{len(valid_urls)}")
print(f"成功获取内容数：{success_count}")
print(f"生成文件数：{file_index}")
if len(valid_urls) > 0:
    print(f"有效内容率：{success_count/len(valid_urls):.1%}")
if success_count < MAX_SUCCESS:
    print("警告：未能达到目标数量，原始列表可能有效URL不足")
print(f"结果文件已保存至：{OUTPUT_FILE}.1, {OUTPUT_FILE}.2, ...")
print(f"成功URL已保存至：{success_urls_file}")
print(f"失败URL已保存至：{failed_urls_file}")
