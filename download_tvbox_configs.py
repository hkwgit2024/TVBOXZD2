import os
import requests
import json
from datetime import datetime, timezone
import logging
import time

# 配置日志记录
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# GitHub API Token，从环境变量中获取
TOKEN = os.getenv('BOT')
if not TOKEN:
    logging.error("未设置 BOT 环境变量")
    exit(1)

# GitHub API 搜索 URL
SEARCH_URL = 'https://api.github.com/search/code'

# 搜索关键词
KEYWORDS = ['spider', 'sites', 'key', 'lives', 'ads', 'wallpaper']

# 保存目录
SAVE_DIR = './tvbox'

# 时间戳文件
TIMESTAMP_FILE = './tvbox/last_search_timestamp.txt'

# 创建保存目录（如果不存在）
os.makedirs(SAVE_DIR, exist_ok=True)

# 重试机制参数
MAX_RETRIES = 3
RETRY_DELAY = 5  # 秒

def get_last_search_timestamp():
    """读取上次搜索的时间戳"""
    if os.path.exists(TIMESTAMP_FILE):
        with open(TIMESTAMP_FILE, 'r') as f:
            timestamp_str = f.read().strip()
            return datetime.fromisoformat(timestamp_str)
    else:
        # 如果没有时间戳文件，返回一个较早的默认时间
        return datetime(1970, 1, 1, tzinfo=timezone.utc)

def save_current_timestamp():
    """保存当前时间戳"""
    current_timestamp = datetime.now(timezone.utc).isoformat()
    with open(TIMESTAMP_FILE, 'w') as f:
        f.write(current_timestamp)

def search_and_download():
    """搜索并下载包含指定关键词的 JSON 文件，支持分页和时间戳过滤"""
    headers = {'Authorization': f'token {TOKEN}'}
    last_timestamp = get_last_search_timestamp()
    query = f'filename:json extension:json updated:>={last_timestamp.isoformat()} ' + ' '.join(KEYWORDS)
    page = 1

    while True:
        params = {'q': query, 'per_page': 100, 'page': page}
        for attempt in range(MAX_RETRIES):
            try:
                response = requests.get(SEARCH_URL, headers=headers, params=params, timeout=10)
                response.raise_for_status()
                break
            except requests.exceptions.RequestException as e:
                logging.warning(f"API 请求失败（尝试 {attempt+1}/{MAX_RETRIES}）：{e}")
                if attempt < MAX_RETRIES - 1:
                    time.sleep(RETRY_DELAY)
                else:
                    logging.error("API 请求失败，达到最大重试次数")
                    return

        results = response.json().get('items', [])
        if not results:
            logging.info("没有更多搜索结果")
            break

        # 处理当前页的结果
        for item in results:
            repo = item['repository']['full_name']
            path = item['path']
            download_url = f'https://raw.githubusercontent.com/{repo}/main/{path}'
            download_file(download_url, path)

        # 检查是否还有更多页
        if len(results) < 100:
            logging.info(f"搜索完成，共处理 {page} 页")
            break
        page += 1
        logging.info(f"处理第 {page} 页")

    # 更新时间戳
    save_current_timestamp()

def download_file(url, path):
    """下载文件并保存到指定目录"""
    file_name = os.path.basename(path)
    save_path = get_unique_filename(os.path.join(SAVE_DIR, file_name))

    # 检查本地文件是否已存在且无需更新
    if os.path.exists(save_path):
        logging.info(f"文件已存在，跳过下载：{save_path}")
        return

    for attempt in range(MAX_RETRIES):
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            with open(save_path, 'wb') as f:
                f.write(response.content)
            logging.info(f"已下载：{save_path}")
            break
        except requests.exceptions.RequestException as e:
            logging.warning(f"下载失败（尝试 {attempt+1}/{MAX_RETRIES}）：{url} - {e}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
            else:
                logging.error(f"下载失败，达到最大重试次数：{url}")

def get_unique_filename(file_path):
    """处理重名文件，返回唯一的文件名"""
    if not os.path.exists(file_path):
        return file_path
    base, ext = os.path.splitext(file_path)
    counter = 1
    while True:
        new_file_path = f"{base}_{counter}{ext}"
        if not os.path.exists(new_file_path):
            return new_file_path
        counter += 1

if __name__ == '__main__':
    search_and_download()
