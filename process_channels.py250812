import os
import re
import logging
import yaml
import aiohttp
import asyncio
import hashlib
from urllib.parse import urlparse
from cachetools import TTLCache
from datetime import datetime
import tenacity
from tqdm.asyncio import tqdm
from aiohttp import ClientSession
from typing import List, Tuple, Dict, Optional

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('process_channels.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)

# 加载配置文件
with open('config/config.yaml', 'r', encoding='utf-8') as f:
    CONFIG = yaml.safe_load(f)

# 初始化缓存
content_cache = TTLCache(maxsize=10000, ttl=CONFIG['url_state']['cache_ttl'])

def load_url_states() -> Dict[str, Dict]:
    """加载 URL 状态"""
    try:
        with open('config/url_states.yaml', 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        return {}

def save_url_states(url_states: Dict[str, Dict]):
    """保存 URL 状态"""
    with open('config/url_states.yaml', 'w', encoding='utf-8') as f:
        yaml.safe_dump(url_states, f, allow_unicode=True)

def get_url_file_extension(url: str) -> str:
    """获取 URL 文件扩展名"""
    parsed_url = urlparse(url)
    return os.path.splitext(parsed_url.path)[1].lower()

def pre_screen_url(url: str) -> bool:
    """预筛选 URL"""
    if not isinstance(url, str) or not url:
        return False
    if not re.match(r'^[a-zA-Z0-9+.-]+://', url):
        return False
    if re.search(r'[^\x00-\x7F]', url) or ' ' in url:
        return False
    try:
        parsed_url = urlparse(url)
        if parsed_url.scheme not in CONFIG['url_pre_screening']['allowed_protocols']:
            return False
        if not parsed_url.netloc:
            return False
        # 添加文件扩展名检查
        extension = os.path.splitext(parsed_url.path)[1].lower()
        if extension not in ['.m3u', '.m3u8', '.txt', '.csv', '']:
            logging.debug(f"预筛选过滤（不支持的扩展名）: {url}")
            return False
        invalid_url_patterns = CONFIG['url_pre_screening']['invalid_url_patterns']
        compiled_invalid_url_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in invalid_url_patterns]
        for pattern in compiled_invalid_url_patterns:
            if pattern.search(url):
                return False
        if len(url) < 15:
            return False
        return True
    except ValueError as e:
        logging.debug(f"预筛选过滤（URL 解析错误）: {url} - {e}")
        return False

def clean_url_params(url: str) -> str:
    """清理 URL 参数"""
    try:
        parsed_url = urlparse(url)
        return f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
    except ValueError:
        return url

def convert_m3u_to_txt(m3u_content: str) -> str:
    """将 M3U 格式转换为 TXT 格式"""
    lines = m3u_content.split('\n')
    result = []
    current_name = None
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith('#EXTINF'):
            parts = line.split(',', 1)
            if len(parts) > 1:
                current_name = parts[1].strip()
        elif line.startswith('http') and current_name:
            result.append(f"{current_name},{line}")
            current_name = None
    return '\n'.join(result)

@tenacity.retry(
    stop=tenacity.stop_after_attempt(3),
    wait=tenacity.wait_fixed(5),
    reraise=True,
    retry=tenacity.retry_if_exception_type(aiohttp.ClientError)
)
async def fetch_url_content_with_retry(url: str, url_states: Dict[str, Dict], session: ClientSession) -> Optional[str]:
    """获取 URL 内容，支持重试和缓存"""
    if CONFIG['url_state']['cache_enabled'] and url in content_cache:
        logging.debug(f"从缓存读取 URL 内容: {url}")
        return content_cache[url]

    headers = {}
    current_state = url_states.get(url, {})
    if 'etag' in current_state:
        headers['If-None-Match'] = current_state['etag']
    if 'last_modified' in current_state:
        headers['If-Modified-Since'] = current_state['last_modified']

    try:
        logging.debug(f"正在请求 URL: {url}，headers: {headers}")
        async with session.get(url, headers=headers, timeout=10) as response:
            logging.debug(f"URL: {url}，状态码: {response.status}")
            response.raise_for_status()

            if response.status == 304:
                logging.debug(f"URL 内容未变更 (304): {url}")
                return None

            content = await response.text()
            content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()

            if 'content_hash' in current_state and current_state['content_hash'] == content_hash:
                logging.debug(f"URL 内容未变更（哈希相同）: {url}")
                return None

            url_states[url] = {
                'etag': response.headers.get('ETag'),
                'last_modified': response.headers.get('Last-Modified'),
                'content_hash': content_hash,
                'last_checked': datetime.now().isoformat()
            }

            if CONFIG['url_state']['cache_enabled']:
                content_cache[url] = content

            logging.info(f"成功获取新内容: {url}")
            return content
    except aiohttp.ClientResponseError as e:
        logging.error(f"请求 URL 失败（状态码 {e.status}）: {url} - {e}")
        raise
    except aiohttp.ClientTimeout:
        logging.error(f"请求 URL 超时: {url}")
        return None
    except Exception as e:
        logging.error(f"获取 URL 内容未知错误: {url} - {e}")
        return None

async def extract_channels_from_url(url: str, url_states: Dict[str, Dict], session: ClientSession) -> List[Tuple[str, str]]:
    """从 URL 提取频道"""
    extracted_channels = []
    try:
        text = await fetch_url_content_with_retry(url, url_states, session)
        if text is None:
            logging.debug(f"URL 无新内容: {url}")
            return []

        extension = get_url_file_extension(url).lower()
        if extension in [".m3u", ".m3u8"]:
            text = convert_m3u_to_txt(text)
        elif extension not in [".txt", ".csv", ""]:
            logging.info(f"不支持的文件扩展名: {url}")
            return []

        lines = text.split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if "," in line and "://" in line:
                parts = line.split(',', 1)
                if len(parts) != 2:
                    continue
                channel_name, channel_address_raw = parts
                channel_name = channel_name.strip() or "未知频道"
                channel_address_raw = channel_address_raw.strip()

                if not re.match(r'^[a-zA-Z0-9+.-]+://', channel_address_raw):
                    continue

                if '#' in channel_address_raw:
                    url_list = channel_address_raw.split('#')
                    for channel_url in url_list:
                        channel_url = clean_url_params(channel_url.strip())
                        if channel_url and pre_screen_url(channel_url):
                            extracted_channels.append((channel_name, channel_url))
                else:
                    channel_url = clean_url_params(channel_address_raw)
                    if channel_url and pre_screen_url(channel_url):
                        extracted_channels.append((channel_name, channel_url))
    except BaseException as e:
        logging.error(f"从 {url} 提取频道失败: {e}")
        return []
    except Exception as e:
        logging.error(f"从 {url} 提取频道失败（非标准异常）: {e}")
        return []
    return extracted_channels

def filter_channels(channels: List[Tuple[str, str]]) -> List[Tuple[str, str]]:
    """过滤频道"""
    name_filter_words = CONFIG.get('name_filter_words', [])
    filtered_channels = []
    for name, url in channels:
        if any(word.lower() in name.lower() for word in name_filter_words):
            continue
        filtered_channels.append((name, url))
    return filtered_channels

async def main():
    """主函数"""
    url_states = load_url_states()
    all_channels = []

    # 读取 URL 列表
    with open('config/urls.txt', 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and pre_screen_url(line.strip())]

    async with aiohttp.ClientSession() as session:
        tasks = [extract_channels_from_url(url, url_states, session) for url in urls]
        for task in tqdm.as_completed(tasks, total=len(tasks), desc="提取频道"):
            channels = await task
            all_channels.extend(channels)

    logging.info(f"完成频道提取，过滤前总计提取 {len(all_channels)} 个频道")
    filtered_channels = filter_channels(all_channels)
    logging.info(f"过滤和修改后剩余 {len(filtered_channels)} 个频道")

    # 保存结果
    os.makedirs('output', exist_ok=True)
    with open('output/iptv.txt', 'w', encoding='utf-8') as f:
        for name, url in filtered_channels:
            f.write(f"{name},{url}\n")

    # 保存 URL 状态
    save_url_states(url_states)

if __name__ == "__main__":
    asyncio.run(main())
