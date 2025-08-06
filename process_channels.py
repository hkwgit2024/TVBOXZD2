import os
import re
import subprocess
import time
from datetime import datetime
import logging
import logging.handlers
import aiohttp
import asyncio
from urllib.parse import urlparse, urljoin
from concurrent.futures import ProcessPoolExecutor
from tenacity import retry, stop_after_attempt, wait_fixed
import json
import hashlib
import yaml
from cachetools import TTLCache
from tqdm.asyncio import tqdm
from bs4 import BeautifulSoup

# 配置日志系统
def setup_logging(config):
    log_level = getattr(logging, config['logging']['log_level'], logging.INFO)
    log_file = config['logging']['log_file'].replace('main.log', 'process_channels.log')
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger()
    logger.setLevel(log_level)

    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10*1024*1024, backupCount=1
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))

    logger.handlers = [file_handler, console_handler]
    return logger

# 加载配置文件
def load_config(config_path="config/config.yaml"):
    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file)
            logging.info("配置文件 config.yaml 加载成功")
            return config
    except FileNotFoundError:
        logging.error(f"错误：未找到配置文件 '{config_path}'")
        exit(1)
    except yaml.YAMLError as e:
        logging.error(f"错误：配置文件 '{config_path}' 格式错误: {e}")
        exit(1)
    except Exception as e:
        logging.error(f"错误：加载配置文件 '{config_path}' 失败: {e}")
        exit(1)

# 配置文件路径
CONFIG_PATH = "config/config.yaml"
CONFIG = load_config(CONFIG_PATH)
setup_logging(CONFIG)

# 从配置中获取文件路径
URLS_PATH = CONFIG['output']['paths']['channel_cache_file'].replace('channel_cache.json', 'urls.txt')
URL_STATES_PATH = CONFIG['output']['paths']['channel_cache_file'].replace('channel_cache.json', 'url_states.json')
IPTV_LIST_PATH = 'output/iptv.txt'
os.makedirs(os.path.dirname(IPTV_LIST_PATH), exist_ok=True)

# 初始化缓存
if CONFIG['url_state']['cache_enabled']:
    os.makedirs(CONFIG['url_state']['cache_dir'], exist_ok=True)
    content_cache = TTLCache(maxsize=1000, ttl=CONFIG['url_state']['cache_ttl'])

# --- 辅助函数 ---
def read_txt_to_array_local(file_name):
    """从本地 TXT 文件读取内容到数组"""
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            lines = [line.strip() for line in file if line.strip()]
        return lines
    except FileNotFoundError:
        logging.warning(f"文件 '{file_name}' 未找到")
        return []
    except Exception as e:
        logging.error(f"读取文件 '{file_name}' 失败: {e}")
        return []

def get_url_file_extension(url):
    """获取 URL 的文件扩展名"""
    try:
        parsed_url = urlparse(url)
        return os.path.splitext(parsed_url.path)[1].lower()
    except ValueError as e:
        logging.info(f"获取 URL 扩展名失败: {url} - {e}")
        return ""

def clean_url_params(url):
    """清理 URL 参数，仅保留方案、网络位置和路径"""
    try:
        parsed_url = urlparse(url)
        # 优化: 某些URL参数是必需的，例如直播token，不应被清理
        # 仅清理常见的跟踪参数
        query_params = parsed_url.query
        cleaned_query = re.sub(r'(?:&?utm_source=[^&]+|&?utm_medium=[^&]+|&?utm_campaign=[^&]+|&?utm_term=[^&]+|&?utm_content=[^&]+)', '', query_params)
        
        # 重新构建URL
        cleaned_url = urlparse(url)._replace(query=cleaned_query).geturl()
        return cleaned_url
    except ValueError as e:
        logging.info(f"清理 URL 参数失败: {url} - {e}")
        return url

def pre_screen_url(url):
    """根据配置预筛选 URL（协议、长度、无效模式）"""
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
        invalid_url_patterns = CONFIG['url_pre_screening']['invalid_url_patterns']
        compiled_invalid_url_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in invalid_url_patterns]
        for pattern in compiled_invalid_url_patterns:
            if pattern.search(url):
                return False
        if len(url) < 15:
            return False
        return True
    except ValueError as e:
        logging.info(f"预筛选过滤（URL 解析错误）: {url} - {e}")
        return False

@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True)
async def fetch_url_content_with_retry(url, url_states, session):
    """
    异步获取 URL 内容，使用缓存和 ETag/Last-Modified/Content-Hash。
    返回一个包含内容和 Content-Type 的字典。
    """
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
        async with session.get(url, headers=headers, timeout=10) as response:
            response.raise_for_status()

            if response.status == 304:
                logging.debug(f"URL 内容未变更 (304): {url}")
                return None

            content = await response.text()
            content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()
            content_type = response.headers.get('Content-Type', '').lower()

            if 'content_hash' in current_state and current_state['content_hash'] == content_hash:
                logging.debug(f"URL 内容未变更（哈希相同）: {url}")
                return None

            url_states[url] = {
                'etag': response.headers.get('ETag'),
                'last_modified': response.headers.get('Last-Modified'),
                'content_hash': content_hash,
                'last_checked': datetime.now().isoformat()
            }

            result = {'content': content, 'content_type': content_type, 'url': url}
            if CONFIG['url_state']['cache_enabled']:
                content_cache[url] = result

            logging.info(f"成功获取新内容: {url} (Content-Type: {content_type})")
            return result
    except aiohttp.ClientResponseError as e:
        if e.status in [429, 500, 502, 503, 504]:
            logging.error(f"请求 URL 失败（状态码 {e.status}）: {url}")
            raise
        logging.error(f"请求 URL 失败: {url} - {e}")
        return None
    except aiohttp.ClientTimeout:
        logging.error(f"请求 URL 超时: {url}")
        return None
    except Exception as e:
        logging.error(f"获取 URL 内容未知错误: {url} - {e}")
        return None

def load_url_states_local():
    """加载 URL 状态"""
    url_states = {}
    try:
        with open(URL_STATES_PATH, 'r', encoding='utf-8') as file:
            url_states = json.load(file)
    except FileNotFoundError:
        logging.warning(f"URL 状态文件 '{URL_STATES_PATH}' 未找到，使用空状态")
    except json.JSONDecodeError as e:
        logging.error(f"解析 '{URL_STATES_PATH}' 的 JSON 失败: {e}")
        return {}
    return url_states

def save_url_states_local(url_states):
    """保存 URL 状态到本地文件"""
    try:
        os.makedirs(os.path.dirname(URL_STATES_PATH), exist_ok=True)
        with open(URL_STATES_PATH, 'w', encoding='utf-8') as file:
            json.dump(url_states, file, indent=4, ensure_ascii=False)
    except Exception as e:
        logging.error(f"保存 URL 状态到 '{URL_STATES_PATH}' 失败: {e}")

# --- 新增和优化的解析器函数 ---

def _parse_m3u_or_txt(content):
    """解析 M3U 或纯文本文件"""
    extracted_channels = []
    lines = content.split('\n')
    channel_name = "未知频道"
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#EXTM3U'):
            continue
        
        if line.startswith('#EXTINF'):
            match = re.search(r'#EXTINF:-1.*?\,(.*)', line, re.IGNORECASE)
            channel_name = match.group(1).strip() if match else "未知频道"
        elif re.match(r'^[a-zA-Z0-9+.-]+://', line) and not line.startswith('#'):
            if channel_name == "未知频道":
                path_segments = urlparse(line).path.split('/')
                potential_name = path_segments[-1].split('.')[0] if path_segments else "未知频道"
                if potential_name:
                    channel_name = potential_name
            
            urls = [line]
            if '#' in line:
                urls = line.split('#')
            
            for url in urls:
                url = clean_url_params(url.strip())
                if url and pre_screen_url(url):
                    extracted_channels.append((channel_name, url))
            
            channel_name = "未知频道"
    return extracted_channels

def _parse_html(content, base_url):
    """解析 HTML 页面，提取视频链接"""
    extracted_channels = []
    soup = BeautifulSoup(content, 'html.parser')
    
    for link in soup.find_all('a', href=True):
        href = link['href']
        
        if any(ext in href for ext in ['.m3u', '.m3u8', '.ts', '.mpd', '.flv', '.avi', '.mp4', '.rmvb']):
            full_url = urljoin(base_url, href)
            
            channel_name = link.text.strip() or "未知频道"
            
            if pre_screen_url(full_url):
                extracted_channels.append((channel_name, full_url))
                
    return extracted_channels

def _parse_json(content, json_config):
    """
    解析 JSON 格式内容。
    需要用户在配置文件中定义解析规则。
    """
    extracted_channels = []
    try:
        data = json.loads(content)
        
        items = data
        path_keys = json_config.get('path', '').split('.')
        for key in path_keys:
            if isinstance(items, dict) and key in items:
                items = items[key]
            else:
                logging.warning(f"JSON 路径 '{json_config.get('path')}' 不存在或无法解析。")
                return []
        
        if not isinstance(items, list):
            logging.warning(f"JSON 路径 '{json_config.get('path')}' 不是一个列表。")
            return []
            
        for item in items:
            name_key = json_config.get('name_key', 'name')
            url_key = json_config.get('url_key', 'url')
            
            channel_name = item.get(name_key, "未知频道")
            channel_url = item.get(url_key)
            
            if channel_url and pre_screen_url(channel_url):
                extracted_channels.append((channel_name, channel_url))

    except json.JSONDecodeError:
        logging.error("JSON 解析失败。")
    except Exception as e:
        logging.error(f"解析 JSON 时发生错误: {e}")
        
    return extracted_channels


async def extract_channels_from_url(url, url_states, session):
    """从 URL 提取频道，支持多种文件格式，包括 GitHub Raw M3U 文件"""
    extracted_channels = []
    try:
        response_data = await fetch_url_content_with_retry(url, url_states, session)
        if response_data is None:
            return []
        
        content = response_data['content']
        content_type = response_data['content_type']
        
        # 优化：优先处理 GitHub raw URL，因为它的内容类型通常准确
        if 'raw.githubusercontent.com' in url.lower():
            logging.info(f"正在处理 GitHub Raw URL，尝试根据内容解析: {url}")
            # 对于GitHub Raw文件，我们不依赖Content-Type，因为有时候是text/plain
            # 直接尝试用M3U/TXT解析器
            if any(ext in content for ext in ['#EXTM3U', '#EXTINF']):
                extracted_channels = _parse_m3u_or_txt(content)
            elif json_config := CONFIG.get('json_configs', {}).get(url, {}):
                extracted_channels = _parse_json(content, json_config)
            else:
                logging.warning(f"GitHub Raw URL 内容无法识别为M3U或JSON格式，跳过: {url}")
        
        # 处理非 GitHub raw URL
        else:
            if 'text/html' in content_type:
                logging.info(f"解析 HTML 页面: {url}")
                extracted_channels = _parse_html(content, url)
            elif 'application/json' in content_type:
                logging.info(f"解析 JSON 响应: {url}")
                json_config = CONFIG.get('json_configs', {}).get(url, {})
                extracted_channels = _parse_json(content, json_config)
            else:
                # 否则，退回使用文件扩展名或假设为 M3U/TXT 格式
                extension = get_url_file_extension(url).lower()
                if any(ext in content for ext in ['#EXTM3U', '#EXTINF']) or extension in [".m3u", ".m3u8", ".txt", ".csv", ""]:
                    logging.info(f"解析 M3U/TXT 格式: {url}")
                    extracted_channels = _parse_m3u_or_txt(content)
                else:
                    logging.warning(f"无法识别的内容类型和扩展名，跳过解析: {url} (Content-Type: {content_type}, Extension: {extension})")
    
    except Exception as e:
        logging.error(f"从 {url} 提取频道失败: {e}")
    
    return extracted_channels

def filter_and_modify_channels(channels):
    """过滤和修改频道名称及 URL"""
    filtered_channels = []
    for name, url in channels:
        if not pre_screen_url(url):
            continue
        new_name = name
        for old_str, new_str in CONFIG['channel_name_replacements'].items():
            new_name = re.sub(old_str, new_str, new_name, flags=re.IGNORECASE)
        new_name = new_name.strip()
        if any(word.lower() in new_name.lower() for word in CONFIG['name_filter_words']):
            continue
        filtered_channels.append((new_name, url))
    return filtered_channels

def write_channels_to_file(file_path, channels):
    """将频道数据写入文件，并去重"""
    seen_channels = set()
    unique_channels = []
    for name, url in channels:
        if (name, url) not in seen_channels:
            seen_channels.add((name, url))
            unique_channels.append((name, url))

    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as file:
            for name, url in sorted(unique_channels, key=lambda x: x[0]):
                file.write(f"{name},{url}\n")
        logging.warning(f"成功将 {len(unique_channels)} 个唯一频道写入 '{file_path}'")
    except Exception as e:
        logging.error(f"写入文件 '{file_path}' 失败: {e}")

async def process_urls(urls, url_states):
    """异步处理 URL 列表"""
    async with aiohttp.ClientSession() as session:
        tasks = [extract_channels_from_url(url, url_states, session) for url in urls]
        results = []
        for future in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="提取频道"):
            try:
                channels = await future
                if channels:
                    results.extend(channels)
            except Exception as exc:
                logging.error(f"URL 提取异常: {exc}")
        return results

async def main():
    """异步主函数，执行频道提取、过滤和去重流程"""
    logging.warning("开始执行频道提取和过滤脚本")
    total_start_time = time.time()

    url_states = load_url_states_local()
    urls = read_txt_to_array_local(URLS_PATH)
    if not urls:
        logging.error("未在 urls.txt 中找到 URL，退出")
        exit(1)
    logging.warning(f"从 '{URLS_PATH}' 加载 {len(urls)} 个 URL")

    all_extracted_channels = await process_urls(urls, url_states)
    logging.warning(f"完成频道提取，过滤前总计提取 {len(all_extracted_channels)} 个频道")

    # 过滤和修改频道
    filtered_and_modified_channels = filter_and_modify_channels(all_extracted_channels)
    logging.warning(f"过滤和修改后剩余 {len(filtered_and_modified_channels)} 个频道")

    # 保存去重后的频道列表
    write_channels_to_file(IPTV_LIST_PATH, filtered_and_modified_channels)

    # 保存 URL 状态
    save_url_states_local(url_states)
    logging.warning("URL 状态已保存")

    total_elapsed_time = time.time() - total_start_time
    logging.warning(f"频道提取、过滤和去重脚本完成，总耗时 {total_elapsed_time:.2f} 秒")

if __name__ == "__main__":
    asyncio.run(main())
