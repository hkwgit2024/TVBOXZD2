import asyncio
import logging
import os
import re
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import aiohttp
import aiofiles
import yaml
from bs4 import BeautifulSoup
from tenacity import retry, stop_after_attempt, wait_exponential
import requests
import dns.resolver
import psutil
import subprocess
import json
from tqdm import tqdm

# 配置日志
def setup_logging(log_level):
    logging.basicConfig(
        level=getattr(logging, log_level.upper(), logging.INFO),
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('iptv_script.log', encoding='utf-8'),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

# 加载配置文件
def load_config():
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        logger.info(f"Loaded config from {CONFIG_PATH}")
        return config
    except Exception as e:
        logger.error(f"Error loading config from {CONFIG_PATH}: {e}")
        return {}

# 加载 URL 列表
def load_urls(max_urls=50):
    try:
        with open(URLS_PATH, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        urls = urls[:max_urls]  # 限制最大 URL 数量
        logger.info(f"Loaded {len(urls)} URLs from {URLS_PATH} (limited to {max_urls})")
        return urls
    except Exception as e:
        logger.error(f"Error loading URLs from {URLS_PATH}: {e}")
        return []

# 加载无效 URL 列表
def load_invalid_urls():
    try:
        if os.path.exists(INVALID_URLS_PATH):
            with open(INVALID_URLS_PATH, 'r', encoding='utf-8') as f:
                invalid_urls = {line.strip() for line in f if line.strip() and not line.startswith('#')}
            logger.info(f"Loaded {len(invalid_urls)} invalid URLs from {INVALID_URLS_PATH}")
            return invalid_urls
        else:
            logger.info(f"No invalid URLs file found at {INVALID_URLS_PATH}")
            return set()
    except Exception as e:
        logger.error(f"Error loading invalid URLs from {INVALID_URLS_PATH}: {e}")
        return set()

# 保存无效 URL
def save_invalid_url(url, reason="Invalid"):
    try:
        with open(INVALID_URLS_PATH, 'a', encoding='utf-8') as f:
            f.write(f"{url} # {reason}\n")
        logger.info(f"Added invalid URL to {INVALID_URLS_PATH}: {url} ({reason})")
    except Exception as e:
        logger.error(f"Error saving invalid URL to {INVALID_URLS_PATH}: {e}")

# 验证 URL 是否有效
def is_valid_url(url, invalid_patterns, allowed_protocols, stream_extensions):
    for pattern in invalid_patterns:
        if re.search(pattern, url, re.IGNORECASE):
            save_invalid_url(url, "Matches invalid pattern")
            return False
    return (re.match(r'^(https?|rtmp|rtp|p3p|udp|rtsp)://[\S]+$', url, re.IGNORECASE) and
            any(url.lower().endswith(ext) for ext in stream_extensions))

# 解析 HLS 变体播放列表
async def resolve_hls_variant(url, timeout=15):
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            async with session.get(url, headers={'User-Agent': 'Mozilla/5.0'}) as response:
                response.raise_for_status()
                content = await response.text()
                if content.startswith('#EXTM3U'):
                    lines = content.splitlines()
                    for line in lines:
                        if line.startswith('#EXT-X-STREAM-INF'):
                            sub_url = lines[lines.index(line) + 1].strip()
                            # 构造完整子播放列表 URL
                            if not sub_url.startswith('http'):
                                base_url = url.rsplit('/', 1)[0]
                                sub_url = f"{base_url}/{sub_url}"
                            return sub_url
                return url  # 非变体播放列表，直接返回原 URL
    except Exception as e:
        logger.warning(f"Error resolving HLS variant for {url}: {e}")
        save_invalid_url(url, "Failed to resolve HLS variant")
        return None

# 应用频道名称替换和过滤
def process_channel_name(name, replacements, filter_words):
    # 过滤无效名称
    if not name or name in ['未知频道', 'Unknown']:  # 过滤“未知频道”
        logger.warning(f"Channel name filtered out: {name} (invalid name)")
        return None
    # 应用替换规则
    for old, new in replacements.items():
        name = name.replace(old, new)
    # 过滤无效名称
    for word in filter_words:
        if word.lower() in name.lower():
            logger.warning(f"Channel name filtered out: {name} (contains {word})")
            return None
    return name

# 异步获取 URL 内容
@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
async def fetch_url_content_with_retry(url, timeout=15):
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
            async with session.get(url, headers={'User-Agent': 'Mozilla/5.0'}) as response:
                response.raise_for_status()
                content = await response.text()
                logger.debug(f"Fetched content from {url}")
                return content
    except Exception as e:
        logger.error(f"Request error fetching URL (after retries): {url} - {e}")
        save_invalid_url(url, "Fetch failed")
        return None

# 提取频道信息
def extract_channels_from_content(content, replacements, filter_words, invalid_patterns, allowed_protocols, stream_extensions):
    logger.info("Starting channel extraction from content")
    channels = []
    try:
        # 处理 M3U 格式
        if content.startswith('#EXTM3U'):
            lines = content.splitlines()
            i = 0
            while i < len(lines):
                line = lines[i].strip()
                if line.startswith('#EXTINF:'):
                    name = ''
                    tvg_name_match = re.search(r'tvg-name="([^"]*)"', line)
                    if tvg_name_match:
                        name = tvg_name_match.group(1).strip()
                    else:
                        try:
                            name = line.split(',', 1)[1].strip()
                        except IndexError:
                            logger.warning(f"Invalid #EXTINF line, no name found: {line}")
                            i += 1
                            continue
                    
                    # 应用名称替换和过滤
                    processed_name = process_channel_name(name, replacements, filter_words)
                    if not processed_name:
                        i += 2
                        continue
                    
                    if i + 1 < len(lines):
                        url = lines[i + 1].strip()
                        if url and is_valid_url(url, invalid_patterns, allowed_protocols, stream_extensions):
                            channels.append((processed_name, url))
                            logger.debug(f"Extracted channel: {processed_name}, {url}")
                        else:
                            logger.warning(f"Invalid or non-stream URL skipped: {url}")
                            if url:
                                save_invalid_url(url, "Invalid stream URL")
                    else:
                        logger.warning(f"No URL found for #EXTINF line: {line}")
                    i += 2
                else:
                    i += 1
        # 处理 JSON 格式
        elif content.startswith('{'):
            data = json.loads(content)
            for item in data.get('channels', []):
                name = item.get('name', '')
                url = item.get('url', '')
                processed_name = process_channel_name(name, replacements, filter_words)
                if processed_name and url and is_valid_url(url, invalid_patterns, allowed_protocols, stream_extensions):
                    channels.append((processed_name, url))
                    logger.debug(f"Extracted JSON channel: {processed_name}, {url}")
                else:
                    logger.warning(f"Invalid JSON channel skipped: name={name}, url={url}")
                    if url:
                        save_invalid_url(url, "Invalid JSON stream URL")
        # 处理纯文本格式
        else:
            for line in content.splitlines():
                line = line.strip()
                if ',' in line and not line.startswith('#'):
                    name, url = line.split(',', 1)
                    name, url = name.strip(), url.strip()
                    processed_name = process_channel_name(name, replacements, filter_words)
                    if processed_name and url and is_valid_url(url, invalid_patterns, allowed_protocols, stream_extensions):
                        channels.append((processed_name, url))
                        logger.debug(f"Extracted text channel: {processed_name}, {url}")
                    else:
                        logger.warning(f"Invalid text channel skipped: {line}")
                        if url:
                            save_invalid_url(url, "Invalid text stream URL")
        
        logger.info(f"Extracted {len(channels)} channels from content")
    except Exception as e:
        logger.error(f"Error extracting channels: {e}")
    return channels

# 保存频道到文件
def save_channels_to_file(channels, filepath, format="m3u"):
    try:
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        # 去重频道，保留第一次出现的记录
        seen_names = set()
        unique_channels = []
        for name, url in channels:
            if name.lower() not in seen_names:
                seen_names.add(name.lower())
                unique_channels.append((name, url))
            else:
                logger.warning(f"Duplicate channel skipped: {name}, {url}")
        
        with open(filepath, 'w', encoding='utf-8') as f:
            if format == "m3u":
                f.write("#EXTM3U\n")
                for name, url in unique_channels:
                    f.write(f"#EXTINF:-1,{name}\n{url}\n")
            else:  # 纯文本格式
                if not unique_channels:
                    f.write("# No channels extracted\n")
                for name, url in unique_channels:
                    f.write(f"{name},{url}\n")
        logger.info(f"Saved {len(unique_channels)} channels to {filepath} in {format} format")
    except Exception as e:
        logger.error(f"Error saving channels to {filepath}: {e}")

# 按分类保存频道
def save_categorized_channels(channels, categories):
    categorized = {cat['name']: [] for cat in categories}
    uncategorized = []
    
    for name, url in channels:
        matched = False
        for cat in categories:
            if re.search(cat['pattern'], name, re.IGNORECASE):
                categorized[cat['name']].append((name, url))
                matched = True
                break
        if not matched:
            uncategorized.append((name, url))
    
    # 保存分类频道（使用 M3U 格式）
    for cat in categories:
        if categorized[cat['name']]:
            save_channels_to_file(categorized[cat['name']], cat['file'], format="m3u")
    
    # 保存未分类频道（使用纯文本格式）
    if uncategorized:
        save_channels_to_file(uncategorized, UNCATEGORIZED_CHANNELS_PATH, format="text")
    
    return uncategorized

# 验证频道有效性
async def check_channel_validity(url, timeout=15):
    try:
        # 解析 HLS 变体播放列表
        resolved_url = await resolve_hls_variant(url, timeout)
        if not resolved_url:
            return False
        
        cmd = ['ffprobe', '-v', 'error', '-timeout', '15000000', '-i', resolved_url]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode == 0:
            logger.debug(f"Validated channel: {resolved_url}")
            return True
        else:
            logger.warning(f"Invalid channel: {resolved_url} (ffprobe error)")
            save_invalid_url(url, "ffprobe validation failed")
            return False
    except subprocess.TimeoutExpired:
        logger.warning(f"Timeout checking channel: {url}")
        save_invalid_url(url, "Timeout during validation")
        return False
    except Exception as e:
        logger.error(f"Error checking channel {url}: {e}")
        save_invalid_url(url, f"Validation error: {str(e)}")
        return False

# 异步验证频道
async def validate_channels(channels, workers=10, timeout=15):
    valid_channels = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        loop = asyncio.get_event_loop()
        tasks = [loop.run_in_executor(executor, lambda u=url: asyncio.run(check_channel_validity(u, timeout)) for _, url in channels]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for (name, url), result in zip(channels, results):
            if isinstance(result, bool) and result:
                valid_channels.append((name, url))
            logger.info(f"Checked channel {name}: {'Valid' if result else 'Invalid'}")
    return valid_channels

# 保存 URL 状态
def save_url_states(url_states):
    try:
        with open(URL_STATES_PATH, 'w', encoding='utf-8') as f:
            yaml.safe_dump(url_states, f)
        logger.info(f"Saved {len(url_states)} URL states to {URL_STATES_PATH}")
    except Exception as e:
        logger.error(f"Error saving URL states: {e}")

# 主函数
async def main():
    global logger, config
    config = load_config()
    logger = setup_logging(config.get('log_level', 'INFO'))
    logger.info("Starting IPTV channel update script")
    
    # 加载 URL 列表
    urls = load_urls(max_urls=50)  # 限制为 50 个 URL
    if not urls:
        logger.error("No URLs loaded, exiting")
        return
    
    # 加载无效 URL 列表
    invalid_urls = load_invalid_urls()
    
    # 加载现有 URL 状态
    url_states = {}
    try:
        with open(URL_STATES_PATH, 'r', encoding='utf-8') as f:
            url_states = yaml.safe_load(f) or {}
        logger.info(f"Loaded {len(url_states)} URL states from {URL_STATES_PATH}")
    except Exception:
        logger.warning(f"No URL states found at {URL_STATES_PATH}, starting fresh")
    
    # 提取频道
    raw_channels = []
    new_url_states = {}
    for url in tqdm(urls, desc="Processing URLs"):
        if url in invalid_urls or not is_valid_url(url, 
                                                  config['rules']['invalid_url_patterns'],
                                                  config['rules']['url_pre_screening']['allowed_protocols'],
                                                  config['rules']['url_pre_screening']['stream_extensions']):
            logger.info(f"Skipping invalid URL: {url}")
            new_url_states[url] = {'valid': False, 'last_checked': datetime.now().isoformat()}
            continue
        try:
            content = await fetch_url_content_with_retry(url, timeout=config['request_timeout'])
            if content:
                channels = extract_channels_from_content(
                    content,
                    config['channel_name_replacements'],
                    config['rules']['name_filter_words'],
                    config['rules']['invalid_url_patterns'],
                    config['rules']['url_pre_screening']['allowed_protocols'],
                    config['rules']['url_pre_screening']['stream_extensions']
                )
                raw_channels.extend(channels)
                new_url_states[url] = {'valid': True, 'last_checked': datetime.now().isoformat()}
            else:
                new_url_states[url] = {'valid': False, 'last_checked': datetime.now().isoformat()}
        except Exception as e:
            logger.error(f"Failed to process URL {url}: {e}")
            new_url_states[url] = {'valid': False, 'last_checked': datetime.now().isoformat()}
    
    # 保存未分类频道（纯文本格式）
    logger.info(f"Extracted {len(raw_channels)} raw channels")
    save_channels_to_file(raw_channels, UNCATEGORIZED_CHANNELS_PATH, format="text")
    
    # 按分类保存频道
    uncategorized = save_categorized_channels(raw_channels, config['categories'])
    
    # 合并频道（去重）
    unique_channels = list(dict.fromkeys(uncategorized))  # 保留顺序去重
    logger.info(f"Total unique channels to check: {len(unique_channels)}")
    
    # 验证频道有效性
    valid_channels = await validate_channels(
        unique_channels,
        workers=config['channel_check_workers'],
        timeout=config['check_timeout']
    )
    logger.info(f"Completed channel validity check. Valid channels: {len(valid_channels)}")
    
    # 保存最终 IPTV 列表
    save_channels_to_file(valid_channels, IPTV_LIST_PATH, format=config['output_format'])
    
    # 更新 URL 状态
    url_states.update(new_url_states)
    save_url_states(url_states)
    
    # 清理临时文件
    try:
        for folder in [config['paths']['channels_dir'], config['paths']['output_dir']]:
            if os.path.exists(folder):
                for file in os.listdir(folder):
                    if file not in [os.path.basename(cat['file']) for cat in config['categories']]:
                        os.remove(os.path.join(folder, file))
        logger.info("Temporary files cleanup completed")
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")
    
    logger.info("Script finished")

# 路径配置
CONFIG_PATH = os.getenv('CONFIG_PATH', 'config/config.yaml')
URLS_PATH = os.getenv('URLS_PATH', 'config/urls.txt')
URL_STATES_PATH = os.getenv('URL_STATES_PATH', 'config/url_states.yaml')
INVALID_URLS_PATH = os.getenv('INVALID_URLS_PATH', 'config/invalid_urls.txt')
UNCATEGORIZED_CHANNELS_PATH = 'uncategorized_channels.txt'
IPTV_LIST_PATH = 'iptv_list.txt'

if __name__ == "__main__":
    asyncio.run(main())
