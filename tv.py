import os
import re
import json
import time
import yaml
import asyncio
import aiohttp
import logging
import hashlib
import aiofiles
import requests
from datetime import datetime
from logging.handlers import RotatingFileHandler
from tenacity import retry, stop_after_attempt, wait_fixed
from urllib.parse import urlparse, unquote
from concurrent.futures import ThreadPoolExecutor

# 日志配置
log_file = 'iptv_crawler.log'  # 统一日志文件
handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=5)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler.setFormatter(formatter)
logger = logging.getLogger()
logger.setLevel(os.getenv('LOG_LEVEL', 'INFO'))
logger.addHandler(handler)

# 全局配置
CONFIG_PATH = os.getenv('CONFIG_PATH', 'config/config.yaml')
URLS_PATH = os.getenv('URLS_PATH', 'urls.txt')
URL_STATES_PATH = os.getenv('URL_STATES_PATH', 'config/url_states.json')
GITHUB_TOKEN = os.getenv('BOT')
CHANNEL_CACHE_PATH = None  # 将在 load_config 中设置
KEYWORD_STATS_PATH = None
STREAM_SKIP_FAILED_HOURS = 24
CHANNEL_CACHE_TTL = None
CATEGORY_RULES = None

# 加载配置
def load_config():
    content = fetch_from_github(CONFIG_PATH)
    if content:
        try:
            config = yaml.safe_load(content)
            global CHANNEL_CACHE_PATH, KEYWORD_STATS_PATH, CHANNEL_CACHE_TTL, CATEGORY_RULES
            CHANNEL_CACHE_PATH = config.get('paths', {}).get('channel_cache_file', 'config/channel_cache.json')
            KEYWORD_STATS_PATH = config.get('paths', {}).get('keyword_stats_file', 'config/keyword_stats.json')
            CHANNEL_CACHE_TTL = config.get('channel_cache_ttl', 86400)
            CATEGORY_RULES = config.get('category_rules', [])
            logger.info("成功加载 config.yaml")
            return config
        except yaml.YAMLError as e:
            logger.error(f"解析 YAML 配置 {CONFIG_PATH} 失败：{e}")
            exit(1)
    logger.error(f"无法加载配置 {CONFIG_PATH}")
    exit(1)

CONFIG = load_config()

# 文件操作类
class FileHandler:
    def __init__(self, is_remote=False, github_token=None):
        self.is_remote = is_remote
        self.github_token = github_token

    def read_txt(self, path):
        try:
            if self.is_remote:
                content = fetch_from_github(path)
                return content.splitlines() if content else []
            with open(path, 'r', encoding='utf-8') as f:
                return f.read().splitlines()
        except Exception as e:
            logger.error(f"读取文件 {path} 失败：{e}")
            return []

    def write_txt(self, path, lines, commit_message, backup=False):
        try:
            content = '\n'.join(lines) + '\n'
            if self.is_remote:
                save_to_github(path, content, commit_message, backup)
            else:
                os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
                with open(path, 'w', encoding='utf-8') as f:
                    f.write(content)
            logger.info(f"成功写入文件 {path}")
        except Exception as e:
            logger.error(f"写入文件 {path} 失败：{e}")

# GitHub API 操作
def fetch_from_github(path):
    try:
        url = f"https://api.github.com/repos/{os.getenv('REPO_OWNER')}/{os.getenv('REPO_NAME')}/contents/{path}"
        headers = {'Authorization': f'token {GITHUB_TOKEN}', 'Accept': 'application/vnd.github.v3+json'}
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        content = response.json().get('content')
        if content:
            import base64
            return base64.b64decode(content).decode('utf-8')
        return None
    except requests.RequestException as e:
        logger.error(f"从 GitHub 获取 {path} 失败：{e}")
        return None

def save_to_github(path, content, commit_message, backup=False):
    try:
        url = f"https://api.github.com/repos/{os.getenv('REPO_OWNER')}/{os.getenv('REPO_NAME')}/contents/{path}"
        headers = {'Authorization': f'token {GITHUB_TOKEN}', 'Accept': 'application/vnd.github.v3+json'}
        response = requests.get(url, headers=headers)
        sha = response.json().get('sha') if response.status_code == 200 else None
        encoded_content = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        payload = {
            'message': commit_message,
            'content': encoded_content,
            'sha': sha,
            'branch': 'main'
        }
        response = requests.put(url, headers=headers, json=payload)
        response.raise_for_status()
        logger.debug(f"成功保存 {path} 到 GitHub")
    except requests.RequestException as e:
        logger.error(f"保存 {path} 到 GitHub 失败：{e}")

# 缓存和状态管理
def load_channel_cache():
    content = fetch_from_github(CHANNEL_CACHE_PATH)
    try:
        return json.loads(content) if content else {}
    except json.JSONDecodeError as e:
        logger.error(f"解码 {CHANNEL_CACHE_PATH} 失败：{e}")
        return {}

def save_channel_cache(channel_cache):
    try:
        content = json.dumps(channel_cache, indent=4, ensure_ascii=False)
        FileHandler(is_remote=True, github_token=GITHUB_TOKEN).write_txt(CHANNEL_CACHE_PATH, [content], "更新频道缓存", backup=True)
        logger.info("成功保存 channel_cache 到 config/channel_cache.json")
    except Exception as e:
        logger.error(f"保存 channel_cache 失败：{e}")

def load_url_states():
    content = fetch_from_github(URL_STATES_PATH)
    try:
        return json.loads(content) if content else {}
    except json.JSONDecodeError as e:
        logger.error(f"解码 {URL_STATES_PATH} 失败：{e}")
        return {}

def save_url_states(url_states):
    try:
        content = json.dumps(url_states, indent=4, ensure_ascii=False)
        FileHandler(is_remote=True, github_token=GITHUB_TOKEN).write_txt(URL_STATES_PATH, [content], "更新 URL 状态", backup=True)
        logger.info("成功保存 url_states 到 config/url_states.json")
    except Exception as e:
        logger.error(f"保存 url_states 失败：{e}")

def save_keyword_stats(keyword_stats):
    try:
        content = json.dumps(keyword_stats, indent=4, ensure_ascii=False)
        FileHandler(is_remote=True, github_token=GITHUB_TOKEN).write_txt(KEYWORD_STATS_PATH, [content], "更新关键词统计", backup=True)
        logger.info("成功保存 keyword_stats 到 config/keyword_stats.json")
    except Exception as e:
        logger.error(f"保存 keyword_stats 失败：{e}")

# URL 发现
@retry(stop=stop_after_attempt(3), wait=wait_fixed(30))
async def discover_urls():
    keyword_stats = {}
    async with aiohttp.ClientSession() as session:
        for keyword in CONFIG.get('search_keywords', []):
            keyword_stats[keyword] = {"success": 0, "failed": 0, "urls": set()}
            for page in range(1, CONFIG.get('max_search_pages', 1) + 1):
                try:
                    url = f"https://api.github.com/search/code?q={keyword}&per_page={CONFIG.get('per_page', 100)}&page={page}"
                    headers = {'Authorization': f'token {GITHUB_TOKEN}', 'Accept': 'application/vnd.github.v3+json'}
                    async with session.get(url, headers=headers, timeout=CONFIG.get('github_api_timeout', 30)) as response:
                        response.raise_for_status()
                        data = await response.json()
                        keyword_stats[keyword]["success"] += 1
                        for item in data.get('items', []):
                            raw_url = item.get('html_url').replace('blob/', 'raw/')
                            keyword_stats[keyword]["urls"].add(raw_url)
                except aiohttp.ClientError as e:
                    logger.error(f"搜索 '{keyword}' 第 {page} 页失败：{e}")
                    keyword_stats[keyword]["failed"] += 1
                    continue
    urls = set()
    for stats in keyword_stats.values():
        urls.update(stats['urls'])
    FileHandler(is_remote=True, github_token=GITHUB_TOKEN).write_txt(URLS_PATH, sorted(urls), "更新 URL 列表", backup=True)
    save_keyword_stats(keyword_stats)
    logger.info(f"发现 {len(urls)} 个唯一 URL")

# 频道提取
def extract_channels_from_url(url, url_states):
    content = fetch_url_content(url, url_states)
    channels = set()
    if content:
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if line.startswith('#EXTINF'):
                name = line.split('tvg-name="')[1].split('"')[0] if 'tvg-name="' in line else line.split(',')[-1].strip()
                if i + 1 < len(lines) and lines[i + 1].startswith('http'):
                    url = lines[i + 1].strip()
                    channels.add((name, url))
    return channels

def fetch_url_content(url, url_states):
    current_state = url_states.get(url, {})
    headers = {}
    if 'etag' in current_state:
        headers['If-None-Match'] = current_state['etag']
    if 'last_modified' in current_state:
        headers['If-Modified-Since'] = current_state['last_modified']
    try:
        response = requests.get(url, headers=headers, timeout=CONFIG.get('channel_fetch_timeout', 15))
        if response.status_code == 304:
            url_states[url]['last_checked'] = datetime.now().isoformat()
            save_url_states(url_states)
            return None
        response.raise_for_status()
        content = response.text
        content_hash = hashlib.md5(content.encode('utf-8')).hexdigest()
        if 'content_hash' in current_state and current_state['content_hash'] == content_hash:
            url_states[url]['last_checked'] = datetime.now().isoformat()
            save_url_states(url_states)
            return None
        url_states[url].update({
            'etag': response.headers.get('ETag', ''),
            'last_modified': response.headers.get('Last-Modified', ''),
            'content_hash': content_hash,
            'last_checked': datetime.now().isoformat()
        })
        save_url_states(url_states)
        return content
    except requests.RequestException as e:
        logger.error(f"获取 URL {url} 内容失败：{e}")
        return None

# 频道验证
async def check_channel_validity_async(name, url, url_states, channel_cache):
    current_time = datetime.now()
    current_state = url_states.get(url, {})
    if 'stream_check_failed_at' in current_state:
        last_failed = datetime.fromisoformat(current_state['stream_check_failed_at'])
        if (current_time - last_failed).total_seconds() / 3600 < STREAM_SKIP_FAILED_HOURS:
            return None, False
    cache_entry = channel_cache.get(url, {})
    if cache_entry.get('is_valid') and 'last_successful_check' in cache_entry:
        last_check = datetime.fromisoformat(cache_entry['last_successful_check'])
        if (current_time - last_check).total_seconds() < CHANNEL_CACHE_TTL:
            logger.info(f"使用缓存：{name} ({url})，有效")
            return cache_entry.get('elapsed_time'), True
    start_time = time.time()
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=CONFIG.get('channel_check_timeout', 8)) as response:
                response.raise_for_status()
                elapsed_time = (time.time() - start_time) * 1000
                channel_cache[url] = {
                    'name': name,
                    'is_valid': True,
                    'elapsed_time': elapsed_time,
                    'last_stream_checked': current_time.isoformat(),
                    'last_successful_check': current_time.isoformat()
                }
                url_states[url]['stream_fail_count'] = 0
                save_url_states(url_states)
                return elapsed_time, True
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logger.error(f"验证频道 {name} ({url}) 失败：{e}")
        channel_cache[url] = {
            'name': name,
            'is_valid': False,
            'elapsed_time': None,
            'last_stream_checked': current_time.isoformat()
        }
        url_states[url]['stream_check_failed_at'] = current_time.isoformat()
        url_states[url]['stream_fail_count'] = current_state.get('stream_fail_count', 0) + 1
        save_url_states(url_states)
        return None, False

async def check_channels_async(channels, url_states, channel_cache):
    logger.info(f"开始验证 {len(channels)} 个频道")
    tasks = [check_channel_validity_async(name, url, url_states, channel_cache) for name, url in channels]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    valid_channels = []
    for (t, valid), (name, url) in zip(results, channels):
        if isinstance(t, Exception):
            logger.error(f"验证频道 {name} ({url}) 时发生异常：{t}")
            continue
        if valid:
            valid_channels.append((t, f"{name},{url}"))
    logger.info(f"有效频道数量：{len(valid_channels)}")
    if not valid_channels:
        logger.warning("没有发现有效频道，可能原因：URL 无效、过滤规则严格、缓存跳过或网络问题")
    save_channel_cache(channel_cache)
    return valid_channels

# 分类和保存
def categorize_channel(channel_name):
    for rule in CATEGORY_RULES:
        if re.search(rule['pattern'], channel_name, re.IGNORECASE):
            logger.debug(f"频道 {channel_name} 匹配规则 {rule['pattern']}，分类为 {rule['category']}")
            return rule['category']
    logger.debug(f"频道 {channel_name} 未匹配任何规则，分类为默认 '其他'")
    return next((rule['default'] for rule in CATEGORY_RULES if 'default' in rule), '其他')

def save_unmatched_channels(channels, unmatched_file="unmatched_channels.txt"):
    logger.info(f"保存未匹配频道到 {unmatched_file}")
    file_handler = FileHandler(is_remote=True, github_token=GITHUB_TOKEN)
    unmatched_lines = [line for _, line in channels if categorize_channel(line.split(',', 1)[0]) == '其他']
    file_handler.write_txt(unmatched_file, unmatched_lines or ["# 没有未匹配的频道"], "更新未匹配频道列表", backup=True)
    logger.info(f"保存 {len(unmatched_lines)} 个未匹配频道到 {unmatched_file}")

def merge_local_channel_files(channels_dir, output_file="iptv_list.txt"):
    logger.info(f"开始合并频道文件到 {output_file}")
    output_lines = [f"更新时间,#genre#\n{datetime.now().strftime('%Y-%m-%d')},url\n{datetime.now().strftime('%H:%M:%S')},url\n"]
    file_handler = FileHandler()
    
    categories = set()
    for file_name in os.listdir(channels_dir):
        if file_name.endswith('_iptv.txt'):
            category = file_name.replace('_iptv.txt', '')
            categories.add(category)
    
    if not categories:
        logger.warning(f"未找到任何分类文件在 {channels_dir}")
        output_lines.append("无分类频道,#genre#\n")
    
    for category in sorted(categories):
        file_path = os.path.join(channels_dir, f"{category}_iptv.txt")
        lines = file_handler.read_txt(file_path)
        if lines:
            output_lines.append(f"{category},#genre#\n")
            output_lines.extend(lines)
            logger.info(f"合并 {category} 的 {len(lines)} 个频道")
    
    file_handler.write_txt(output_file, output_lines, "合并频道文件")
    logger.info(f"合并完成，生成 {output_file}，包含 {len(output_lines)} 行")
    return output_lines

def main():
    file_handler = FileHandler(is_remote=True, github_token=GITHUB_TOKEN)
    local_file_handler = FileHandler()
    url_states = load_url_states()
    channel_cache = load_channel_cache()
    
    try:
        # 发现 URL
        logger.info("开始发现 URL")
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            loop.run_until_complete(discover_urls())
        finally:
            loop.close()
        
        # 提取和过滤频道
        urls = file_handler.read_txt(URLS_PATH)
        logger.info(f"从 {URLS_PATH} 读取 {len(urls)} 个 URL")
        channels = set()
        for url in urls:
            try:
                extracted = extract_channels_from_url(url, url_states)
                channels.update(extracted)
                logger.info(f"从 {url} 提取 {len(extracted)} 个频道")
            except Exception as e:
                logger.error(f"处理 URL {url} 失败：{e}")
                continue
        
        logger.info(f"共提取 {len(channels)} 个唯一频道")
        
        # 异步验证频道
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            valid_channels = loop.run_until_complete(check_channels_async(channels, url_states, channel_cache))
        finally:
            loop.close()
        
        # 保存未匹配频道
        save_unmatched_channels(valid_channels)
        
        # 保存状态和缓存
        save_url_states(url_states)
        save_channel_cache(channel_cache)
        
        # 分类和保存
        channels_dir = CONFIG.get('paths', {}).get('channels_dir', '地方频道')
        logger.info(f"使用频道目录：{channels_dir}")
        os.makedirs(channels_dir, exist_ok=True)
        
        grouped_channels = {}
        for _, line in valid_channels:
            name = line.split(',', 1)[0]
            category = categorize_channel(name)
            grouped_channels.setdefault(category, []).append(line)
        
        logger.info(f"分类结果：{len(grouped_channels)} 个类别")
        for category, lines in grouped_channels.items():
            local_file_handler.write_txt(os.path.join(channels_dir, f"{category}_iptv.txt"), lines, f"保存 {category} 频道")
            logger.info(f"保存 {category} 的 {len(lines)} 个频道到 {channels_dir}/{category}_iptv.txt")
        
        # 合并和上传
        final_content = merge_local_channel_files(channels_dir)
        file_handler.write_txt("output/iptv_list.txt", final_content, "更新 IPTV 列表", backup=True)
        logger.info("上传 iptv_list.txt 到 output/iptv_list.txt")
    
    except Exception as e:
        logger.error(f"主程序执行失败：{e}")
        save_url_states(url_states)
        save_channel_cache(channel_cache)
        save_keyword_stats(keyword_stats)
        raise

if __name__ == "__main__":
    main()
