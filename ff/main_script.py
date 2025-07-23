import os
import re
import subprocess
import time
import logging
import json
import validators
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from urllib.parse import urlparse
import sys

# 添加当前脚本目录到模块搜索路径
sys.path.append(os.path.dirname(__file__))

# 设置日志
def setup_logging(log_file):
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    return logging.getLogger(__name__)

# 加载配置文件
def load_config():
    config_path = os.path.join('ff', 'config.json')
    try:
        if not os.path.exists(config_path):
            logger.error(f"Config file {config_path} not found. Please create it.")
            raise FileNotFoundError(f"Config file {config_path} not found.")
        with open(config_path, 'r') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load config: {e}")
        raise

CONFIG = load_config()
logger = setup_logging(CONFIG['log_file'])
FFMPEG_PATH = CONFIG['ffmpeg_path']
TIMEOUT = CONFIG['timeout']
READ_DURATION = CONFIG['read_duration']
MAX_RETRIES = CONFIG['max_retries']
MAX_WORKERS = CONFIG['max_workers']
MIN_RESOLUTION_WIDTH = CONFIG['min_resolution_width']
MIN_BITRATE = CONFIG['min_bitrate']
MAX_RESPONSE_TIME = CONFIG['max_response_time']
QUICK_CHECK_TIMEOUT = CONFIG['quick_check_timeout']
DEFAULT_HEADERS = CONFIG['default_headers']
EXCLUDE_DOMAINS = CONFIG.get('exclude_domains', [])
INPUT_FILE = CONFIG['input_file']
OUTPUT_FILE = CONFIG['output_file']
FAILED_LINKS_FILE = CONFIG['failed_links_file']
CHECKPOINT_FILE = CONFIG.get('checkpoint_file', 'ff/checkpoint.json')

def is_valid_url(url):
    """验证URL格式"""
    return validators.url(url) is True

def is_excluded_url(url):
    """检查URL是否在排除列表中"""
    parsed_url = urlparse(url)
    domain = parsed_url.hostname or ''
    for exclude in EXCLUDE_DOMAINS:
        if exclude in domain:
            logger.info(f"URL {url} excluded due to domain: {exclude}")
            return True
    return False

def quick_check_url(url):
    """快速检查URL的HTTP状态码"""
    try:
        response = requests.head(url, timeout=QUICK_CHECK_TIMEOUT, allow_redirects=True, headers=DEFAULT_HEADERS)
        if response.status_code == 200:
            return True, None
        return False, f"HTTP Error {response.status_code}"
    except requests.RequestException as e:
        return False, f"Connection failed: {str(e)}"

def load_failed_links():
    """加载已保存的失败链接"""
    failed_urls = set()
    if os.path.exists(FAILED_LINKS_FILE):
        try:
            with open(FAILED_LINKS_FILE, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split(',', 2)
                    if len(parts) >= 2:
                        failed_urls.add(parts[1])
        except Exception as e:
            logger.error(f"Failed to load {FAILED_LINKS_FILE}: {e}")
    return failed_urls

def load_checkpoint():
    """加载检查点"""
    if os.path.exists(CHECKPOINT_FILE):
        try:
            with open(CHECKPOINT_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load checkpoint {CHECKPOINT_FILE}: {e}")
    return {'processed_urls': [], 'valid_links': [], 'failed_links': []}

def save_checkpoint(processed_urls, valid_links, failed_links):
    """保存检查点"""
    try:
        with open(CHECKPOINT_FILE, 'w', encoding='utf-8') as f:
            json.dump({
                'processed_urls': processed_urls,
                'valid_links': valid_links,
                'failed_links': failed_links
            }, f, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Failed to save checkpoint {CHECKPOINT_FILE}: {e}")

def get_stream_info(url):
    """使用FFmpeg提取视频流信息"""
    cmd = [
        FFMPEG_PATH,
        "-headers", f"User-Agent: {DEFAULT_HEADERS['User-Agent']}\r\nReferer: {DEFAULT_HEADERS['Referer']}\r\n",
        "-i", url,
        "-hide_banner",
        "-show_streams",
        "-print_format", "json",
        "-loglevel", "error",
        "-probesize", "500000",
        "-analyzeduration", "500000"
    ]
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=TIMEOUT
        )
        if result.returncode == 0:
            try:
                info = json.loads(result.stdout)
                return info.get('streams', []), None
            except json.JSONDecodeError:
                return [], "Invalid JSON response"
        return [], f"FFmpeg error: {result.stderr[:50]}"
    except subprocess.SubprocessError as e:
        return [], f"Subprocess error: {str(e)}"

def check_content_variation(url, channel_name):
    """检查内容变化（占位，待认证逻辑）"""
    # TODO: 实现动态 token 认证逻辑，需用户提供 API 细节
    return True, None

def is_link_playable(url, channel_name):
    """检查链接是否可播放并获取质量信息"""
    if is_excluded_url(url):
        return False, 0.0, None, None, "Excluded domain"

    if not is_valid_url(url):
        logger.warning(f"Invalid URL format for {channel_name}: {url}")
        return False, 0.0, None, None, "Invalid URL"

    is_accessible, reason = quick_check_url(url)
    if not is_accessible:
        logger.warning(f"Quick check failed for {channel_name}: {url} ({reason})")
        return False, 0.0, None, None, reason

    is_varying, variation_error = check_content_variation(url, channel_name)
    if not is_varying:
        logger.warning(f"No content variation for {channel_name}: {url} ({variation_error})")
        return False, 0.0, None, None, f"No content variation ({variation_error})"

    video_width = None
    bitrate = None

    streams, stream_error = get_stream_info(url)
    if stream_error:
        logger.warning(f"Stream info error for {channel_name}: {url} ({stream_error})")
        return False, 0.0, None, None, stream_error

    for stream in streams:
        if stream.get('codec_type') == 'video':
            video_width = stream.get('width', 0)
            bitrate = stream.get('bit_rate', None)
            if bitrate is None and stream.get('tags', {}).get('BPS'):
                bitrate = stream.get('tags', {}).get('BPS')
            try:
                bitrate = int(bitrate) if bitrate else None
            except (ValueError, TypeError):
                bitrate = None
            break

    if video_width and video_width < MIN_RESOLUTION_WIDTH:
        reason = f"Low resolution ({video_width}x{stream.get('height', 0)})"
        logger.warning(f"{reason} for {channel_name}: {url}")
        return False, 0.0, video_width, bitrate, reason
    if bitrate and bitrate < MIN_BITRATE:
        reason = f"Low bitrate ({bitrate} bps)"
        logger.warning(f"{reason} for {channel_name}: {url}")
        return False, 0.0, video_width, bitrate, reason

    for attempt in range(MAX_RETRIES):
        try:
            start_time = time.time()
            logger.info(f"Checking {channel_name}: {url} (Attempt {attempt + 1}/{MAX_RETRIES})")
            
            cmd = [
                FFMPEG_PATH,
                "-headers", f"User-Agent: {DEFAULT_HEADERS['User-Agent']}\r\nReferer: {DEFAULT_HEADERS['Referer']}\r\n",
                "-i", url,
                "-t", str(READ_DURATION),
                "-c:v", "copy",
                "-c:a", "copy",
                "-probesize", "500000",
                "-analyzeduration", "500000",
                "-f", "null", "-",
                "-loglevel", "error"
            ]
            
            process = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=TIMEOUT + READ_DURATION
            )
            
            response_time = time.time() - start_time
            if process.returncode != 0:
                if any(err in process.stderr for err in ["Connection refused", "Server returned", "Input/output error", "403 Forbidden", "401 Unauthorized"]):
                    reason = f"Unstable connection ({process.stderr[:50]})"
                    logger.warning(f"{reason} for {channel_name}: {url}")
                else:
                    reason = f"FFmpeg error ({process.stderr[:50]})"
                    logger.warning(f"Failed to read data from {channel_name}: {url} - {reason}")
                return False, response_time, video_width, bitrate, reason
                
            if response_time > MAX_RESPONSE_TIME:
                reason = f"Slow response ({response_time:.2f}s)"
                logger.warning(f"{reason} for {channel_name}: {url}")
                return False, response_time, video_width, bitrate, reason
                
            logger.info(f"Successfully connected to {channel_name}: {url} (took {response_time:.2f}s, resolution: {video_width or 'N/A'}x{stream.get('height', 'N/A')}, bitrate: {bitrate or 'N/A'} bps)")
            return True, response_time, video_width, bitrate, "Success"
            
        except subprocess.TimeoutExpired:
            response_time = time.time() - start_time
            reason = "Timeout"
            logger.warning(f"{reason} checking {channel_name}: {url}")
            return False, response_time, video_width, bitrate, reason
        except subprocess.SubprocessError as e:
            response_time = time.time() - start_time
            reason = f"Subprocess error ({str(e)})"
            logger.error(f"{reason} checking {channel_name}: {url}")
            if attempt == MAX_RETRIES - 1:
                return False, response_time, video_width, bitrate, reason
            time.sleep(0.5)
        except Exception as e:
            response_time = time.time() - start_time
            reason = f"Unexpected error ({str(e)})"
            logger.error(f"{reason} for {channel_name}: {url}")
            return False, response_time, video_width, bitrate, reason

def read_input_file():
    """读取输入文件并解析链接"""
    checkpoint = load_checkpoint()
    processed_urls = set(checkpoint['processed_urls'])
    links_to_check = []
    failed_urls = load_failed_links()
    
    try:
        with open(INPUT_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    logger.info(f"Skipping line: {line}")
                    continue
                match = re.match(r'^(.*?),(http[s]?://.*)$', line)
                if match:
                    channel_name = match.group(1).strip()
                    url = match.group(2).strip()
                    if url in failed_urls:
                        logger.info(f"Skipping previously failed URL: {url}")
                        continue
                    if url in processed_urls:
                        logger.info(f"Skipping previously processed URL: {url}")
                        continue
                    if is_excluded_url(url):
                        logger.info(f"Skipping excluded URL: {url}")
                        continue
                    links_to_check.append((channel_name, url))
                else:
                    logger.warning(f"Skipping malformed line: {line}")
    except Exception as e:
        logger.error(f"Failed to read {INPUT_FILE}: {e}")
        return None, checkpoint
    return links_to_check, checkpoint

def write_output_file(valid_links, failed_links, checkpoint):
    """写入输出文件和失败链接文件"""
    success_count = 0
    
    # 确保输出目录存在
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    os.makedirs(os.path.dirname(FAILED_LINKS_FILE), exist_ok=True)

    final_valid_links = valid_links + checkpoint['valid_links']
    final_failed_links = failed_links + checkpoint['failed_links']

    try:
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write("#EXTM3U\n") # M3U 头部
            for response_time, link_entry in sorted(final_valid_links, key=lambda x: x[0]):
                # link_entry 格式为 "channel_name,url"
                parts = link_entry.split(',', 1)
                if len(parts) == 2:
                    channel_name = parts[0]
                    url = parts[1]
                    f.write(f'#EXTINF:-1 group-title="直播", {channel_name}\n')
                    f.write(f'{url}\n')
                    success_count += 1
                else:
                    logger.warning(f"Skipping malformed valid link entry: {link_entry}")

    except Exception as e:
        logger.error(f"Failed to write {OUTPUT_FILE}: {e}")
        return 0

    try:
        with open(FAILED_LINKS_FILE, 'w', encoding='utf-8') as f: # **这里从 'a' 改为 'w'**
            for channel_name, url, reason in final_failed_links:
                f.write(f"{channel_name},{url},{reason}\n")
    except Exception as e:
        logger.error(f"Failed to write {FAILED_LINKS_FILE}: {e}")

    return success_count

def main():
    start_time = time.time()
    
    if not os.path.exists(INPUT_FILE):
        logger.error(f"Input file {INPUT_FILE} not found.")
        return

    links_to_check, checkpoint = read_input_file()
    if links_to_check is None:
        return

    if not links_to_check:
        logger.warning(f"No links to check in {INPUT_FILE}. Clearing {OUTPUT_FILE}.")
        # 确保在没有链接可检查时，output.txt也被清空
        os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            f.write("")
        os.makedirs(os.path.dirname(FAILED_LINKS_FILE), exist_ok=True)
        with open(FAILED_LINKS_FILE, 'w', encoding='utf-8') as f:
            f.write("")
        return

    stats = {'checked': len(links_to_check), 'success': 0, 'invalid': 0, 'low_quality': 0, 'slow': 0, 'unstable': 0, 'excluded': 0}
    valid_links = []
    failed_links = []
    processed_urls = set(checkpoint['processed_urls'])

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_link = {executor.submit(is_link_playable, url, channel): (channel, url) 
                          for channel, url in links_to_check}
        for future in tqdm(as_completed(future_to_link), total=len(links_to_check), desc="Checking links"):
            channel_name, url = future_to_link[future]
            processed_urls.add(url)
            try:
                is_playable, response_time, width, bitrate, reason = future.result()
                if is_playable:
                    valid_links.append((response_time, f"{channel_name},{url}"))
                    stats['success'] += 1
                else:
                    failed_links.append((channel_name, url, reason))
                    if reason.startswith("Invalid"):
                        stats['invalid'] += 1
                    elif reason.startswith("Low"):
                        stats['low_quality'] += 1
                    elif reason.startswith("Slow"):
                        stats['slow'] += 1
                    elif reason.startswith("Excluded"):
                        stats['excluded'] += 1
                    else:
                        stats['unstable'] += 1
            except Exception as exc:
                logger.error(f"{channel_name}: {url} generated an exception: {exc}")
                failed_links.append((channel_name, url, f"Exception ({str(exc)})"))
                stats['unstable'] += 1

            # 每处理 50 个链接保存一次检查点
            if len(processed_urls) % 50 == 0:
                save_checkpoint(list(processed_urls), valid_links + checkpoint['valid_links'], failed_links + checkpoint['failed_links'])

    # 最后保存检查点
    save_checkpoint(list(processed_urls), valid_links + checkpoint['valid_links'], failed_links + checkpoint['failed_links'])

    success_count = write_output_file(valid_links, failed_links, checkpoint)
    elapsed_time = time.time() - start_time
    logger.info(f"Stats: {success_count}/{stats['checked'] + len(checkpoint['valid_links'])} links passed (invalid: {stats['invalid']}, low quality: {stats['low_quality']}, slow: {stats['slow']}, unstable: {stats['unstable']}, excluded: {stats['excluded']})")
    logger.info(f"Total processing time: {elapsed_time:.2f} seconds")

if __name__ == '__main__':
    main()
