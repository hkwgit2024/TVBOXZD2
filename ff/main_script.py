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

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(os.path.join('ff', 'iptv_checker.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# 加载配置文件
def load_config():
    config_path = os.path.join('ff', 'config.json')
    default_config = {
        "ffmpeg_path": "ffmpeg",
        "timeout": 3,
        "read_duration": 1,
        "max_retries": 2,
        "max_workers": min(max(4, os.cpu_count() or 8), 50),
        "min_resolution_width": 1280,
        "min_bitrate": 1000000,
        "max_response_time": 1.5,
        "quick_check_timeout": 2,
        "default_headers": {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
            "Referer": "https://www.example.com"
        }
    }
    try:
        if os.path.exists(config_path):
            with open(config_path, 'r') as f:
                config = json.load(f)
            default_config.update(config)
        else:
            with open(config_path, 'w') as f:
                json.dump(default_config, f, indent=4)
    except Exception as e:
        logger.error(f"Failed to load config: {e}. Using default settings.")
    return default_config

CONFIG = load_config()
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

def is_valid_url(url):
    """验证URL格式"""
    return validators.url(url) is True

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
    failed_path = os.path.join('ff', 'failed_links.txt')
    failed_urls = set()
    if os.path.exists(failed_path):
        try:
            with open(failed_path, 'r', encoding='utf-8') as f:
                for line in f:
                    parts = line.strip().split(',', 2)
                    if len(parts) >= 2:
                        failed_urls.add(parts[1])  # 提取 URL
        except Exception as e:
            logger.error(f"Failed to load {failed_path}: {e}")
    return failed_urls

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
        "-probesize", "250000",
        "-analyzeduration", "250000"
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
                return info.get('streams', [])
            except json.JSONDecodeError:
                return [], "Invalid JSON response"
        return [], f"FFmpeg error: {result.stderr[:50]}"
    except subprocess.SubprocessError as e:
        return [], f"Subprocess error: {str(e)}"

def is_link_playable(url, channel_name):
    """检查链接是否可播放并获取质量信息"""
    if not is_valid_url(url):
        logger.warning(f"Invalid URL format for {channel_name}: {url}")
        return False, 0.0, None, None, "Invalid URL"

    is_accessible, reason = quick_check_url(url)
    if not is_accessible:
        logger.warning(f"Quick check failed for {channel_name}: {url} ({reason})")
        return False, 0.0, None, None, reason

    video_width = None
    bitrate = None
    is_stable = True

    # 获取流信息
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

    # 检查分辨率和比特率
    if video_width and video_width < MIN_RESOLUTION_WIDTH:
        reason = f"Low resolution ({video_width}x{stream.get('height', 0)})"
        logger.warning(f"{reason} for {channel_name}: {url}")
        return False, 0.0, video_width, bitrate, reason
    if bitrate and bitrate < MIN_BITRATE:
        reason = f"Low bitrate ({bitrate} bps)"
        logger.warning(f"{reason} for {channel_name}: {url}")
        return False, 0.0, video_width, bitrate, reason

    # 检查可播放性和稳定性
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
                "-probesize", "250000",
                "-analyzeduration", "250000",
                "-f", "null", "-",
                "-loglevel", "error"
            ]
            
            process = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True,
                timeout=TIMEOUT
            )
            
            response_time = time.time() - start_time
            if process.returncode != 0:
                if any(err in process.stderr for err in ["Connection refused", "Server returned", "Input/output error", "403 Forbidden", "401 Unauthorized"]):
                    is_stable = False
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

def read_input_file(input_file):
    """读取输入文件并解析链接"""
    input_path = os.path.join('ff', input_file)
    links_to_check = []
    failed_urls = load_failed_links()
    
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                match = re.match(r'^(.*?),(http[s]?://.*)$', line)
                if match:
                    channel_name = match.group(1).strip()
                    url = match.group(2).strip()
                    if url not in failed_urls:
                        links_to_check.append((channel_name, url))
                    else:
                        logger.info(f"Skipping previously failed URL: {url}")
                else:
                    logger.warning(f"Skipping malformed line: {line}")
    except Exception as e:
        logger.error(f"Failed to read {input_path}: {e}")
        return None
    return links_to_check

def write_output_file(output_file, valid_links, failed_links):
    """写入输出文件和失败链接文件"""
    output_path = os.path.join('ff', output_file)
    failed_path = os.path.join('ff', 'failed_links.txt')
    success_count = 0
    
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            for response_time, link_entry in sorted(valid_links, key=lambda x: x[0]):
                f.write(link_entry + '\n')
                success_count += 1
    except Exception as e:
        logger.error(f"Failed to write {output_path}: {e}")
        return 0

    try:
        with open(failed_path, 'a', encoding='utf-8') as f:  # 追加模式
            for channel_name, url, reason in failed_links:
                f.write(f"{channel_name},{url},{reason}\n")
    except Exception as e:
        logger.error(f"Failed to write {failed_path}: {e}")

    return success_count

def main():
    input_file = 'list.txt'
    output_file = 'ff.txt'
    start_time = time.time()
    
    input_path = os.path.join('ff', input_file)
    if not os.path.exists(input_path):
        logger.error(f"Input file {input_file} not found in ff directory.")
        return

    links_to_check = read_input_file(input_file)
    if links_to_check is None:
        return

    if not links_to_check:
        logger.warning(f"No links to check in {input_file}. Clearing {output_file}.")
        with open(os.path.join('ff', output_file), 'w', encoding='utf-8') as f:
            f.write("")
        return

    stats = {'checked': len(links_to_check), 'success': 0, 'invalid': 0, 'low_quality': 0, 'slow': 0, 'unstable': 0}
    valid_links = []
    failed_links = []

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_link = {executor.submit(is_link_playable, url, channel): (channel, url) 
                         for channel, url in links_to_check}
        for future in tqdm(as_completed(future_to_link), total=len(links_to_check), desc="Checking links"):
            channel_name, url = future_to_link[future]
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
                    else:
                        stats['unstable'] += 1
            except Exception as exc:
                logger.error(f"{channel_name}: {url} generated an exception: {exc}")
                failed_links.append((channel_name, url, f"Exception ({str(exc)})"))
                stats['unstable'] += 1

    success_count = write_output_file(output_file, valid_links, failed_links)
    elapsed_time = time.time() - start_time
    logger.info(f"Stats: {success_count}/{stats['checked']} links passed (invalid: {stats['invalid']}, low quality: {stats['low_quality']}, slow: {stats['slow']}, unstable: {stats['unstable']})")
    logger.info(f"Total processing time: {elapsed_time:.2f} seconds")

if __name__ == '__main__':
    main()
