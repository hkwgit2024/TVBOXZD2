import os
import subprocess
import logging
import json
import requests
import yaml
from datetime import datetime
from urllib.parse import urlparse

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 确保输出目录存在
os.makedirs('output', exist_ok=True)

# 读取配置文件
with open('config/config.yaml', 'r', encoding='utf-8') as f:
    CONFIG = yaml.safe_load(f)

# 读取时间戳文件
TIMESTAMPS_FILE = 'output/timestamps.json'
try:
    with open(TIMESTAMPS_FILE, 'r', encoding='utf-8') as f:
        timestamps = json.load(f)
except FileNotFoundError:
    timestamps = {}

# 读取失败的链接
FAILED_FILE = 'output/failed.txt'
failed_urls = set()
try:
    with open(FAILED_FILE, 'r', encoding='utf-8') as f:
        failed_urls = set(line.strip() for line in f if line.strip())
except FileNotFoundError:
    pass

def get_url_timestamp(url):
    """获取 URL 的最后修改时间"""
    try:
        response = requests.head(url, timeout=5)
        if response.status_code == 200:
            last_modified = response.headers.get('Last-Modified')
            if last_modified:
                return datetime.strptime(last_modified, '%a, %d %b %Y %H:%M:%S %Z').isoformat()
        return None
    except Exception as e:
        logging.warning(f"无法获取 {url} 的时间戳: {e}")
        return None

def check_url_validity(url):
    """使用 FFmpeg 检查 URL 是否有效"""
    protocol = urlparse(url).scheme.lower()
    ffmpeg_config = CONFIG.get('ffmpeg', {}).get(protocol, CONFIG.get('ffmpeg', {}).get('default', {}))
    timeout = ffmpeg_config.get('timeout', 10000000) / 1000000  # 转换为秒
    
    cmd = [
        'ffprobe', '-v', 'error',
        '-timeout', str(int(timeout * 1000000)),
        '-i', url
    ]
    
    if protocol == 'rtmp':
        cmd.extend(['-rtmp_transport', ffmpeg_config.get('rtmp_transport', 'tcp')])
        cmd.extend(['-rtmp_buffer', str(ffmpeg_config.get('rtmp_buffer', 3000))])
    elif protocol == 'rtp':
        cmd.extend(['-buffer_size', str(ffmpeg_config.get('buffer_size', 800000))])
        cmd.extend(['-rtcpport', str(ffmpeg_config.get('rtcpport', 5005))])
    
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logging.info(f"URL 检查超时: {url}")
        return False
    except Exception as e:
        logging.info(f"URL 检查错误: {url} - {e}")
        return False

def main():
    # 读取 urls.txt
    with open('config/urls.txt', 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    # 去重
    unique_urls = set(urls)
    logging.info(f"读取到 {len(urls)} 个 URL，去重后 {len(unique_urls)} 个")

    # 保存去重后的 URL 到 output/list.txt
    with open('output/list.txt', 'w', encoding='utf-8') as f:
        for url in unique_urls:
            f.write(url + '\n')

    # 检查 URL 更新和有效性
    valid_urls = []
    new_failed_urls = set()
    current_time = datetime.now().isoformat()

    for url in unique_urls:
        if url in failed_urls:
            logging.info(f"跳过已失败的 URL: {url}")
            continue

        # 检查时间戳
        last_timestamp = timestamps.get(url)
        current_timestamp = get_url_timestamp(url)
        
        if last_timestamp and current_timestamp and last_timestamp == current_timestamp:
            logging.info(f"跳过未更新的 URL: {url}")
            continue

        # 更新时间戳
        if current_timestamp:
            timestamps[url] = current_timestamp

        # 检查有效性
        if check_url_validity(url):
            valid_urls.append(url)
        else:
            new_failed_urls.add(url)

    # 保存有效 URL 到 output/mpeg.txt
    with open('output/mpeg.txt', 'w', encoding='utf-8') as f:
        for url in valid_urls:
            f.write(url + '\n')

    # 保存失败 URL 到 output/failed.txt
    with open(FAILED_FILE, 'w', encoding='utf-8') as f:
        for url in failed_urls | new_failed_urls:
            f.write(url + '\n')

    # 保存时间戳
    with open(TIMESTAMPS_FILE, 'w', encoding='utf-8') as f:
        json.dump(timestamps, f, ensure_ascii=False, indent=2)

    logging.info(f"处理完成：有效 URL {len(valid_urls)} 个，失败 URL {len(new_failed_urls)} 个")

if __name__ == "__main__":
    main()
