import os
import subprocess
import logging
import json
import requests
import yaml
from datetime import datetime, timedelta
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import multiprocessing
import argparse

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 确保输出目录存在
os.makedirs('output', exist_ok=True)

# 读取配置文件
with open('scripts/config.yaml', 'r', encoding='utf-8') as f:
    CONFIG = yaml.safe_load(f)

# 读取时间戳文件
TIMESTAMPS_FILE = 'output/timestamps.json'
try:
    with open(TIMESTAMPS_FILE, 'r', encoding='utf-8') as f:
        timestamps = json.load(f)
except FileNotFoundError:
    timestamps = {}

# 读取失败的链接及其时间和计数
FAILED_FILE = 'output/failed.txt'
failed_urls = {}
try:
    with open(FAILED_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                parts = line.strip().split('|')
                url = parts[0]
                timestamp = parts[1] if len(parts) > 1 else None
                count = int(parts[2]) if len(parts) > 2 else 1
                failed_urls[url] = {'timestamp': timestamp, 'count': count}
except FileNotFoundError:
    pass

# 读取黑名单
BLACKLIST_FILE = 'config/blacklist.txt'
blacklist_urls = set()
try:
    with open(BLACKLIST_FILE, 'r', encoding='utf-8') as f:
        blacklist_urls = set(line.strip() for line in f if line.strip() and not line.startswith('#'))
except FileNotFoundError:
    pass

def get_url_timestamp(url):
    """获取 URL 的最后修改时间"""
    try:
        response = requests.head(url, timeout=3)
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
    timeout = ffmpeg_config.get('timeout', 3000000) / 1000000
    
    cmd = [
        'ffprobe', '-v', 'error',
        '-timeout', str(int(timeout * 1000000)),
        '-probesize', str(ffmpeg_config.get('probesize', 500000)),
        '-analyzeduration', str(ffmpeg_config.get('analyzeduration', 500000)),
        '-i', url
    ]
    
    if protocol == 'rtmp':
        cmd.extend(['-rtmp_transport', ffmpeg_config.get('rtmp_transport', 'tcp')])
        cmd.extend(['-rtmp_buffer', str(ffmpeg_config.get('rtmp_buffer', 1000))])
    elif protocol == 'rtp':
        cmd.extend(['-buffer_size', str(ffmpeg_config.get('buffer_size', 200000))])
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

def parse_m3u(url):
    """解析 M3U 文件并提取分类信息"""
    try:
        response = requests.get(url, timeout=3)
        if response.status_code != 200:
            return None, []
        lines = response.text.splitlines()
        category = None
        channels = []
        for line in lines:
            if line.startswith('#EXTINF'):
                parts = line.split(',')
                if len(parts) > 1:
                    channel_name = parts[1].strip()
                if 'group-title="' in line:
                    category = line.split('group-title="')[1].split('"')[0]
            elif line.startswith('http'):
                channels.append((category, line.strip()))
        return category, channels
    except Exception as e:
        logging.warning(f"解析 M3U 文件失败: {url} - {e}")
        return None, []

def check_url_wrapper(url, total_urls, processed_urls, start_time, avg_times):
    """并行检查 URL 的包装函数"""
    processed_urls[0] += 1
    url_start_time = time.time()
    
    if url in blacklist_urls:
        logging.info(f"跳过黑名单 URL: {url}")
        return url, False, None
    
    if url in failed_urls:
        fail_info = failed_urls.get(url)
        fail_time = fail_info['timestamp']
        fail_count = fail_info['count']
        if fail_time:
            fail_datetime = datetime.fromisoformat(fail_time)
            skip_duration = timedelta(hours=24) if fail_count < 3 else timedelta(days=7)
            if datetime.now() - fail_datetime < skip_duration:
                logging.info(f"跳过最近失败的 URL（失败 {fail_count} 次）: {url}")
                return url, False, None
    
    current_timestamp = get_url_timestamp(url)
    if url in timestamps and current_timestamp and timestamps[url] == current_timestamp:
        logging.info(f"跳过未更新的 URL: {url}")
        return url, None, current_timestamp
    
    is_valid = check_url_validity(url)
    url_end_time = time.time()
    avg_times.append(url_end_time - url_start_time)
    
    if not is_valid:
        failed_urls[url] = failed_urls.get(url, {'timestamp': None, 'count': 0})
        failed_urls[url]['timestamp'] = datetime.now().isoformat()
        failed_urls[url]['count'] += 1
    
    return url, is_valid, current_timestamp

def check_m3u_channel(channel_url, failed_urls, current_time, processed_urls, total_urls, avg_times, progress_interval):
    """检查 M3U 频道 URL 的包装函数"""
    processed_urls[0] += 1
    channel_start_time = time.time()
    if channel_url not in failed_urls:
        if check_url_validity(channel_url):
            avg_times.append(time.time() - channel_start_time)
            if processed_urls[0] % progress_interval == 0 or processed_urls[0] == total_urls:
                progress = (processed_urls[0] / total_urls) * 100
                remaining = total_urls - processed_urls[0]
                avg_time = sum(avg_times) / len(avg_times) if avg_times else 0
                eta_minutes = (remaining * avg_time) / 60
                logging.info(f"进度: {processed_urls[0]}/{total_urls} ({progress:.1f}%)，剩余: {remaining}，预计剩余时间: {eta_minutes:.1f}分钟")
            return channel_url, True
        else:
            avg_times.append(time.time() - channel_start_time)
            if processed_urls[0] % progress_interval == 0 or processed_urls[0] == total_urls:
                progress = (processed_urls[0] / total_urls) * 100
                remaining = total_urls - processed_urls[0]
                avg_time = sum(avg_times) / len(avg_times) if avg_times else 0
                eta_minutes = (remaining * avg_time) / 60
                logging.info(f"进度: {processed_urls[0]}/{total_urls} ({progress:.1f}%)，剩余: {remaining}，预计剩余时间: {eta_minutes:.1f}分钟")
            return channel_url, False
    return channel_url, False

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--shard', type=int, default=0, help='Shard index')
    parser.add_argument('--total-shards', type=int, default=1, help='Total number of shards')
    args = parser.parse_args()
    
    # 优先尝试读取 output/list.txt，如果存在
    urls_with_priority = []
    list_txt_path = 'output/list.txt'
    urls_txt_path = 'config/urls.txt'
    
    if os.path.exists(list_txt_path):
        logging.info("检测到 output/list.txt，优先从中读取 URL")
        with open(list_txt_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip() and not line.startswith('#'):
                    parts = line.strip().split('|')
                    url = parts[0]
                    priority = parts[1] if len(parts) > 1 else 'normal'
                    urls_with_priority.append((url, priority))
    else:
        logging.info("output/list.txt 不存在，从 config/urls.txt 读取")
        with open(urls_txt_path, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip() and not line.startswith('#'):
                    parts = line.strip().split('|')
                    url = parts[0]
                    priority = parts[1] if len(parts) > 1 else 'normal'
                    urls_with_priority.append((url, priority))
        unique_urls = set(url for url, _ in urls_with_priority)
        logging.info(f"从 config/urls.txt 读取到 {len(urls_with_priority)} 个 URL，去重后 {len(unique_urls)} 个")
        with open(list_txt_path, 'w', encoding='utf-8') as f:
            for url, priority in urls_with_priority:
                if url in unique_urls:
                    f.write(f"{url}|{priority}\n")
                    unique_urls.remove(url)
        logging.info("去重后的 URL 已保存到 output/list.txt")

    # 按优先级排序
    priority_order = {'high': 1, 'normal': 2, 'low': 3}
    urls_with_priority.sort(key=lambda x: priority_order.get(x[1], 2))
    unique_urls = [url for url, _ in urls_with_priority]
    
    # 分片处理
    shard_size = len(unique_urls) // args.total_shards + 1
    start_idx = args.shard * shard_size
    shard_urls = unique_urls[start_idx:start_idx + shard_size]
    logging.info(f"处理分片 {args.shard + 1}/{args.total_shards}，包含 {len(shard_urls)} 个 URL")
    
    # 初始化进度跟踪
    total_urls = len(shard_urls)
    processed_urls = [0]
    avg_times = []
    start_time = time.time()
    progress_interval = 5000
    temp_mpeg_file = f'output/mpeg_temp_shard_{args.shard}.txt'
    temp_category_files = {}
    
    # 并行检查 URL
    valid_urls = []
    new_failed_urls = {}
    categorized_urls = {}
    current_time = datetime.now().isoformat()

    cpu_count = multiprocessing.cpu_count()
    max_workers = min(max(2, cpu_count), int(total_urls / 1000) + 2)
    max_workers = min(max_workers, 10)
    logging.info(f"使用 {max_workers} 个并发线程处理 {total_urls} 个 URL")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_url = {executor.submit(check_url_wrapper, url, total_urls, processed_urls, start_time, avg_times): url for url in shard_urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                url, is_valid, current_timestamp = future.result()
                if current_timestamp:
                    timestamps[url] = current_timestamp
                if is_valid is None:
                    continue
                if is_valid:
                    if url.endswith('.m3u') or url.endswith('.m3u8'):
                        category, channels = parse_m3u(url)
                        if category:
                            if category not in categorized_urls:
                                categorized_urls[category] = []
                                temp_category_files[category] = f'output/{category.replace("/", "_").replace(" ", "_")}_temp_shard_{args.shard}.txt'
                            channel_futures = {executor.submit(check_m3u_channel, channel_url, failed_urls, current_time, processed_urls, total_urls, avg_times, progress_interval): channel_url for _, channel_url in channels}
                            for channel_future in as_completed(channel_futures):
                                channel_url = channel_futures[channel_future]
                                try:
                                    channel_url, channel_valid = channel_future.result()
                                    if channel_valid:
                                        categorized_urls[category].append(channel_url)
                                    else:
                                        new_failed_urls[channel_url] = {'timestamp': current_time, 'count': new_failed_urls.get(channel_url, {'count': 0})['count'] + 1}
                                except Exception as e:
                                    logging.error(f"处理 M3U 频道 {channel_url} 时出错: {e}")
                                    new_failed_urls[channel_url] = {'timestamp': current_time, 'count': new_failed_urls.get(channel_url, {'count': 0})['count'] + 1}
                    else:
                        valid_urls.append(url)
                else:
                    new_failed_urls[url] = {'timestamp': current_time, 'count': new_failed_urls.get(url, {'count': 0})['count'] + 1}
                
                # 中间保存
                if processed_urls[0] % progress_interval == 0 or processed_urls[0] == total_urls:
                    with open(temp_mpeg_file, 'w', encoding='utf-8') as f:
                        for url in valid_urls:
                            f.write(url + '\n')
                    for category, urls in categorized_urls.items():
                        with open(temp_category_files[category], 'w', encoding='utf-8') as f:
                            for url in urls:
                                f.write(url + '\n')
                    progress = (processed_urls[0] / total_urls) * 100
                    remaining = total_urls - processed_urls[0]
                    avg_time = sum(avg_times) / len(avg_times) if avg_times else 0
                    eta_minutes = (remaining * avg_time) / 60
                    logging.info(f"进度: {processed_urls[0]}/{total_urls} ({progress:.1f}%)，剩余: {remaining}，预计剩余时间: {eta_minutes:.1f}分钟，中间结果已保存")
            except Exception as e:
                logging.error(f"处理 URL {url} 时出错: {e}")
                new_failed_urls[url] = {'timestamp': current_time, 'count': new_failed_urls.get(url, {'count': 0})['count'] + 1}
                processed_urls[0] += 1
                if processed_urls[0] % progress_interval == 0 or processed_urls[0] == total_urls:
                    progress = (processed_urls[0] / total_urls) * 100
                    remaining = total_urls - processed_urls[0]
                    avg_time = sum(avg_times) / len(avg_times) if avg_times else 0
                    eta_minutes = (remaining * avg_time) / 60
                    logging.info(f"进度: {processed_urls[0]}/{total_urls} ({progress:.1f}%)，剩余: {remaining}，预计剩余时间: {eta_minutes:.1f}分钟，中间结果已保存")

    # 保存最终结果
    with open(f'output/mpeg_shard_{args.shard}.txt', 'w', encoding='utf-8') as f:
        for url in valid_urls:
            f.write(url + '\n')
    logging.info(f"有效 URL 已保存到 output/mpeg_shard_{args.shard}.txt，共 {len(valid_urls)} 个")

    for category, urls in categorized_urls.items():
        category_filename = f'output/{category.replace("/", "_").replace(" ", "_")}_shard_{args.shard}.txt'
        with open(category_filename, 'w', encoding='utf-8') as f:
            for url in urls:
                f.write(url + '\n')
    logging.info(f"分类 URL 已保存，共 {len(categorized_urls)} 个分类文件")

    # 保存失败 URL
    with open(FAILED_FILE, 'w', encoding='utf-8') as f:
        for url, info in {**failed_urls, **new_failed_urls}.items():
            timestamp = info['timestamp'] or datetime.now().isoformat()
            count = info['count']
            f.write(f"{url}|{timestamp}|{count}\n")
    logging.info(f"失败 URL 已保存到 output/failed.txt，共 {len(new_failed_urls)} 个")

    # 保存时间戳
    with open(TIMESTAMPS_FILE, 'w', encoding='utf-8') as f:
        json.dump(timestamps, f, ensure_ascii=False, indent=2)
    logging.info("时间戳已保存到 output/timestamps.json")

    # 最终进度
    progress = (processed_urls[0] / total_urls) * 100
    remaining = total_urls - processed_urls[0]
    avg_time = sum(avg_times) / len(avg_times) if avg_times else 0
    eta_minutes = (remaining * avg_time) / 60
    logging.info(f"处理完成：有效 URL {len(valid_urls)} 个，失败 URL {len(new_failed_urls)} 个，分类文件 {len(categorized_urls)} 个")
    logging.info(f"最终进度: {processed_urls[0]}/{total_urls} ({progress:.1f}%)，剩余: {remaining}，预计剩余时间: {eta_minutes:.1f}分钟")

if __name__ == "__main__":
    main()
