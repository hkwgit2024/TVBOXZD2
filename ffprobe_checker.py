import subprocess
import os
import re
import sys
import asyncio
import aiohttp
import logging
import tempfile
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from collections import defaultdict
from urllib.parse import urlparse
from time import time
import argparse
import multiprocessing

def parse_arguments():
    """解析命令行参数和环境变量"""
    parser = argparse.ArgumentParser(description="Check m3u8 streaming URLs with async HTTP pre-check and ffprobe.")
    parser.add_argument('--timeout', type=float, default=float(os.getenv('FFPROBE_TIMEOUT', 5)),
                        help='Timeout for ffprobe in seconds (default: 5)')
    parser.add_argument('--http-timeout', type=float, default=float(os.getenv('HTTP_TIMEOUT', 2)),
                        help='Timeout for HTTP pre-check in seconds (default: 2)')
    parser.add_argument('--workers', type=int, default=int(os.getenv('MAX_WORKERS', max(4, multiprocessing.cpu_count() * 2))),
                        help='Number of concurrent workers (default: CPU cores * 2)')
    parser.add_argument('--retries', type=int, default=int(os.getenv('MAX_RETRIES', 2)),
                        help='Number of retries for failed URLs (default: 2)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    args = parser.parse_args()
    if not (1 <= args.timeout <= 30): raise ValueError("Timeout must be between 1 and 30 seconds.")
    if not (0.5 <= args.http_timeout <= 10): raise ValueError("HTTP timeout must be between 0.5 and 10 seconds.")
    if not (1 <= args.workers <= 100): raise ValueError("Max workers must be between 1 and 100.")
    if not (0 <= args.retries <= 5): raise ValueError("Retries must be between 0 and 5.")
    return args.timeout, args.http_timeout, args.workers, args.retries, args.verbose

def setup_logging(verbose=False):
    """配置日志"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')

async def check_url_http(url, timeout_seconds=2):
    """异步检查URL的HTTP状态码"""
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout_seconds)) as session:
            async with session.head(url, allow_redirects=True) as response:
                if response.status == 200:
                    return True, time() - time()
                logging.debug(f"HTTP check failed for {url}: Status {response.status}")
                return False, time() - time()
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logging.debug(f"HTTP check failed for {url}: {e}")
        return False, time() - time()

def check_stream(url, timeout_seconds=5, retries=2):
    """使用ffprobe检查m3u8流的有效性，返回(是否成功, 耗时)"""
    start_time = time()
    non_fatal_warnings = ["deprecated pixel format", "non-monotonous DTS"]
    for attempt in range(retries + 1):
        try:
            command = [
                'ffprobe', '-v', 'error', '-print_format', 'json',
                '-show_streams', '-show_format', '-timeout', str(int(timeout_seconds * 1_000_000)),
                '-i', url
            ]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            if result.stderr and not any(warning in result.stderr.lower() for warning in non_fatal_warnings):
                logging.warning(f"Attempt {attempt+1}/{retries+1} for {url}: {result.stderr.strip()}")
                if attempt == retries:
                    return False, time() - start_time
                continue
            return True, time() - start_time
        except subprocess.CalledProcessError as e:
            logging.error(f"Attempt {attempt+1}/{retries+1} failed for {url}: {e.stderr.strip()}")
            if attempt == retries:
                return False, time() - start_time
        except FileNotFoundError:
            logging.error("ffprobe command not found. Ensure FFmpeg is installed and in PATH.")
            return False, time() - start_time
        except Exception as e:
            logging.error(f"Unexpected error in attempt {attempt+1}/{retries+1} for {url}: {e}")
            return False, time() - start_time
    return False, time() - start_time

def group_urls_by_domain(urls):
    """按域名分组URL，限制每个域名的并发"""
    domain_groups = defaultdict(list)
    for line_num, name, url in urls:
        domain = urlparse(url).netloc
        domain_groups[domain].append((line_num, name, url))
    return domain_groups

async def main():
    timeout_seconds, http_timeout, max_workers, retries, verbose = parse_arguments()
    setup_logging(verbose)
    logging.info(f"Starting with timeout={timeout_seconds}s, http_timeout={http_timeout}s, workers={max_workers}, retries={retries}...")

    list_file = 'list.txt'
    failed_links_file = 'failed_links.txt'
    output_file = 'ff.txt'

    # 检查list.txt
    if not os.path.exists(list_file):
        logging.error(f"'{list_file}' not found.")
        sys.exit(1)

    # 加载已知失败链接
    failed_links = set()
    if os.path.exists(failed_links_file):
        try:
            with open(failed_links_file, 'r', encoding='utf-8') as f:
                failed_links = {line.strip() for line in f if line.strip()}
            logging.info(f"Loaded {len(failed_links)} previously failed links.")
        except Exception as e:
            logging.warning(f"Could not load '{failed_links_file}': {e}")

    # 读取并验证URL
    url_pattern = re.compile(r'^https?://[^\s/$.?#].[^\s]*\.m3u8(\?.*)?$')
    lines_to_process = []
    original_structure = []
    channel_urls = defaultdict(list)
    logging.info(f"Reading '{list_file}'...")
    try:
        with open(list_file, 'r', encoding='utf-8') as infile:
            for line_num, line in enumerate(infile):
                line = line.strip()
                original_structure.append(line)
                if not line or '#genre#' in line:
                    continue
                parts = line.split(',', 1)
                if len(parts) != 2:
                    logging.warning(f"Skipping malformed line {line_num+1}: {line}")
                    continue
                name, url = parts[0].strip(), parts[1].strip()
                if not url_pattern.match(url):
                    logging.warning(f"Skipping invalid URL at line {line_num+1}: {url}")
                    continue
                if url not in failed_links:
                    lines_to_process.append((line_num, name, url))
                    channel_urls[name].append((line_num, url))
    except Exception as e:
        logging.error(f"Could not read '{list_file}': {e}")
        sys.exit(1)

    if not lines_to_process:
        logging.info("No new links to process. Updating output files...")
        update_files(output_file, failed_links_file, original_structure, set(), failed_links)
        return

    # 异步HTTP预检查
    logging.info(f"Performing HTTP pre-check for {len(lines_to_process)} URLs...")
    http_results = {}
    async with aiohttp.ClientSession() as session:
        tasks = [check_url_http(url, http_timeout) for _, _, url in lines_to_process]
        for (line_num, name, url), (is_valid, duration) in zip(lines_to_process, await asyncio.gather(*tasks)):
            http_results[url] = is_valid
            logging.debug(f"HTTP check for {url}: {'Valid' if is_valid else 'Invalid'} ({duration:.2f}s)")

    # 过滤有效URL进行ffprobe检查
    ffprobe_urls = [(line_num, name, url) for line_num, name, url in lines_to_process if http_results[url]]
    logging.info(f"Checking {len(ffprobe_urls)} URLs with ffprobe (filtered by HTTP)...")

    # 按域名分组，限制每个域名的并发
    domain_groups = group_urls_by_domain(ffprobe_urls)
    successful_urls = {}
    current_failed_links = set(failed_links)
    url_cache = {}  # 缓存相同URL的结果

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        for domain, urls in domain_groups.items():
            domain_max_workers = max(1, max_workers // len(domain_groups))  # 每个域名分配线程
            future_to_link = {
                executor.submit(check_stream, url, timeout_seconds, retries): (line_num, name, url)
                for line_num, name, url in urls if url not in url_cache
            }
            for future in tqdm(as_completed(future_to_link), total=len(future_to_link), desc=f"Checking {domain}"):
                line_num, name, url = future_to_link[future]
                try:
                    is_successful, duration = future.result()
                    url_cache[url] = (is_successful, duration)
                    if is_successful:
                        if name not in successful_urls or duration < successful_urls[name][1]:
                            successful_urls[name] = (url, duration)
                        logging.debug(f"Success: {name} - {url} ({duration:.2f}s)")
                    else:
                        current_failed_links.add(url)
                        logging.debug(f"Failed: {name} - {url} ({duration:.2f}s)")
                except Exception as e:
                    logging.error(f"Unexpected error for {url}: {e}")
                    current_failed_links.add(url)
                    url_cache[url] = (False, 0)

    # 应用缓存结果到重复URL
    for line_num, name, url in ffprobe_urls:
        if url in url_cache and url not in successful_urls.get(name, (None, float('inf')))[0]:
            is_successful, duration = url_cache[url]
            if is_successful and (name not in successful_urls or duration < successful_urls[name][1]):
                successful_urls[name] = (url, duration)

    # 更新输出文件
    logging.info("Updating output files...")
    final_successful_urls = {url for _, (url, _) in successful_urls.items()}
    update_files(output_file, failed_links_file, original_structure, final_successful_urls, current_failed_links)

def update_files(output_file, failed_links_file, original_structure, successful_urls, current_failed_links):
    """使用临时文件写入结果"""
    final_ff_content = []
    for line in original_structure:
        if '#genre#' in line or ',' not in line:
            final_ff_content.append(line)
        else:
            parts = line.split(',', 1)
            if len(parts) == 2:
                name, url = parts[0].strip(), parts[1].strip()
                if url in successful_urls:
                    final_ff_content.append(line)

    with tempfile.NamedTemporaryFile('w', encoding='utf-8', delete=False) as tmp:
        tmp.write('\n'.join(final_ff_content) + '\n')
        tmp_name = tmp.name
    try:
        shutil.move(tmp_name, output_file)
        logging.info(f"Successfully wrote to '{output_file}'")
    except Exception as e:
        logging.error(f"Could not write to '{output_file}': {e}")

    with tempfile.NamedTemporaryFile('w', encoding='utf-8', delete=False) as tmp:
        for link in sorted(current_failed_links):
            tmp.write(f"{link}\n")
        tmp_name = tmp.name
    try:
        shutil.move(tmp_name, failed_links_file)
        logging.info(f"Successfully updated '{failed_links_file}'")
    except Exception as e:
        logging.error(f"Could not write to '{failed_links_file}': {e}")

if __name__ == "__main__":
    asyncio.run(main())
