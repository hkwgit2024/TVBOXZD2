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
    parser = argparse.ArgumentParser(description="Check streaming URLs with async HTTP pre-check and ffprobe.")
    parser.add_argument('--timeout', type=float, default=float(os.getenv('FFPROBE_TIMEOUT', 10)),
                        help='Timeout for ffprobe in seconds (default: 10)')
    parser.add_argument('--http-timeout', type=float, default=float(os.getenv('HTTP_TIMEOUT', 3)),
                        help='Timeout for HTTP pre-check in seconds (default: 3)')
    parser.add_argument('--workers', type=int, default=int(os.getenv('MAX_WORKERS', max(10, multiprocessing.cpu_count() * 4))),
                        help='Number of concurrent workers (default: CPU cores * 4)')
    parser.add_argument('--retries', type=int, default=int(os.getenv('MAX_RETRIES', 2)),
                        help='Number of retries for failed URLs (default: 2)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    parser.add_argument('--batch-size', type=int, default=int(os.getenv('BATCH_SIZE', 1000)),
                        help='Batch size for URL processing (default: 1000)')
    args = parser.parse_args()
    if not (1 <= args.timeout <= 30): raise ValueError("Timeout must be between 1 and 30 seconds.")
    if not (0.5 <= args.http_timeout <= 10): raise ValueError("HTTP timeout must be between 0.5 and 10 seconds.")
    if not (1 <= args.workers <= 200): raise ValueError("Max workers must be between 1 and 200.")
    if not (0 <= args.retries <= 5): raise ValueError("Retries must be between 0 and 5.")
    if not (100 <= args.batch_size <= 5000): raise ValueError("Batch size must be between 100 and 5000.")
    return args.timeout, args.http_timeout, args.workers, args.retries, args.verbose, args.batch_size

def setup_logging(verbose=False):
    """配置日志"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')
    if verbose and os.path.getsize('list.txt') > 10_000_000:  # 如果 list.txt > 10MB
        logging.getLogger().setLevel(logging.INFO)
        logging.info("Verbose logging disabled for large URL lists to reduce output.")

async def check_url_http(url, timeout_seconds=3, proxy=None):
    """异步检查URL的HTTP状态码和Content-Type"""
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout_seconds)) as session:
            method = os.getenv('HTTP_METHOD', 'GET').upper()  # 默认使用 GET
            async with getattr(session, method.lower())(url, allow_redirects=True, proxy=proxy) as response:
                if response.status == 200:
                    content_type = response.headers.get('Content-Type', '').lower()
                    valid_types = [
                        'application/vnd.apple.mpegurl',  # m3u8
                        'video/mp4',                      # mp4
                        'video/mp2t',                     # ts
                        'video/x-flv',                    # flv
                        'video/x-matroska',               # mkv
                        'application/octet-stream'         # 某些动态流
                    ]
                    if any(t in content_type for t in valid_types) or url.endswith('.php'):
                        return True, time() - time()
                    logging.debug(f"HTTP check failed for {url}: Invalid Content-Type {content_type}")
                    return False, time() - time()
                logging.debug(f"HTTP check failed for {url}: Status {response.status}")
                return False, time() - time()
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        logging.debug(f"HTTP check failed for {url}: {e}")
        return False, time() - time()

def check_stream(url, timeout_seconds=10, retries=2):
    """使用ffprobe检查流的有效性，返回(是否成功, 耗时)"""
    start_time = time()
    non_fatal_warnings = ["deprecated pixel format", "non-monotonous DTS", "invalid data found"]
    for attempt in range(retries + 1):
        try:
            command = [
                'ffprobe', '-v', 'error', '-print_format', 'json',
                '-show_streams', '-show_format', '-timeout', str(int(timeout_seconds * 1_000_000)),
                '-i', url
            ]
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            if result.stderr and not any(warning in result.stderr.lower() for warning in non_fatal_warnings):
                logging.warning(f"Attempt {attempt+1}/{retries+1} for {url}: {result.stderr.strip() or 'Unknown error'}")
                if attempt == retries:
                    return False, time() - start_time
                continue
            return True, time() - start_time
        except subprocess.CalledProcessError as e:
            logging.error(f"Attempt {attempt+1}/{retries+1} failed for {url}: {e.stderr.strip() or 'Unknown error'}")
            if attempt == retries:
                return False, time() - start_time
        except FileNotFoundError:
            logging.error("ffprobe command not found. Ensure FFmpeg is installed and in PATH.")
            sys.exit(1)
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

async def process_batch(urls, timeout_seconds, http_timeout, max_workers, retries, batch_size):
    """分批处理URL"""
    successful_urls = {}
    current_failed_links = set()
    url_cache = {}  # 缓存相同URL的结果
    proxy = os.getenv('HTTP_PROXY')

    for i in range(0, len(urls), batch_size):
        batch = urls[i:i + batch_size]
        logging.info(f"Processing batch {i // batch_size + 1} with {len(batch)} URLs...")

        # HTTP 预检查
        logging.info(f"Performing HTTP pre-check for {len(batch)} URLs...")
        http_results = {}
        async with aiohttp.ClientSession() as session:
            tasks = [check_url_http(url, http_timeout, proxy) for _, _, url in batch]
            for (line_num, name, url), (is_valid, duration) in zip(batch, await asyncio.gather(*tasks)):
                http_results[url] = is_valid
                logging.debug(f"HTTP check for {url}: {'Valid' if is_valid else 'Invalid'} ({duration:.2f}s)")

        # 过滤有效URL进行ffprobe检查
        ffprobe_urls = [(line_num, name, url) for line_num, name, url in batch if http_results[url]]
        logging.info(f"Checking {len(ffprobe_urls)} URLs with ffprobe (filtered by HTTP)...")

        # 按域名分组
        domain_groups = group_urls_by_domain(ffprobe_urls)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for domain, domain_urls in domain_groups.items():
                domain_max_workers = max(1, max_workers // max(1, len(domain_groups)))
                future_to_link = {
                    executor.submit(check_stream, url, timeout_seconds, retries): (line_num, name, url)
                    for line_num, name, url in domain_urls if url not in url_cache
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

    return successful_urls, current_failed_links

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

async def main():
    start_time = time()
    timeout_seconds, http_timeout, max_workers, retries, verbose, batch_size = parse_arguments()
    setup_logging(verbose)
    logging.info(f"Starting with timeout={timeout_seconds}s, http_timeout={http_timeout}s, workers={max_workers}, retries={retries}, batch_size={batch_size}...")

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
    url_pattern = re.compile(r'^https?://[^\s/$.?#].[^\s]*\.(m3u8|php|mp4|ts|flv|mkv)(\?.*)?$')
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

    # 分批处理URL
    successful_urls, current_failed_links = await process_batch(lines_to_process, timeout_seconds, http_timeout, max_workers, retries, batch_size)

    # 更新输出文件
    logging.info("Updating output files...")
    final_successful_urls = {url for _, (url, _) in successful_urls.items()}
    update_files(output_file, failed_links_file, original_structure, final_successful_urls, current_failed_links)
    logging.info(f"Total runtime: {time() - start_time:.2f} seconds")

if __name__ == "__main__":
    asyncio.run(main())
