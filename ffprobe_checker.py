import subprocess
import os
import re
import sys
import argparse
import logging
import tempfile
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
from collections import defaultdict
from time import time

def parse_arguments():
    """解析命令行参数和环境变量"""
    parser = argparse.ArgumentParser(description="Check m3u8 streaming URLs using ffprobe.")
    parser.add_argument('--timeout', type=float, default=float(os.getenv('FFPROBE_TIMEOUT', 5)),
                        help='Timeout for ffprobe in seconds (default: 5)')
    parser.add_argument('--workers', type=int, default=int(os.getenv('MAX_WORKERS', 10)),
                        help='Number of concurrent workers (default: 10)')
    parser.add_argument('--retries', type=int, default=int(os.getenv('MAX_RETRIES', 2)),
                        help='Number of retries for failed URLs (default: 2)')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    args = parser.parse_args()
    if not (1 <= args.timeout <= 30):
        raise ValueError("Timeout must be between 1 and 30 seconds.")
    if not (1 <= args.workers <= 100):
        raise ValueError("Max workers must be between 1 and 100.")
    if not (0 <= args.retries <= 5):
        raise ValueError("Retries must be between 0 and 5.")
    return args.timeout, args.workers, args.retries, args.verbose

def setup_logging(verbose=False):
    """配置日志"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')

def check_stream(url, timeout_seconds=5, retries=2):
    """
    使用 ffprobe 检查 m3u8 流的有效性，支持重试。
    返回 (是否成功, 检查耗时)。
    """
    start_time = time()
    non_fatal_warnings = ["deprecated pixel format", "non-monotonous DTS"]
    for attempt in range(retries + 1):
        try:
            command = [
                'ffprobe',
                '-v', 'error',
                '-print_format', 'json',
                '-show_streams',
                '-show_format',
                '-timeout', str(int(timeout_seconds * 1_000_000)),
                '-i', url  # 显式指定输入
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

def main():
    timeout_seconds, max_workers, retries, verbose = parse_arguments()
    setup_logging(verbose)
    logging.info(f"Starting ffprobe_checker.py with timeout={timeout_seconds}s, workers={max_workers}, retries={retries}...")

    list_file = 'list.txt'
    failed_links_file = 'failed_links.txt'
    output_file = 'ff.txt'

    # 检查 list.txt 是否存在
    if not os.path.exists(list_file):
        logging.error(f"'{list_file}' not found. Please ensure it's in the repository root.")
        sys.exit(1)

    # 加载已知失败的链接
    failed_links = set()
    if os.path.exists(failed_links_file):
        try:
            with open(failed_links_file, 'r', encoding='utf-8') as f:
                failed_links = {line.strip() for line in f if line.strip()}
            logging.info(f"Loaded {len(failed_links)} previously failed links.")
        except Exception as e:
            logging.warning(f"Could not load '{failed_links_file}': {e}. Starting with empty failed links.")

    # 读取 list.txt，验证 URL 格式
    url_pattern = re.compile(r'^https?://[^\s/$.?#].[^\s]*\.m3u8(\?.*)?$')
    lines_to_process = []
    original_structure = []
    channel_urls = defaultdict(list)  # 按频道分组 URL
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
                    logging.warning(f"Skipping invalid URL format at line {line_num+1}: {url}")
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

    logging.info(f"Checking {len(lines_to_process)} URLs with {max_workers} workers...")
    successful_urls = {}
    current_failed_links = set(failed_links)

    # 并发检查 URL
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_link = {
            executor.submit(check_stream, url, timeout_seconds, retries): (line_num, name, url)
            for line_num, name, url in lines_to_process
        }
        for future in tqdm(as_completed(future_to_link), total=len(future_to_link), desc="Checking URLs"):
            line_num, name, url = future_to_link[future]
            try:
                is_successful, duration = future.result()
                if is_successful:
                    if name not in successful_urls or duration < successful_urls[name][1]:
                        successful_urls[name] = (url, duration)  # 保留响应最快的 URL
                    logging.debug(f"Success: {name} - {url} ({duration:.2f}s)")
                else:
                    current_failed_links.add(url)
                    logging.debug(f"Failed: {name} - {url} ({duration:.2f}s)")
            except Exception as e:
                logging.error(f"Unexpected error for {url}: {e}")
                current_failed_links.add(url)

    # 更新输出文件
    logging.info("Updating output files...")
    final_successful_urls = {url for _, (url, _) in successful_urls.items()}
    update_files(output_file, failed_links_file, original_structure, final_successful_urls, current_failed_links)

def update_files(output_file, failed_links_file, original_structure, successful_urls, current_failed_links):
    """使用临时文件写入结果，保留原始结构"""
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
        tmp.write('\n'.join(final_ff_content))
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
    main()
