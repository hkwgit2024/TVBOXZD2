import os
import re
import requests
import logging
import json
import hashlib
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, urljoin
from tqdm import tqdm

# --- 配置 ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# 从环境变量获取敏感信息和关键路径
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
PRIVATE_REMOTE_URLS_TXT_BASE_URL = os.getenv('PRIVATE_REMOTE_URLS_TXT_BASE_URL')

OUTPUT_DIR = "output"
LOCAL_URLS_FILE = os.path.join(OUTPUT_DIR, "urls.txt") # 本地保存的urls.txt，会被工作流提交
PROCESSING_STATE_FILE = os.path.join(OUTPUT_DIR, "url_processing_state.json") # 保存处理状态（哈希和时间戳）
VALID_SOURCE_URLS_FILE = os.path.join(OUTPUT_DIR, "valid_source_urls.txt") # 可访问且可能是节目源的URL
FINAL_IPTV_SOURCES_FILE = os.path.join(OUTPUT_DIR, "final_iptv_sources.txt") # 最终去重后的节目源列表
VALID_IPTV_SOURCES_FILE = os.path.join(OUTPUT_DIR, "valid_iptv_sources.txt") # 通过测试的节目源
INVALID_IPTV_SOURCES_LOG = os.path.join(OUTPUT_DIR, "invalid_iptv_sources.log") # 不可用节目源日志

# 并发数配置
MAX_WORKERS = 100 # 提高并发数以加快处理速度，可以根据实际效果调整

# 如果某个源链接内容连续多少天没有变化，则重新检查（强制刷新机制）
FORCE_RECHECK_DAYS = 7

# 单个源文件内容下载的最大大小（字节），防止下载超大文件导致内存溢出和时间过长
MAX_SOURCE_FILE_SIZE_BYTES = 10 * 1024 * 1024 # 10 MB

# 正则表达式：用于从文本中提取实际的节目源URL
URL_EXTRACTION_REGEX = re.compile(
    r'https?://[^\s"<>\'\\]+\.(?:m3u8|m3u|ts|mp4|flv|webm|avi|mkv|mov|wmv|mpg|mpeg|3gp|mov|vob|ogg|ogv|ogx|amv|rm|rmvb|asf|divx|xvid|f4v|vob|flac|aac|mp3|wav|ogg|wma|pls|asx|wax|wvx|ram|sdp|smi|smil)(?:[?#][^\s"<>\'\\]*)?'
    r'|https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d+)?(?:/[^\s"<>\'\\]*)?' # IP地址
    r'|https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s"<>\'\\]*)?', # 域名
    re.IGNORECASE
)

# 用于解析M3U8/M3U播放列表中的分片URL (改进：支持相对路径)
M3U8_SEGMENT_REGEX = re.compile(
    r'^(?!#).*?\.(?:ts|m3u8|m3u|mp4)(?:[?#][^\s"<>\'\\]*)?$', re.IGNORECASE
)

# --- 辅助函数 ---

def read_file_lines(file_path):
    """读取文件内容并按行返回列表，处理文件不存在的情况"""
    try:
        if not os.path.exists(file_path):
            logging.warning(f"文件不存在: {file_path}，将创建空文件。")
            return []
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f if line.strip()]
            logging.info(f"成功从 {file_path} 读取 {len(lines)} 行。")
            return lines
    except Exception as e:
        logging.error(f"读取文件失败 {file_path}: {e}")
        return []

def write_file_lines(file_path, lines, chunk_size=100000): # 增加 chunk_size 参数，默认 10万行
    """
    将列表内容写入文件，每行一个元素，支持分块写入。
    已优化：移除对大量数据进行排序的步骤，直接去重后写入。
    """
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True) # 确保目录存在
        
        unique_lines = list(set(lines)) # 先去重，转换为列表以便分块
        total_lines = len(unique_lines)
        logging.info(f"开始写入 {total_lines} 个唯一行到 {file_path}，使用分块大小 {chunk_size}。")

        with open(file_path, 'w', encoding='utf-8') as f:
            for i in range(0, total_lines, chunk_size):
                chunk = unique_lines[i:i + chunk_size]
                f.write("\n".join(chunk) + "\n")
                # Removed debug log here to reduce log volume during large writes.
                # logging.debug(f"已写入 {i + len(chunk)}/{total_lines} 行到 {file_path}") 

        logging.info(f"成功写入 {total_lines} 个唯一行到 {file_path}")
    except Exception as e:
        logging.error(f"写入文件失败 {file_path}: {e}")
        raise

def log_invalid_url(file_path, url, error_message):
    """记录不可用的URL及其错误信息到日志文件"""
    try:
        with open(file_path, 'a', encoding='utf-8') as f:
            f.write(f"{datetime.now().isoformat()} - {url}: {error_message}\n")
    except Exception as e:
        logging.error(f"写入不可用URL日志失败 {file_path}: {e}")

def clear_log_file(file_path):
    """清空日志文件"""
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8'):
            pass
        logging.info(f"已清空日志文件 {file_path}")
    except Exception as e:
        logging.error(f"清空日志文件失败 {file_path}: {e}")

def load_json_state(file_path):
    """加载 JSON 状态文件"""
    try:
        if not os.path.exists(file_path):
            logging.info(f"状态文件不存在: {file_path}，将创建空状态。")
            return {}
        with open(file_path, 'r', encoding='utf-8') as f:
            state = json.load(f)
            logging.info(f"成功加载状态文件 {file_path}。")
            return state
    except json.JSONDecodeError as e:
        logging.error(f"解析 JSON 状态文件失败 {file_path}: {e}。文件可能损坏或为空，将返回空状态。")
        return {}
    except Exception as e:
        logging.error(f"加载 JSON 状态文件失败 {file_path}: {e}")
        return {}

def save_json_state(file_path, state):
    """保存 JSON 状态文件"""
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True) # 确保目录存在
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(state, f, indent=4)
        logging.info(f"成功保存状态到 {file_path}")
    except Exception as e:
        logging.error(f"保存 JSON 状态文件失败 {file_path}: {e}")
        raise

def fetch_remote_urls_txt(url, token):
    """从私有GitHub raw链接下载urls.txt内容"""
    headers = {
        'Authorization': f'token {token}',
        'Accept': 'application/vnd.github.com.v3.raw',
        'User-Agent': 'GitHubActions-IPTV-Processor'
    }
    try:
        logging.info(f"正在下载远程 {url}")
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        lines = [line.strip() for line in response.text.splitlines() if line.strip()]
        logging.info(f"成功下载 {len(lines)} 行远程 urls.txt。")
        return lines
    except requests.exceptions.RequestException as e:
        logging.error(f"下载远程urls.txt失败 {url}: {e}")
        return []

def check_url_accessibility_and_format(url):
    """
    检查URL是否可访问且可能是节目源（基于扩展名或Content-Type）。
    返回 (url, is_valid, error_message)：
    - is_valid: True 表示可访问且可能是节目源，False 表示不可用或非节目源
    - error_message: 如果不可用，返回错误原因
    """
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        response.raise_for_status()
        content_type = response.headers.get('Content-Type', '').lower()

        valid_extensions = ['.m3u8', '.m3u', '.ts', '.mp4', '.flv', '.webm', '.avi', '.mkv', '.mov', '.wmv', '.mpg', '.mpeg', '.3gp', '.vob', '.ogg', '.ogv', '.ogx', '.amv', '.rm', '.rmvb', '.asf', '.divx', '.xvid', '.f4v', '.vob', '.flac', '.aac', '.mp3', '.wav', '.pls', '.asx', '.wax', '.wvx', '.ram', '.sdp', '.smi', '.smil']
        valid_content_types = [
            'application/vnd.apple.mpegurl', 'application/x-mpegurl', # M3U8
            'video/', 'audio/', # 广泛匹配所有视频和音频类型
            'application/octet-stream' # 有些服务器对流文件会返回这个
        ]

        url_lower = url.lower()
        is_potential_stream = any(ext in url_lower for ext in valid_extensions) or \
                             any(ct in content_type for ct in valid_content_types)

        if not is_potential_stream:
            return url, False, f"非节目源URL（Content-Type: {content_type} 或扩展名不匹配）"

        return url, True, ""
    except requests.exceptions.Timeout:
        return url, False, "请求超时"
    except requests.exceptions.HTTPError as e:
        return url, False, f"HTTP错误: {e.response.status_code}"
    except requests.exceptions.RequestException as e:
        return url, False, f"请求错误: {str(e)}"
    except Exception as e:
        return url, False, f"未知错误: {str(e)}"

def get_url_content_hash(url):
    """获取URL内容的MD5哈希值，用于判断内容是否变化"""
    # Using stream=True to prevent full download for large files,
    # though content hash implies full content.
    # We still rely on requests.get which eventually reads all content for hashing.
    # The MAX_SOURCE_FILE_SIZE_BYTES will effectively limit this.
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return hashlib.md5(response.content).hexdigest()
    except requests.exceptions.RequestException as e:
        logging.warning(f"获取URL内容哈希失败 {url}: {e}")
        return None

def extract_stream_urls_from_content(content):
    """从文本内容中提取潜在的节目源URL"""
    return list(set(URL_EXTRACTION_REGEX.findall(content)))

# --- 修改后的 process_single_source_url 函数 ---
def process_single_source_url(source_url, processing_state):
    """
    处理单个源URL：检查内容是否变化，提取节目源。
    返回提取到的节目源列表和更新后的状态信息。
    """
    extracted_urls = []
    current_time_str = datetime.now().isoformat()
    last_processed_info = processing_state.get(source_url, {})
    
    # 判断是否需要强制重新处理
    force_reprocess_by_time = False
    if "last_processed" in last_processed_info:
        last_processed_dt = datetime.fromisoformat(last_processed_info["last_processed"])
        if datetime.now() - last_processed_dt > timedelta(days=FORCE_RECHECK_DAYS):
            force_reprocess_by_time = True
            logging.info(f"源URL {source_url} 超过 {FORCE_RECHECK_DAYS} 天未更新，强制重新处理")

    # 获取内容哈希 (此处仍然会下载完整内容，受 MAX_SOURCE_FILE_SIZE_BYTES 限制)
    # 我们可以选择跳过哈希计算，如果不想在提取前下载两次内容。
    # 但哈希是用于优化“不重复处理未更改内容”的核心机制。
    # 更好的方式是在第一次下载内容时同时计算哈希。
    
    # 暂时保持现有逻辑，先尝试获取哈希，如果失败或内容未变则跳过。
    # 如果要避免重复下载，需要重构此函数，将下载和哈希计算合并。
    
    # 获取内容哈希，这里仍然会触发一次请求
    current_content_hash = get_url_content_hash(source_url)
    
    # 如果内容未变化且不需要强制刷新，则跳过
    if current_content_hash and \
       current_content_hash == last_processed_info.get("content_hash") and \
       not force_reprocess_by_time:
        logging.debug(f"源URL {source_url} 内容未变化，跳过提取。")
        processing_state[source_url] = {
            "last_processed": current_time_str,
            "content_hash": current_content_hash
        }
        return extracted_urls, source_url # 返回空列表，因为没有新提取的URL
    
    # 提取节目源
    try:
        logging.info(f"正在提取 {source_url} 中的节目源...")
        content_bytes = b""
        total_downloaded = 0
        
        # 使用 stream=True 和 iter_content 来处理大文件和超时
        with requests.get(source_url, stream=True, timeout=15) as response:
            response.raise_for_status() # 检查HTTP错误

            for chunk in response.iter_content(chunk_size=8192): # 每次读取8KB
                if chunk:
                    content_bytes += chunk
                    total_downloaded += len(chunk)
                    if total_downloaded > MAX_SOURCE_FILE_SIZE_BYTES:
                        logging.warning(f"源文件 {source_url} 超过最大允许大小 {MAX_SOURCE_FILE_SIZE_BYTES / (1024 * 1024):.1f}MB，中止下载。")
                        break # 超过大小限制，停止下载

        if total_downloaded > MAX_SOURCE_FILE_SIZE_BYTES:
            raise ValueError(f"文件过大，已中止下载 (> {MAX_SOURCE_FILE_SIZE_BYTES / (1024 * 1024):.1f}MB)")

        # 尝试解码内容，如果不是 UTF-8 可能会失败
        try:
            content = content_bytes.decode('utf-8')
        except UnicodeDecodeError:
            # 尝试其他常见编码，例如 Latin-1
            try:
                content = content_bytes.decode('latin-1')
                logging.warning(f"源文件 {source_url} 非UTF-8编码，尝试使用 Latin-1 解码。")
            except Exception:
                raise ValueError("无法解码源文件内容为文本。")

        extracted_urls = extract_stream_urls_from_content(content)
        logging.info(f"从 {source_url} 提取到 {len(extracted_urls)} 个节目源 (大小: {total_downloaded / (1024 * 1024):.2f}MB)。")

        # 更新状态（确保哈希是基于实际下载的内容，如果之前未获取到有效哈希的话）
        # 如果哈希在 get_url_content_hash 中已经成功获取，这里无需再次计算。
        # 如果 get_url_content_hash 失败，但这里成功下载了内容，则更新哈希。
        final_content_hash = hashlib.md5(content_bytes).hexdigest() if content_bytes else None
        processing_state[source_url] = {
            "last_processed": current_time_str,
            "content_hash": final_content_hash if final_content_hash else last_processed_info.get("content_hash")
        }
        return extracted_urls, source_url
    
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.HTTPError, ValueError) as e:
        logging.warning(f"提取源URL失败 {source_url}: {e}。将保留旧状态或更新为当前时间戳。")
        processing_state[source_url] = {
            "last_processed": current_time_str,
            "content_hash": last_processed_info.get("content_hash")
        }
    except Exception as e:
        logging.error(f"处理源URL {source_url} 时发生未知错误: {e}。")
        processing_state[source_url] = {
            "last_processed": current_time_str,
            "content_hash": last_processed_info.get("content_hash")
        }
    return extracted_urls, source_url

# --- 主逻辑（保持不变） ---
def main():
    if not GITHUB_TOKEN:
        logging.error("错误：环境变量 'GITHUB_TOKEN' 未设置。请确保已配置。")
        exit(1)
    if not PRIVATE_REMOTE_URLS_TXT_BASE_URL:
        logging.error("错误：环境变量 'PRIVATE_REMOTE_URLS_TXT_BASE_URL' 未设置。请确保已配置。")
        exit(1)

    logging.info("--- IPTV 节目源处理脚本开始运行 ---")

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    local_source_urls_set = set(read_file_lines(LOCAL_URLS_FILE))
    processing_state = load_json_state(PROCESSING_STATE_FILE)
    logging.info(f"本地 urls.txt 包含 {len(local_source_urls_set)} 个源URL。")

    remote_source_urls = fetch_remote_urls_txt(PRIVATE_REMOTE_URLS_TXT_BASE_URL, GITHUB_TOKEN)
    remote_source_urls_set = set(remote_source_urls)
    all_source_urls_set = local_source_urls_set | remote_source_urls_set
    logging.info(f"合并本地和远程源后，共有 {len(all_source_urls_set)} 个唯一源URL。")

    write_file_lines(LOCAL_URLS_FILE, list(all_source_urls_set))

    logging.info("--- 检查源URL可访问性和格式 ---")
    valid_source_urls = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(check_url_accessibility_and_format, url): url for url in tqdm(all_source_urls_set, desc="检查源URL") if url}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                _, is_valid, error_message = future.result()
                if is_valid:
                    valid_source_urls.append(url)
                else:
                    logging.debug(f"源URL不可用或非节目源: {url} ({error_message})")
            except Exception as exc:
                logging.error(f"检查源URL {url} 时发生异常: {exc}")

    logging.info(f"筛选出 {len(valid_source_urls)} 个可访问且可能是节目源的URL。")
    write_file_lines(VALID_SOURCE_URLS_FILE, valid_source_urls)

    logging.info("--- 提取节目源 ---")
    all_extracted_stream_urls = set()
    updated_processing_state = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(process_single_source_url, url, processing_state): url for url in tqdm(valid_source_urls, desc="提取节目源") if url}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                extracted_streams, updated_url_key = future.result()
                all_extracted_stream_urls.update(extracted_streams)
                updated_processing_state[updated_url_key] = processing_state.get(updated_url_key, {}) 
            except Exception as exc:
                logging.error(f"提取节目源 {url} 时发生异常: {exc}")
                updated_processing_state[url] = processing_state.get(url, {})

    for url, state_info in processing_state.items():
        if url not in updated_processing_state and url in all_source_urls_set:
            updated_processing_state[url] = state_info

    logging.info(f"提取到 {len(all_extracted_stream_urls)} 个去重后的节目源。")
    save_json_state(PROCESSING_STATE_FILE, updated_processing_state)
    write_file_lines(FINAL_IPTV_SOURCES_FILE, list(all_extracted_stream_urls))

    logging.info("--- 测试节目源可播放性 ---")
    stream_urls = read_file_lines(FINAL_IPTV_SOURCES_FILE)
    if not stream_urls:
        logging.warning("没有可供测试的节目源，跳过测试步骤。")
        logging.info("--- 脚本运行完成 ---")
        return

    valid_stream_urls = []
    clear_log_file(INVALID_IPTV_SOURCES_LOG)
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_url = {executor.submit(test_stream_url, url): url for url in tqdm(stream_urls, desc="测试节目源") if url}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                _, is_valid, error_message = future.result()
                if is_valid:
                    valid_stream_urls.append(url)
                else:
                    log_invalid_url(INVALID_IPTV_SOURCES_LOG, url, error_message)
            except Exception as exc:
                log_invalid_url(INVALID_IPTV_SOURCES_LOG, url, f"测试异常: {str(exc)}")

    logging.info(f"测试完成，{len(valid_stream_urls)}/{len(stream_urls)} 个节目源通过验证。")
    write_file_lines(VALID_IPTV_SOURCES_FILE, valid_stream_urls) 

    logging.info("--- 脚本运行完成 ---")

if __name__ == "__main__":
    main()
