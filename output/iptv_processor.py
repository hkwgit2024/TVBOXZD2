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

# --- 配置 (与之前脚本相同的部分，此处省略以保持简洁) ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
PRIVATE_REMOTE_URLS_TXT_BASE_URL = os.getenv('PRIVATE_REMOTE_URLS_TXT_BASE_URL')

OUTPUT_DIR = "output"
LOCAL_URLS_FILE = os.path.join(OUTPUT_DIR, "urls.txt")
PROCESSING_STATE_FILE = os.path.join(OUTPUT_DIR, "url_processing_state.json")
VALID_SOURCE_URLS_FILE = os.path.join(OUTPUT_DIR, "valid_source_urls.txt")
FINAL_IPTV_SOURCES_FILE = os.path.join(OUTPUT_DIR, "final_iptv_sources.txt")
VALID_IPTV_SOURCES_FILE = os.path.join(OUTPUT_DIR, "valid_iptv_sources.txt")
INVALID_IPTV_SOURCES_LOG = os.path.join(OUTPUT_DIR, "invalid_iptv_sources.log")

MAX_WORKERS = 100
FORCE_RECHECK_DAYS = 7

URL_EXTRACTION_REGEX = re.compile(
    r'https?://[^\s"<>\'\\]+\.(?:m3u8|m3u|ts|mp4|flv|webm|avi|mkv|mov|wmv|mpg|mpeg|3gp|mov|vob|ogg|ogv|ogx|amv|rm|rmvb|asf|divx|xvid|f4v|vob|flac|aac|mp3|wav|ogg|wma|pls|asx|wax|wvx|ram|sdp|smi|smil)(?:[?#][^\s"<>\'\\]*)?'
    r'|https?://(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::\d+)?(?:/[^\s"<>\'\\]*)?'
    r'|https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:/[^\s"<>\'\\]*)?',
    re.IGNORECASE
)

M3U8_SEGMENT_REGEX = re.compile(
    r'^(?!#).*?\.(?:ts|m3u8|m3u|mp4)(?:[?#][^\s"<>\'\\]*)?$', re.IGNORECASE
)

# --- 辅助函数（只修改 write_file_lines，其他保持不变） ---

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
        
        # 对于 urls.txt 和 processing_state.json，以及较小的文件，我们不需要分块
        # 但对于 valid_iptv_sources.txt 和 final_iptv_sources.txt 可能会很大
        # 为了通用性，统一在这里处理去重，然后进行分块写入
        unique_lines = list(set(lines)) # 先去重，转换为列表以便分块
        total_lines = len(unique_lines)
        logging.info(f"开始写入 {total_lines} 个唯一行到 {file_path}，使用分块大小 {chunk_size}。")

        with open(file_path, 'w', encoding='utf-8') as f:
            for i in range(0, total_lines, chunk_size):
                chunk = unique_lines[i:i + chunk_size]
                # 使用 join 拼接字符串，比循环写入效率更高
                f.write("\n".join(chunk) + "\n")
                logging.debug(f"已写入 {i + len(chunk)}/{total_lines} 行到 {file_path}") # 使用 debug 级别避免频繁日志

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
        'Accept': 'application/vnd.github.com.v3.raw', # Adjusted Accept header
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

        # 支持的节目源扩展名和Content-Type
        valid_extensions = ['.m3u8', '.m3u', '.ts', '.mp4', '.flv', '.webm', '.avi', '.mkv', '.mov', '.wmv', '.mpg', '.mpeg', '.3gp', '.vob', '.ogg', '.ogv', '.ogx', '.amv', '.rm', '.rmvb', '.asf', '.divx', '.xvid', '.f4v', '.vob', '.flac', '.aac', '.mp3', '.wav', '.pls', '.asx', '.wax', '.wvx', '.ram', '.sdp', '.smi', '.smil']
        valid_content_types = [
            'application/vnd.apple.mpegurl', 'application/x-mpegurl', # M3U8
            'video/', 'audio/', # 广泛匹配所有视频和音频类型
            'application/octet-stream' # 有些服务器对流文件会返回这个
        ]

        # 检查URL是否包含节目源扩展名或Content-Type
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

def test_stream_url(url):
    """
    测试单个节目源URL是否可访问和可播放，包含复杂流验证。
    返回 (url, is_valid, error_message)：
    - is_valid: True 表示可播放，False 表示不可用
    - error_message: 如果不可用，返回错误原因
    """
    try:
        # 1. 使用 HEAD 请求快速检查可访问性
        response = requests.head(url, timeout=5, allow_redirects=True)
        response.raise_for_status()
        content_type = response.headers.get('Content-Type', '').lower()
        content_length = int(response.headers.get('Content-Length', 0))

        # 支持的流媒体 Content-Type，更全面
        valid_stream_content_types = [
            'application/vnd.apple.mpegurl', 'application/x-mpegurl', # M3U8
            'video/', 'audio/', # 广泛匹配所有视频和音频类型
            'application/octet-stream' # 有些服务器对流文件会返回这个
        ]

        # 2. 检查是否为 M3U8/M3U 播放列表
        is_m3u = 'm3u8' in url.lower() or 'm3u' in url.lower() or any(ct in content_type for ct in ['application/vnd.apple.mpegurl', 'application/x-mpegurl'])
        
        if is_m3u:
            # 对于 M3U8/M3U，需要获取实际内容来解析分片
            response = requests.get(url, timeout=5)
            response.raise_for_status()
            content = response.text
            lines = content.splitlines()
            segment_urls = [line.strip() for line in lines if M3U8_SEGMENT_REGEX.match(line)]
            
            if not segment_urls:
                return url, False, "M3U8/M3U 播放列表为空或无有效分片"

            from random import choice
            segment_relative_url = choice(segment_urls)
            # 构建完整的分片URL，处理相对路径
            segment_full_url = urljoin(url, segment_relative_url)

            # 再次使用 HEAD 请求测试一个分片
            segment_response = requests.head(segment_full_url, timeout=5, allow_redirects=True)
            segment_response.raise_for_status()
            segment_content_type = segment_response.headers.get('Content-Type', '').lower()
            
            if not any(ct in segment_content_type for ct in valid_stream_content_types):
                return url, False, f"M3U8/M3U 分片 Content-Type 无效: {segment_content_type}"
            
            return url, True, ""

        # 3. 对于非 M3U8/M3U 的直接流（如 TS、MP4），进行初步内容校验
        # 检查 Content-Length 是否过小，通常有效的流文件不会是0字节
        if content_length < 100 and content_length != 0: # 允许Content-Length为0但后面可以获取到数据的情况
             return url, False, f"Content-Length 过小: {content_length}字节"

        # 检查 Content-Type 是否为已知的流媒体类型
        is_direct_stream = any(ct in content_type for ct in valid_stream_content_types)
        
        if is_direct_stream:
            # 对于直接流，尝试下载少量数据进行文件头校验
            # 使用 stream=True 和 iter_content 避免下载整个文件
            response = requests.get(url, stream=True, timeout=5)
            response.raise_for_status()
            
            # 获取少量数据块 (例如 2KB)
            chunk = next(response.iter_content(chunk_size=2048), b'')
            response.close() # 及时关闭连接，释放资源

            if not chunk:
                return url, False, "空响应内容或无法读取数据"

            # 简单的文件头校验，提高准确性
            if 'video/mp2t' in content_type or url.lower().endswith('.ts'):
                if not chunk.startswith(b'\x47'): # TS 文件的同步字节
                    return url, False, "TS 文件头无效（缺少同步字节）"
            elif 'video/mp4' in content_type or url.lower().endswith('.mp4'):
                # MP4 文件的主要结构是 box，通常以 ftyp 开头
                if b'ftyp' not in chunk[:20]: # 检查前20字节内是否有 'ftyp'
                    return url, False, "MP4 文件头无效（缺少 'ftyp' 标识）"
            elif 'audio/mpeg' in content_type or url.lower().endswith('.mp3'):
                # 简单的MP3文件头校验 (ID3v2或MPEG帧头)
                if not (chunk.startswith(b'ID3') or (chunk[0] == 0xFF and chunk[1] in [0xFB, 0xF3, 0xF2, 0xFA, 0xF2])):
                    return url, False, "MP3 文件头无效"
            # 可以添加更多文件类型的校验

            return url, True, ""
        
        return url, False, f"Content-Type 不支持或无法识别为节目源: {content_type}"

    except requests.exceptions.Timeout:
        return url, False, "请求超时"
    except requests.exceptions.HTTPError as e:
        return url, False, f"HTTP错误: {e.response.status_code}"
    except requests.exceptions.ConnectionError as e:
        return url, False, f"连接错误: {str(e)}"
    except requests.exceptions.RequestException as e:
        return url, False, f"请求错误: {str(e)}"
    except Exception as e:
        return url, False, f"未知错误: {str(e)}"

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

    # 获取内容哈希
    current_content_hash = get_url_content_hash(source_url)
    
    # 如果内容未变化且不需要强制刷新，则跳过
    if current_content_hash and \
       current_content_hash == last_processed_info.get("content_hash") and \
       not force_reprocess_by_time:
        logging.debug(f"源URL {source_url} 内容未变化，跳过提取。") # 使用debug级别，避免过多日志
        processing_state[source_url] = {
            "last_processed": current_time_str,
            "content_hash": current_content_hash
        }
        return extracted_urls, source_url # 返回空列表，因为没有新提取的URL
    
    # 提取节目源
    try:
        logging.info(f"正在提取 {source_url} 中的节目源...")
        response = requests.get(source_url, timeout=15)
        response.raise_for_status()
        content = response.text
        extracted_urls = extract_stream_urls_from_content(content)
        logging.info(f"从 {source_url} 提取到 {len(extracted_urls)} 个节目源。")

        # 更新状态
        processing_state[source_url] = {
            "last_processed": current_time_str,
            "content_hash": current_content_hash
        }
        return extracted_urls, source_url
    except requests.exceptions.RequestException as e:
        logging.warning(f"提取源URL失败 {source_url}: {e}。将保留旧状态或更新为当前时间戳。")
        # 即使失败，也要更新时间戳，避免重复尝试很快失败的源
        processing_state[source_url] = {
            "last_processed": current_time_str,
            "content_hash": last_processed_info.get("content_hash") # 失败时保持旧哈希
        }
    except Exception as e:
        logging.error(f"处理源URL {source_url} 时发生未知错误: {e}。")
        processing_state[source_url] = {
            "last_processed": current_time_str,
            "content_hash": last_processed_info.get("content_hash")
        }
    return extracted_urls, source_url # 失败时返回空列表


# --- 主逻辑（保持不变） ---
def main():
    if not GITHUB_TOKEN:
        logging.error("错误：环境变量 'GITHUB_TOKEN' 未设置。请确保已配置。")
        exit(1)
    if not PRIVATE_REMOTE_URLS_TXT_BASE_URL:
        logging.error("错误：环境变量 'PRIVATE_REMOTE_URLS_TXT_BASE_URL' 未设置。请确保已配置。")
        exit(1)

    logging.info("--- IPTV 节目源处理脚本开始运行 ---")

    # 确保 output 目录存在
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    # 1. 加载本地 urls.txt 和处理状态
    local_source_urls_set = set(read_file_lines(LOCAL_URLS_FILE))
    processing_state = load_json_state(PROCESSING_STATE_FILE)
    logging.info(f"本地 urls.txt 包含 {len(local_source_urls_set)} 个源URL。")

    # 2. 从远程下载 urls.txt 并去重
    remote_source_urls = fetch_remote_urls_txt(PRIVATE_REMOTE_URLS_TXT_BASE_URL, GITHUB_TOKEN)
    remote_source_urls_set = set(remote_source_urls)
    all_source_urls_set = local_source_urls_set | remote_source_urls_set
    logging.info(f"合并本地和远程源后，共有 {len(all_source_urls_set)} 个唯一源URL。")

    # 保存去重后的源URL到本地，以便工作流提交
    write_file_lines(LOCAL_URLS_FILE, list(all_source_urls_set))

    # 3. 检查源URL可访问性和格式
    logging.info("--- 检查源URL可访问性和格式 ---")
    valid_source_urls = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # 使用tqdm显示进度条
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

    # 4. 从有效URL提取节目源
    logging.info("--- 提取节目源 ---")
    all_extracted_stream_urls = set()
    updated_processing_state = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # 使用tqdm显示进度条
        future_to_url = {executor.submit(process_single_source_url, url, processing_state): url for url in tqdm(valid_source_urls, desc="提取节目源") if url}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                extracted_streams, updated_url_key = future.result()
                all_extracted_stream_urls.update(extracted_streams)
                updated_processing_state[updated_url_key] = processing_state.get(updated_url_key, {}) # 确保获取到最新的状态
            except Exception as exc:
                logging.error(f"提取节目源 {url} 时发生异常: {exc}")
                # 即使发生异常，也要尝试更新其状态以避免反复尝试
                updated_processing_state[url] = processing_state.get(url, {})

    # 保留未处理URL（即不在 valid_source_urls 里的）的旧状态，确保状态文件完整性
    for url, state_info in processing_state.items():
        if url not in updated_processing_state and url in all_source_urls_set:
            updated_processing_state[url] = state_info

    logging.info(f"提取到 {len(all_extracted_stream_urls)} 个去重后的节目源。")
    save_json_state(PROCESSING_STATE_FILE, updated_processing_state)
    write_file_lines(FINAL_IPTV_SOURCES_FILE, list(all_extracted_stream_urls))

    # 5. 测试节目源可播放性
    logging.info("--- 测试节目源可播放性 ---")
    stream_urls = read_file_lines(FINAL_IPTV_SOURCES_FILE)
    if not stream_urls:
        logging.warning("没有可供测试的节目源，跳过测试步骤。")
        logging.info("--- 脚本运行完成 ---")
        return

    valid_stream_urls = []
    clear_log_file(INVALID_IPTV_SOURCES_LOG)  # 清空旧日志
    
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # 使用tqdm显示进度条
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
    # 这里将使用修改后的分块写入函数来写入 valid_iptv_sources.txt
    write_file_lines(VALID_IPTV_SOURCES_FILE, valid_stream_urls) 

    logging.info("--- 脚本运行完成 ---")

if __name__ == "__main__":
    main()
