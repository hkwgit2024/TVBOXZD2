import requests
import json
import os
import hashlib
import logging
import re
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import time

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- 配置项 ---
# URL 列表文件的路径 (包含要处理的远程 M3U/M3U8 源文件的 URL)
REMOTE_URLS_FILE = "output/urls.txt"
# 处理状态文件，用于记录每个源 URL 的最新处理时间和内容哈希
URL_PROCESSING_STATE_FILE = "url_processing_state.json"
# 最大并发线程数
MAX_WORKERS = 50 # 建议根据网络和服务器负载调整，过高可能导致被封或超时
# 单个节目源文件最大允许下载大小 (10MB)
MAX_SOURCE_FILE_SIZE_BYTES = 10 * 1024 * 1024
# 检查节目源有效性的超时时间 (秒)
STREAM_CHECK_TIMEOUT = 10
# 强制重新检查源 URL 的天数 (即使内容未变)
FORCE_RECHECK_DAYS = 7
# 过滤掉提取节目源数量低于此阈值的源
MIN_EXTRACTED_STREAMS_PER_SOURCE = 1

# --- 辅助函数 ---

def get_remote_urls(file_path):
    """从文件中读取远程 URL 列表。"""
    if not os.path.exists(file_path):
        return []
    with open(file_path, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.startswith('#')]
    return urls

def load_processing_state(file_path):
    """加载之前保存的 URL 处理状态。"""
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            logging.warning(f"无法解析 {file_path}，将创建一个新的状态文件。")
    return {}

def get_url_content_hash(url):
    """获取 URL 内容的 MD5 哈希值，用于检测内容是否变化。"""
    try:
        response = requests.head(url, timeout=5, allow_redirects=True)
        response.raise_for_status()
        # 尝试获取 ETag 或 Last-Modified 作为哈希的替代
        etag = response.headers.get('ETag')
        last_modified = response.headers.get('Last-Modified')
        if etag:
            return etag
        elif last_modified:
            return hashlib.md5(last_modified.encode('utf-8')).hexdigest()
        else:
            # 如果没有 ETag 或 Last-Modified，进行小部分内容下载哈希
            # 注意：这可能会稍微增加请求时间
            response = requests.get(url, stream=True, timeout=5)
            response.raise_for_status()
            first_chunk = next(response.iter_content(chunk_size=1024), b'')
            return hashlib.md5(first_chunk).hexdigest()
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
        logging.debug(f"获取 {url} 的内容哈希失败: {e}")
    except Exception as e:
        logging.error(f"获取 {url} 的内容哈希时发生未知错误: {e}")
    return None

# --- 修改：extract_stream_urls_from_content 函数 ---
def extract_stream_urls_from_content(content):
    """
    从 M3U/M3U8 内容中提取节目源 URL、频道名称和分组。
    返回一个 (url, channel_name, group) 元组的列表。
    """
    extracted_streams = []
    lines = content.splitlines()
    
    current_channel_name = "未知频道"
    current_group = "其他"

    # 正则表达式来匹配 EXTINF 标签和属性
    extinf_pattern = re.compile(r'#EXTINF:.*?(?:tvg-name="([^"]*)")?.*?(?:group-title="([^"]*)")?,(.*)')

    for i in range(len(lines)):
        line = lines[i].strip()
        if line.startswith('#EXTINF:'):
            match = extinf_pattern.match(line)
            if match:
                tvg_name = match.group(1) # tvg-name 属性
                group_title = match.group(2) # group-title 属性
                display_name = match.group(3) # 逗号后的显示名称

                current_channel_name = tvg_name if tvg_name else display_name if display_name else "未知频道"
                current_group = group_title if group_title else "其他"
                
                # 清理显示名称，去除可能的额外空格或回车
                current_channel_name = current_channel_name.strip()
                current_group = current_group.strip()

            # 查找下一个非空且不是 EXTINF 的行作为 URL
            next_line_index = i + 1
            while next_line_index < len(lines):
                stream_url_line = lines[next_line_index].strip()
                if stream_url_line and not stream_url_line.startswith('#'):
                    # 确保是有效的 URL 格式，以 http 或 https 开头
                    if stream_url_line.startswith('http://') or stream_url_line.startswith('https://'):
                        extracted_streams.append((stream_url_line, current_channel_name, current_group))
                    else:
                        logging.debug(f"跳过非HTTP(S)格式的URL: {stream_url_line}")
                    break # 找到 URL 后跳出内层循环
                next_line_index += 1
    
    return extracted_streams

# --- 修改：process_single_source_url 函数 ---
def process_single_source_url(source_url, processing_state):
    """
    处理单个节目源 URL，提取其中的节目源信息。
    返回一个 (url, name, group) 元组的列表。
    """
    extracted_streams_with_info = [] # 存储 (url, name, group) 元组
    current_time_str = datetime.now().isoformat()
    last_processed_info = processing_state.get(source_url, {})
    
    force_reprocess_by_time = False
    if "last_processed" in last_processed_info:
        last_processed_dt = datetime.fromisoformat(last_processed_info["last_processed"])
        if datetime.now() - last_processed_dt > timedelta(days=FORCE_RECHECK_DAYS):
            force_reprocess_by_time = True
            logging.info(f"源URL {source_url} 超过 {FORCE_RECHECK_DAYS} 天未更新，强制重新处理")

    current_content_hash = get_url_content_hash(source_url) 
    
    if current_content_hash and \
       current_content_hash == last_processed_info.get("content_hash") and \
       not force_reprocess_by_time:
        logging.debug(f"源URL {source_url} 内容未变化，跳过提取。")
        processing_state[source_url] = {
            "last_processed": current_time_str,
            "content_hash": current_content_hash
        }
        return extracted_streams_with_info, source_url # 返回空列表，因为没有新提取
    
    # 提取节目源
    try:
        logging.info(f"正在提取 {source_url} 中的节目源...")
        content_bytes = b""
        total_downloaded = 0

        # 在实际下载前，尝试通过HEAD请求检查Content-Length
        try:
            head_response = requests.head(source_url, timeout=5, allow_redirects=True)
            head_response.raise_for_status()
            content_length_header = head_response.headers.get('Content-Length')
            if content_length_header:
                estimated_size = int(content_length_header)
                if estimated_size > MAX_SOURCE_FILE_SIZE_BYTES:
                    logging.warning(f"源文件 {source_url} (估计大小: {estimated_size / (1024 * 1024):.2f}MB) 超过最大允许大小 {MAX_SOURCE_FILE_SIZE_BYTES / (1024 * 1024):.1f}MB，直接跳过。")
                    raise ValueError("文件过大，已中止下载（预检）")
        except (requests.exceptions.Timeout, requests.exceptions.HTTPError, requests.exceptions.RequestException, ValueError) as e:
            logging.warning(f"预检源文件 {source_url} 失败或过大: {e}")
            if isinstance(e, ValueError) and "文件过大" in str(e):
                processing_state[source_url] = { 
                    "last_processed": current_time_str,
                    "content_hash": last_processed_info.get("content_hash")
                }
                return extracted_streams_with_info, source_url

        # 使用 stream=True 和 iter_content 来处理大文件和超时
        with requests.get(source_url, stream=True, timeout=15) as response:
            response.raise_for_status() # 检查HTTP错误

            for chunk in response.iter_content(chunk_size=8192): # 每次读取8KB
                if chunk:
                    content_bytes += chunk
                    total_downloaded += len(chunk)
                    if total_downloaded > MAX_SOURCE_FILE_SIZE_BYTES:
                        logging.warning(f"源文件 {source_url} 实际下载大小超过最大允许大小 {MAX_SOURCE_FILE_SIZE_BYTES / (1024 * 1024):.1f}MB，中止下载。")
                        break # 超过大小限制，停止下载

        if total_downloaded > MAX_SOURCE_FILE_SIZE_BYTES:
            raise ValueError(f"文件过大，已中止下载 (> {MAX_SOURCE_FILE_SIZE_BYTES / (1024 * 1024):.1f}MB)")

        # 尝试解码内容
        try:
            content = content_bytes.decode('utf-8')
        except UnicodeDecodeError:
            try:
                content = content_bytes.decode('latin-1')
                logging.warning(f"源文件 {source_url} 非UTF-8编码，尝试使用 Latin-1 解码。")
            except Exception:
                raise ValueError("无法解码源文件内容为文本。")

        extracted_streams_with_info = extract_stream_urls_from_content(content) # 调用更新后的函数
        
        if len(extracted_streams_with_info) < MIN_EXTRACTED_STREAMS_PER_SOURCE:
            logging.info(f"从 {source_url} 提取到 {len(extracted_streams_with_info)} 个节目源，小于阈值 {MIN_EXTRACTED_STREAMS_PER_SOURCE}，将排除此源的所有节目源。")
            extracted_streams_with_info = []
        else:
            logging.info(f"从 {source_url} 提取到 {len(extracted_streams_with_info)} 个节目源 (大小: {total_downloaded / (1024 * 1024):.2f}MB)。")

        final_content_hash = hashlib.md5(content_bytes).hexdigest() if content_bytes else None
        processing_state[source_url] = {
            "last_processed": current_time_str,
            "content_hash": final_content_hash if final_content_hash else last_processed_info.get("content_hash")
        }
        return extracted_streams_with_info, source_url
    
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
    return extracted_streams_with_info, source_url


def check_stream_validity(stream_info_tuple, balance_requests=False):
    """
    检查单个节目源 (url, channel_name, group) 的有效性。
    返回 (stream_info_tuple, is_valid)
    """
    url, channel_name, group = stream_info_tuple
    try:
        # 只检查头部，避免下载整个流
        response = requests.head(url, timeout=STREAM_CHECK_TIMEOUT, allow_redirects=True)
        response.raise_for_status() # 检查 HTTP 状态码
        # 进一步检查内容类型，确保是视频流
        content_type = response.headers.get('Content-Type', '').lower()
        if 'video' in content_type or 'audio' in content_type or 'mpegurl' in content_type or 'vnd.apple.mpegurl' in content_type:
            logging.debug(f"检查通过: {url} (类型: {content_type})")
            return stream_info_tuple, True
        else:
            logging.debug(f"检查失败 (内容类型不符): {url} (类型: {content_type})")
            return stream_info_tuple, False
    except (requests.exceptions.Timeout, requests.exceptions.ConnectionError, requests.exceptions.HTTPError) as e:
        logging.debug(f"检查失败 (请求错误): {url} - {e}")
        return stream_info_tuple, False
    except Exception as e:
        logging.error(f"检查 {url} 时发生未知错误: {e}")
        return stream_info_tuple, False
    finally:
        if balance_requests:
            time.sleep(0.1) # 短暂延迟，用于负载均衡

# --- 修改：main 函数 ---
def main():
    logging.info("IPTV 节目源处理脚本开始运行...")

    # 确保 output 目录存在
    output_dir = "output"
    os.makedirs(output_dir, exist_ok=True)

    # 从环境变量中获取远程 URL，如果没有则使用本地文件
    remote_urls_txt_base_url = os.environ.get('PRIVATE_REMOTE_URLS_TXT_BASE_URL')
    
    if remote_urls_txt_base_url:
        logging.info(f"正在从环境变量中的 URL 获取远程 URL 列表: {remote_urls_txt_base_url}")
        try:
            response = requests.get(remote_urls_txt_base_url, timeout=10)
            response.raise_for_status()
            remote_urls_content = response.text
            url_list = [line.strip() for line in remote_urls_content.splitlines() if line.strip() and not line.startswith('#')]
            logging.info(f"成功从远程 URL 获取到 {len(url_list)} 个源。")
        except Exception as e:
            logging.error(f"从远程 URL 获取 URL 列表失败: {e}。将尝试从本地文件加载。")
            url_list = get_remote_urls(REMOTE_URLS_FILE) # 降级到本地文件
    else:
        logging.info("未配置 PRIVATE_REMOTE_URLS_TXT_BASE_URL，将从本地文件加载 URL 列表。")
        url_list = get_remote_urls(REMOTE_URLS_FILE)

    if not url_list:
        logging.warning("没有找到任何节目源 URL，脚本终止。")
        return

    # 加载现有状态
    url_processing_state = load_processing_state(os.path.join(output_dir, URL_PROCESSING_STATE_FILE))

    # 使用线程池处理每个源 URL
    # results 现在包含 (extracted_streams_with_info_list, source_url)
    all_extracted_stream_info = [] # 存储所有提取到的 (url, name, group) 元组
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        for extracted_streams_list, source_url in tqdm(executor.map(lambda url: process_single_source_url(url, url_processing_state), url_list), total=len(url_list), desc="处理节目源URL"):
            all_extracted_stream_info.extend(extracted_streams_list)

    # 对提取到的节目源进行去重 (根据 URL 去重，保留第一个出现的名称和分组)
    unique_streams_map = {} # {url: (url, name, group)}
    for stream_info in all_extracted_stream_info:
        url = stream_info[0]
        if url not in unique_streams_map:
            unique_streams_map[url] = stream_info
    
    unique_extracted_stream_info = list(unique_streams_map.values())

    logging.info(f"共从所有源中提取到 {len(unique_extracted_stream_info)} 个唯一的节目源。")

    # 进行有效性检查
    valid_streams = [] # 存储 (url, name, group) 元组
    invalid_urls = set() # 仅存储无效的 URL
    
    balance_requests = True 

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # map函数返回的顺序与输入顺序一致
        check_results = list(tqdm(executor.map(lambda info: check_stream_validity(info, balance_requests), unique_extracted_stream_info), total=len(unique_extracted_stream_info), desc="检查节目源有效性"))

    for stream_info_tuple, is_valid in check_results:
        if is_valid:
            valid_streams.append(stream_info_tuple)
        else:
            invalid_urls.add(stream_info_tuple[0]) # 只记录 URL 到无效列表

    logging.info(f"有效节目源数量: {len(valid_streams)}")
    logging.info(f"无效节目源数量: {len(invalid_urls)}")

    # 保存有效节目源列表为 M3U 格式
    final_output_path = os.path.join(output_dir, "final_iptv_sources.m3u")
    with open(final_output_path, 'w', encoding='utf-8') as f:
        f.write("#EXTM3U\n") # M3U 文件头
        
        # 按照分组和频道名称排序，使得列表更整洁
        # sorted_valid_streams = sorted(valid_streams, key=lambda x: (x[2], x[1])) # 按分组和频道名排序
        # 更好的排序方式：先按分组，再按频道名，最后按URL（如果名称相同）
        sorted_valid_streams = sorted(valid_streams, key=lambda x: (x[2] if x[2] else '', x[1] if x[1] else '', x[0]))

        current_group_title = None
        for url, channel_name, group_title in sorted_valid_streams:
            # 添加分组标题行
            if group_title and group_title != current_group_title:
                f.write(f'#EXTGRP:{group_title}\n')
                current_group_title = group_title

            # 写入 EXTINF 行
            f.write(f'#EXTINF:-1 tvg-name="{channel_name}" group-title="{group_title}",{channel_name}\n')
            # 写入 URL 行
            f.write(f'{url}\n')
    logging.info(f"有效节目源已保存到: {final_output_path}")

    # 保存无效节目源列表 (只包含 URL)
    invalid_output_path = os.path.join(output_dir, "invalid_iptv_sources.log")
    with open(invalid_output_path, 'w', encoding='utf-8') as f:
        for url in sorted(list(invalid_urls)):
            f.write(f"{url}\n")
    logging.info(f"无效节目源已保存到: {invalid_output_path}")

    # 保存 URL 处理状态
    with open(os.path.join(output_dir, URL_PROCESSING_STATE_FILE), 'w', encoding='utf-8') as f:
        json.dump(url_processing_state, f, ensure_ascii=False, indent=4)
    logging.info(f"URL 处理状态已保存到: {URL_PROCESSING_STATE_FILE}")

    logging.info("IPTV 节目源处理脚本运行完成。")

if __name__ == "__main__":
    main()
