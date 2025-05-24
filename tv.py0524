import os
import re
import subprocess
import socket
import time
from datetime import datetime
import logging
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- 全局配置 ---
LAST_MODIFIED_FILE = "last_modified_urls.txt"
DEFAULT_LAST_MODIFIED = "Thu, 01 Jan 1970 00:00:00 GMT" # Unix Epoch，用于初始比较

# --- GitHub API 配置 ---
GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"
# 从环境变量获取 GitHub Token
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN') # 此变量将保存从 GitHub Actions 传递的 token

# 优化和扩展的搜索关键词
SEARCH_KEYWORDS = [
    "extension:m3u8 in:file",
    "extension:m3u in:file",
    "iptv playlist extension:m3u,m3u8 in:file",
    "raw.githubusercontent.com path:.m3u8",
    "raw.githubusercontent.com path:.m3u",
    "tv channels extension:m3u,m3u8 in:file",
    "live tv extension:m3u,m3u8 in:file",
    "playlist.m3u8 in:file",
    "index.m3u8 in:file",
    "channels.m3u in:file",
    "iptv links extension:m3u,m3u8 in:file",
    # --- 新增关键词，以扩大搜索范围 ---
    "\"#EXTM3U\" filename:playlist",
    "\"#EXTM3U\" filename:channels",
    "\"#EXTINF\" in:file language:m3u",
    "filename:m3u8 path:public",
    "filename:m3u path:public",
    "extension:txt iptv list",
    "raw.githubusercontent.com m3u",
    "raw.githubusercontent.com m3u8",
    "site:github.com intitle:m3u8 live",
    "site:github.com intitle:m3u live",
    "site:github.com inurl:m3u8 iptv",
    "site:github.com inurl:m3u iptv",
    "\"IPTV\" m3u country:cn", # 搜索中国地区的IPTV列表
    "\"直播源\" filetype:m3u", # 搜索直播源文件
    "\"EPG\" m3u", # 结合 EPG 查找
    "\"电视直播\" filetype:m3u,m3u8",
    "\"playlist.m3u\" in:path", # 更具体的路径搜索
    # --- 新增关键词结束 ---
]
# 每页最大结果数（GitHub API 限制）
PER_PAGE = 100
# 限制总搜索页数，以防止过度请求
MAX_SEARCH_PAGES = 5

# --- 辅助函数 ---

def read_txt_to_array(file_name):
    """从 TXT 文件读取内容，每行一个元素。"""
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            lines = file.readlines()
            lines = [line.strip() for line in lines if line.strip()]
            return lines
    except FileNotFoundError:
        logging.warning(f"文件 '{file_name}' 未找到。将创建一个新文件。")
        return []
    except Exception as e:
        logging.error(f"读取文件 '{file_name}' 时出错: {e}")
        return []

def write_array_to_txt(file_name, data_array):
    """将数组内容写入 TXT 文件，每行一个元素。"""
    try:
        with open(file_name, 'w', encoding='utf-8') as file:
            for item in data_array:
                file.write(item + '\n')
        logging.info(f"数据已成功写入 '{file_name}'。")
    except Exception as e:
        logging.error(f"写入文件 '{file_name}' 时出错: {e}")

def append_to_txt(file_name, data_array):
    """将数组内容追加到 TXT 文件，每行一个元素，避免重复。"""
    existing_content = set(read_txt_to_array(file_name))
    new_content_to_add = []
    for item in data_array:
        if item not in existing_content:
            new_content_to_add.append(item)
            existing_content.add(item) # 更新已存在内容，避免本次操作中重复添加

    if new_content_to_add:
        try:
            with open(file_name, 'a', encoding='utf-8') as file:
                for item in new_content_to_add:
                    file.write(item + '\n')
            logging.info(f"新数据已成功追加到 '{file_name}'。追加了 {len(new_content_to_add)} 条记录。")
        except Exception as e:
            logging.error(f"追加写入文件 '{file_name}' 时出错: {e}")
    else:
        logging.info(f"没有新数据需要追加到 '{file_name}'。")


def get_url_file_extension(url):
    """获取 URL 的文件扩展名。"""
    parsed_url = urlparse(url)
    extension = os.path.splitext(parsed_url.path)[1].lower()
    return extension

def convert_m3u_to_txt(m3u_content):
    """将 m3u/m3u8 内容转换为频道名称和地址的 TXT 格式。"""
    lines = m3u_content.split('\n')
    txt_lines = []
    channel_name = ""
    for line in lines:
        line = line.strip()
        if line.startswith("#EXTM3U"):
            continue
        if line.startswith("#EXTINF"):
            match = re.search(r'#EXTINF:.*?\,(.*)', line)
            if match:
                channel_name = match.group(1).strip()
            else:
                channel_name = "Unknown Channel"
        elif line and not line.startswith('#'):
            if channel_name:
                txt_lines.append(f"{channel_name},{line}")
            channel_name = ""
    return '\n'.join(txt_lines)

def clean_url_params(url):
    """清理 URL 的查询参数和片段标识符，只保留基础 URL。"""
    parsed_url = urlparse(url)
    return parsed_url.scheme + "://" + parsed_url.netloc + parsed_url.path

@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True, retry=retry_if_exception_type(requests.exceptions.RequestException))
def fetch_url_content_with_retry(url, timeout=15):
    """使用 requests 库抓取 URL 内容，带重试机制。"""
    logging.info(f"尝试抓取 URL: {url} (超时: {timeout}s)")
    response = requests.get(url, timeout=timeout)
    response.raise_for_status()
    return response.text, response.headers.get('Last-Modified')

@retry(stop=stop_after_attempt(3), wait=wait_fixed(5), reraise=True, retry=retry_if_exception_type(requests.exceptions.RequestException))
def fetch_url_headers_with_retry(url, timeout=10):
    """使用 requests 库抓取 URL 的头部信息，带重试机制。"""
    logging.debug(f"尝试获取 URL 头部信息: {url} (超时: {timeout}s)")
    response = requests.head(url, timeout=timeout, allow_redirects=True)
    response.raise_for_status()
    return response.headers.get('Last-Modified')


def process_url(url, last_modified_cache):
    """
    处理单个 URL，提取频道名称和地址。
    如果 URL 未更新，则跳过内容抓取。
    """
    cleaned_url = clean_url_params(url)
    cached_last_modified = last_modified_cache.get(cleaned_url, DEFAULT_LAST_MODIFIED)

    try:
        current_last_modified = fetch_url_headers_with_retry(cleaned_url)
        if current_last_modified == cached_last_modified and current_last_modified != DEFAULT_LAST_MODIFIED:
            logging.info(f"URL '{cleaned_url}' 未更新。跳过处理。")
            return [] # 返回空列表，表示没有新频道
    except requests.exceptions.RequestException as e:
        logging.warning(f"无法获取 URL '{cleaned_url}' 的 Last-Modified 头，将尝试重新抓取内容: {e}")
        current_last_modified = None # 无法获取头部，尝试抓取内容
    except Exception as e:
        logging.warning(f"获取 URL '{cleaned_url}' 头部时发生未知错误，将尝试重新抓取内容: {e}")
        current_last_modified = None

    try:
        text, fetched_last_modified = fetch_url_content_with_retry(cleaned_url)
        
        # 更新缓存中的 Last-Modified
        if fetched_last_modified:
            last_modified_cache[cleaned_url] = fetched_last_modified
        elif current_last_modified: # 如果内容抓取没有返回 Last-Modified，但之前头部抓取成功了
            last_modified_cache[cleaned_url] = current_last_modified
        else: # 如果都没有，则设置为当前时间（作为一种标记）
            last_modified_cache[cleaned_url] = datetime.now().strftime("%a, %d %b %Y %H:%M:%S GMT")


        if get_url_file_extension(cleaned_url) in [".m3u", ".m3u8"]:
            text = convert_m3u_to_txt(text)

        lines = text.split('\n')
        channel_list = []
        channel_count = 0
        for line in lines:
            line = line.strip()
            if "#genre#" not in line and "," in line and "://" in line:
                parts = line.split(',', 1)
                channel_name = parts[0].strip()
                channel_address_raw = parts[1].strip()

                if '#' in channel_address_raw:
                    url_list = channel_address_raw.split('#')
                    for channel_url in url_list:
                        channel_url = clean_url_params(channel_url.strip())
                        if channel_url:
                            channel_list.append((channel_name, channel_url))
                            channel_count += 1
                else:
                    channel_url = clean_url_params(channel_address_raw)
                    if channel_url:
                        channel_list.append((channel_name, channel_url))
                        channel_count += 1
        logging.info(f"成功读取 URL: {cleaned_url}，获取到 {channel_count} 个频道。")
        return channel_list
    except requests.exceptions.RequestException as e:
        logging.error(f"处理 URL 时请求出错（重试后失败）: {cleaned_url} - {e}")
        return []
    except Exception as e:
        logging.error(f"处理 URL 时发生未知错误: {cleaned_url} - {e}")
        return []

def filter_and_modify_sources(corrections):
    """过滤和修改频道名称和 URL。"""
    filtered_corrections = []
    # 过滤列表
    name_dict = ['购物', '理财', '导视', '指南', '测试', '芒果', 'CGTN','(480p)','(360p)','(240p)','(406p)',' (540p)','(600p)','(576p)','[Not 24/7]','DJ','音乐','演唱会','舞曲','春晚','格斗','粤','祝','体育','广播','博斯','神话','测试频道']
    url_dict = ['.m3u8?auth_key=', 'token='] # 示例：过滤包含特定参数的 URL

    for name, url in corrections:
        if any(word.lower() in name.lower() for word in name_dict) or \
           any(word in url for word in url_dict):
            logging.info(f"过滤频道: {name},{url}")
        else:
            name = name.replace("FHD", "").replace("HD", "").replace("hd", "").replace("频道", "").replace("高清", "") \
                .replace("超清", "").replace("20M", "").replace("-", "").replace("4k", "").replace("4K", "") \
                .replace("4kR", "").strip() # 添加 strip() 清理末尾空格
            filtered_corrections.append((name, url))
    return filtered_corrections

def clear_txt_files(directory):
    """删除指定目录下所有 TXT 文件。"""
    for filename in os.listdir(directory):
        if filename.endswith('.txt'):
            file_path = os.path.join(directory, filename)
            try:
                os.remove(file_path)
                logging.info(f"已删除文件: {file_path}")
            except Exception as e:
                logging.error(f"删除文件 {file_path} 时出错: {e}")

def check_http_url(url, timeout):
    """检查 HTTP/HTTPS URL 是否活跃。"""
    try:
        # 使用 stream=True 和 iter_content 来避免下载整个文件，提高效率
        with requests.get(url, timeout=timeout, stream=True, allow_redirects=True) as response:
            return 200 <= response.status_code < 400
    except requests.exceptions.RequestException as e:
        logging.debug(f"HTTP URL {url} 检查失败: {e}")
        return False

def check_rtmp_url(url, timeout):
    """使用 ffprobe 检查 RTMP 流是否可用。"""
    try:
        # 检查 ffprobe 是否存在
        subprocess.run(['ffprobe', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2)
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        logging.warning("未找到 ffprobe 或其工作不正常。RTMP 流无法检查。")
        return False
    try:
        # 尝试连接 RTMP 流并获取少量数据
        result = subprocess.run(['ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, timeout=timeout)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        logging.debug(f"RTMP URL {url} 检查超时")
        return False
    except Exception as e:
        logging.debug(f"RTMP URL {url} 检查出错: {e}")
        return False

def check_rtp_url(url, timeout):
    """检查 RTP URL 是否活跃 (UDP 协议)。"""
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port
        if not host or not port:
            logging.debug(f"RTP URL {url} 无效的主机或端口。")
            return False

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            s.sendto(b'', (host, port)) # 发送一个空包，尝试触发响应
            s.recv(1) # 尝试接收数据
        return True
    except (socket.timeout, socket.error) as e:
        logging.debug(f"RTP URL {url} 检查失败: {e}")
        return False
    except Exception as e:
        logging.debug(f"RTP URL {url} 检查出错: {e}")
        return False

def check_p3p_url(url, timeout):
    """检查 P3P URL 是否活跃 (模拟 HTTP 请求)。"""
    try:
        parsed_url = urlparse(url)
        host = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else 80
        path = parsed_url.path if parsed_url.path else '/'

        if not host:
            logging.debug(f"P3P URL {url} 无效的主机。")
            return False

        with socket.create_connection((host, port), timeout=timeout) as s:
            request = f"GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: Python\r\n\r\n"
            s.sendall(request.encode())
            response = s.recv(1024).decode('utf-8', errors='ignore')
            return "P3P" in response or response.startswith("HTTP/1.")
    except Exception as e:
        logging.debug(f"P3P URL {url} 检查失败: {e}")
        return False

def check_url_validity(url, channel_name, timeout=6):
    """根据协议检查 URL 的有效性。"""
    start_time = time.time()
    success = False

    try:
        if url.startswith("http"):
            success = check_http_url(url, timeout)
        elif url.startswith("p3p"):
            success = check_p3p_url(url, timeout)
        elif url.startswith("rtmp"):
            success = check_rtmp_url(url, timeout)
        elif url.startswith("rtp"):
            success = check_rtp_url(url, timeout)
        else:
            logging.debug(f"不支持的协议: {channel_name}: {url}")
            return None, False

        elapsed_time = (time.time() - start_time) * 1000
        if success:
            return elapsed_time, True
        else:
            return None, False
    except Exception as e:
        logging.debug(f"检查频道 {channel_name} ({url}) 时出错: {e}")
        return None, False

def process_line(line):
    """处理单行频道信息并检查有效性。"""
    if "://" not in line:
        return None, None
    parts = line.split(',', 1)
    if len(parts) == 2:
        name, url = parts
        url = url.strip()
        elapsed_time, is_valid = check_url_validity(url, name)
        if is_valid:
            return elapsed_time, f"{name},{url}"
    return None, None

def process_urls_multithreaded(lines, max_workers=200):
    """并发处理 URL 列表以检查有效性。"""
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(process_line, line): line for line in lines}
        for future in as_completed(futures):
            try:
                elapsed_time, result_line = future.result()
                if elapsed_time is not None and result_line is not None:
                    results.append((elapsed_time, result_line))
            except Exception as exc:
                logging.warning(f"处理行时发生异常: {exc}")

    results.sort() # 按响应时间排序
    return results

def write_list(file_path, data_list):
    """将数据列表写入文件。"""
    with open(file_path, 'w', encoding='utf-8') as file:
        for item in data_list:
            file.write(item[1] + '\n')

def sort_cctv_channels(channels):
    """按数字顺序排序 CCTV 频道。"""
    def channel_key(channel_line):
        channel_name_full = channel_line.split(',')[0].strip()
        match = re.search(r'\d+', channel_name_full)
        if match:
            return int(match.group())
        return float('inf') # 没有数字的排在最后

    return sorted(channels, key=channel_key)

def merge_iptv_files(local_channels_directory):
    """将所有本地频道文件合并到 iptv_list.txt。"""
    final_output_lines = []
    
    now = datetime.now()
    update_time_line = [
        f"更新时间,#genre#\n",
        f"{now.strftime('%Y-%m-%d')},url\n",
        f"{now.strftime('%H:%M:%S')},url\n"
    ]
    final_output_lines.extend(update_time_line)

    ordered_categories = ["央视频道", "卫视频道", "湖南频道", "港台频道"]
    
    all_iptv_files_in_dir = [f for f in os.listdir(local_channels_directory) if f.endswith('_iptv.txt')]
    
    files_to_merge_paths = []
    processed_files = set()

    # 优先处理指定顺序的分类
    for category in ordered_categories:
        file_name = f"{category}_iptv.txt"
        if file_name in all_iptv_files_in_dir and file_name not in processed_files:
            files_to_merge_paths.append(os.path.join(local_channels_directory, file_name))
            processed_files.add(file_name)
    
    # 添加剩余的、未处理的文件（按名称排序）
    for file_name in sorted(all_iptv_files_in_dir):
        if file_name not in processed_files:
            files_to_merge_paths.append(os.path.join(local_channels_directory, file_name))
            processed_files.add(file_name)

    # 汇总并合并文件
    for file_path in files_to_merge_paths:
        with open(file_path, "r", encoding="utf-8") as file:
            lines = file.readlines()
            if not lines:
                continue

            header = lines[0].strip()
            if '#genre#' in header:
                final_output_lines.append(header + '\n') # 添加分类头
                
                grouped_channels_in_category = {}
                for line_content in lines[1:]:
                    line_content = line_content.strip()
                    if line_content and "," in line_content and "://" in line_content: # 确保是有效的频道行
                        channel_name = line_content.split(',', 1)[0].strip()
                        if channel_name not in grouped_channels_in_category:
                            grouped_channels_in_category[channel_name] = []
                        grouped_channels_in_category[channel_name].append(line_content)
                
                for channel_name in grouped_channels_in_category:
                    # 限制每个频道最多 200 个 URL，以防止文件过大
                    for ch_line in grouped_channels_in_category[channel_name][:200]:
                        final_output_lines.append(ch_line + '\n')
            else:
                logging.warning(f"文件 {file_path} 没有以类别标题开头。跳过。")

    iptv_list_file_path = "iptv_list.txt"
    with open(iptv_list_file_path, "w", encoding="utf-8") as iptv_list_file:
        iptv_list_file.writelines(final_output_lines)

    try:
        # 删除临时文件
        if os.path.exists('iptv.txt'):
            os.remove('iptv.txt')
            logging.info(f"临时文件 iptv.txt 已删除。")
        if os.path.exists('iptv_speed.txt'):
            os.remove('iptv_speed.txt')
            logging.info(f"临时文件 iptv_speed.txt 已删除。")
    except OSError as e:
        logging.warning(f"删除临时文件时出错: {e}")

    logging.info(f"\n所有地方频道列表文件已合并。输出保存到: {iptv_list_file_path}")


def auto_discover_github_urls(urls_file_path, github_token):
    """
    自动从 GitHub 搜索公共 IPTV 源 URL 并更新 urls.txt 文件。
    """
    if not github_token:
        logging.warning("未设置 GITHUB_TOKEN 环境变量。跳过 GitHub URL 自动发现。")
        return

    existing_urls = set(read_txt_to_array(urls_file_path))
    found_urls = set()
    headers = {
        "Accept": "application/vnd.github.v3.text-match+json",
        "Authorization": f"token {github_token}"
    }

    logging.info("开始从 GitHub 自动发现新的 IPTV 源 URL...")

    for i, keyword in enumerate(SEARCH_KEYWORDS):
        if i > 0: # 处理后续关键词前等待
            logging.info(f"切换到下一个关键词: '{keyword}'。等待 10 秒以避免速率限制...")
            time.sleep(10) # 增加关键词之间的等待时间

        page = 1
        while page <= MAX_SEARCH_PAGES:
            params = {
                "q": keyword,
                "sort": "indexed", # 按索引时间排序（最新更新）
                "order": "desc",
                "per_page": PER_PAGE,
                "page": page
            }
            try:
                response = requests.get(
                    f"{GITHUB_API_BASE_URL}{SEARCH_CODE_ENDPOINT}",
                    headers=headers,
                    params=params,
                    timeout=20
                )
                response.raise_for_status() # 对 4xx 或 5xx 响应引发 HTTPError
                data = response.json()

                # 检查 GitHub API 速率限制头部信息
                rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
                rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0))
                
                if rate_limit_remaining == 0:
                    wait_seconds = max(0, rate_limit_reset - time.time()) + 5 # 多等待 5 秒
                    logging.warning(f"GitHub API 速率限制已达到！剩余请求: 0。等待 {wait_seconds:.0f} 秒后重试。")
                    time.sleep(wait_seconds)
                    continue # 等待后重试当前页面

                if not data.get('items'):
                    logging.info(f"关键词 '{keyword}' 在第 {page} 页没有找到更多结果。")
                    break

                for item in data['items']:
                    html_url = item.get('html_url', '')
                    raw_url = None
                    
                    # 尝试从 html_url 构建 raw.githubusercontent.com URL
                    match = re.search(r'https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)', html_url)
                    
                    if match:
                        user = match.group(1)
                        repo = match.group(2)
                        branch = match.group(3)
                        path = match.group(4)
                        raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{path}"
                    
                    if raw_url:
                        # 确保 URL 是有效的 m3u/m3u8/txt URL (可以来自任何域名，不再局限于 raw.githubusercontent.com)
                        # 但为了确保是文件内容而非网页，通常还是偏向 raw.githubusercontent.com 或直接的文件链接
                        if raw_url.lower().endswith(('.m3u', '.m3u8', '.txt')):
                            cleaned_url = clean_url_params(raw_url)
                            found_urls.add(cleaned_url)
                            logging.debug(f"发现 GitHub 相关 URL: {cleaned_url}")
                        else:
                            logging.debug(f"跳过非 M3U/M3U8/TXT 链接: {raw_url}")
                    else:
                        logging.debug(f"无法从 HTML URL 构建原始 URL: {html_url}")

                logging.info(f"关键词 '{keyword}'，第 {page} 页搜索完成。当前找到 {len(found_urls)} 个 URL。")
                
                # 通过比较项目数量判断是否还有更多页面
                if len(data['items']) < PER_PAGE:
                    break # 已达到最后一页或没有更多结果

                page += 1
                time.sleep(2) # 同一关键词内，不同页面之间等待 2 秒

            except requests.exceptions.RequestException as e:
                logging.error(f"GitHub API 请求失败 (关键词: {keyword}, 页码: {page}): {e}")
                # 如果是 403 Forbidden 错误，专门处理速率限制
                if response.status_code == 403:
                    rate_limit_reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                    wait_seconds = max(0, rate_limit_reset_time - time.time()) + 5 # 多等待 5 秒
                    logging.warning(f"GitHub API 速率限制已达到！等待 {wait_seconds:.0f} 秒后重试。")
                    time.sleep(wait_seconds)
                    continue # 等待后重试当前页面
                else:
                    break # 其他错误则中断当前关键词的搜索
            except Exception as e:
                logging.error(f"GitHub URL 自动发现过程中发生未知错误: {e}")
                break # 发生未知错误则中断

    new_urls_count = 0
    urls_to_add_to_file = []
    for url in found_urls:
        if url not in existing_urls:
            urls_to_add_to_file.append(url)
            new_urls_count += 1

    if new_urls_count > 0:
        append_to_txt(urls_file_path, urls_to_add_to_file)
        logging.info(f"成功发现并添加了 {new_urls_count} 个新的 GitHub IPTV 源 URL 到 {urls_file_path}。总 URL 数量: {len(read_txt_to_array(urls_file_path))}")
    else:
        logging.info("没有发现新的 GitHub IPTV 源 URL。")

    logging.info("GitHub URL 自动发现完成。")

def load_last_modified_cache(file_path):
    """从文件中加载 Last-Modified 缓存。"""
    cache = {}
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split(',', 1)
                if len(parts) == 2:
                    url, timestamp = parts
                    cache[url] = timestamp
    except FileNotFoundError:
        logging.info(f"未找到 '{file_path}'，将创建新的缓存文件。")
    except Exception as e:
        logging.error(f"加载 '{file_path}' 缓存时出错: {e}")
    return cache

def save_last_modified_cache(file_path, cache):
    """将 Last-Modified 缓存保存到文件。"""
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            for url, timestamp in cache.items():
                f.write(f"{url},{timestamp}\n")
        logging.info(f"Last-Modified 缓存已保存到 '{file_path}'。")
    except Exception as e:
        logging.error(f"保存 '{file_path}' 缓存时出错: {e}")


def main():
    config_dir = os.path.join(os.getcwd(), 'config')
    os.makedirs(config_dir, exist_ok=True)
    urls_file_path = os.path.join(config_dir, 'urls.txt')
    last_modified_cache_path = os.path.join(config_dir, LAST_MODIFIED_FILE)

    # --- 调试日志 ---
    if os.getenv('GITHUB_TOKEN'):
        logging.info("环境变量 'GITHUB_TOKEN' 已设置。")
    else:
        logging.error("环境变量 'GITHUB_TOKEN' 未设置！请检查 GitHub Actions 工作流配置。")
    # --- 调试日志结束 ---

    # 1. 自动发现 GitHub URL 并更新 urls.txt
    auto_discover_github_urls(urls_file_path, GITHUB_TOKEN)

    # 2. 读取要处理的 URL (包括新发现的)
    urls_to_process = read_txt_to_array(urls_file_path)
    if not urls_to_process:
        logging.warning(f"在 {urls_file_path} 中未找到 URL，脚本将提前退出。")
        return

    # 3. 加载 Last-Modified 缓存
    last_modified_cache = load_last_modified_cache(last_modified_cache_path)
    
    # 4. 处理 config/urls.txt 中的所有频道列表
    all_channels = []
    updated_urls_in_this_run = set() # 记录本次运行中实际更新内容的 URL
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        # 为每个 URL 提交一个任务，并传递 Last-Modified 缓存
        future_to_url = {executor.submit(process_url, url, last_modified_cache): url for url in urls_to_process}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                channels_from_url = future.result()
                if channels_from_url: # 如果有新的频道数据，表示该 URL 内容有更新
                    all_channels.extend(channels_from_url)
                    updated_urls_in_this_run.add(clean_url_params(url))
            except Exception as exc:
                logging.error(f"处理源 {url} 时发生异常: {exc}")

    # 仅保留本次运行中实际被处理的 URL 的 Last-Modified 记录
    new_last_modified_cache = {
        url: last_modified_cache[url] for url in updated_urls_in_this_run if url in last_modified_cache
    }
    # 添加原有缓存中未被处理但仍有效的URL
    for url, timestamp in last_modified_cache.items():
        if url not in updated_urls_in_this_run and url in urls_to_process: # 确保URL还在urls.txt里
            new_last_modified_cache[url] = timestamp

    save_last_modified_cache(last_modified_cache_path, new_last_modified_cache) # 保存更新后的缓存

    # 5. 过滤并清理频道名称
    filtered_channels = filter_and_modify_sources(all_channels)
    unique_channels = list(set(filtered_channels)) # 去重
    unique_channels_str = [f"{name},{url}" for name, url in unique_channels]

    iptv_file_path = os.path.join(os.getcwd(), 'iptv.txt')
    # 使用 'w' 模式，因为这是所有渠道的汇总，每次都重新生成
    write_array_to_txt(iptv_file_path, unique_channels_str)
    logging.info(f"\n所有频道已保存到: {iptv_file_path}，共收集到 {len(unique_channels_str)} 个频道。\n")

    # 6. 多线程频道有效性和速度检查
    logging.info("开始多线程频道有效性和速度检查...")
    results = process_urls_multithreaded(unique_channels_str)
    logging.info(f"有效且响应的频道数量: {len(results)}")

    iptv_speed_file_path = os.path.join(os.getcwd(), 'iptv_speed.txt')
    write_list(iptv_speed_file_path, results)
    for elapsed_time, result in results:
        channel_name, channel_url = result.split(',', 1)
        logging.info(f"频道 {channel_name},{channel_url} 检查成功。响应时间: {elapsed_time:.0f} ms")

    # 7. 处理地方频道和频道模板
    local_channels_directory = os.path.join(os.getcwd(), '地方频道')
    os.makedirs(local_channels_directory, exist_ok=True)
    clear_txt_files(local_channels_directory) # 清除旧的频道文件

    template_directory = os.path.join(os.getcwd(), '频道模板')
    os.makedirs(template_directory, exist_ok=True)
    template_files = [f for f in os.listdir(template_directory) if f.endswith('.txt')]

    iptv_speed_channels = read_txt_to_array(iptv_speed_file_path)

    all_template_channel_names = set()
    for template_file in template_files:
        names_from_current_template = read_txt_to_array(os.path.join(template_directory, template_file))
        all_template_channel_names.update(names_from_current_template)

    for template_file in template_files:
        template_channels_names = read_txt_to_array(os.path.join(template_directory, template_file))
        template_name = os.path.splitext(template_file)[0]

        current_template_matched_channels = []
        for channel_line in iptv_speed_channels:
            channel_name = channel_line.split(',', 1)[0].strip()
            if channel_name in template_channels_names:
                current_template_matched_channels.append(channel_line)

        if "央视" in template_name or "CCTV" in template_name:
            current_template_matched_channels = sort_cctv_channels(current_template_matched_channels)
            logging.info(f"已对 {template_name} 频道进行数字排序。")

        output_file_path = os.path.join(local_channels_directory, f"{template_name}_iptv.txt")
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(f"{template_name},#genre#\n")
            for channel in current_template_matched_channels:
                f.write(channel + '\n')
        logging.info(f"频道列表已写入: {template_name}_iptv.txt，包含 {len(current_template_matched_channels)} 个频道。")

    # 8. 合并所有 IPTV 文件
    merge_iptv_files(local_channels_directory)

    # 9. 查找未匹配的频道
    unmatched_channels = []
    for channel_line in iptv_speed_channels:
        channel_name = channel_line.split(',', 1)[0].strip()
        if channel_name not in all_template_channel_names:
            unmatched_channels.append(channel_line)

    unmatched_output_file_path = os.path.join(os.getcwd(), 'unmatched_channels.txt')
    # 未匹配频道文件也使用追加模式，如果存在则添加新的未匹配项
    unmatched_channel_names_only = [line.split(',')[0].strip() for line in unmatched_channels]
    append_to_txt(unmatched_output_file_path, unmatched_channel_names_only)
    logging.info(f"\n未匹配但已检测到的频道列表已保存到: {unmatched_output_file_path}，共 {len(unmatched_channels)} 个频道。")


if __name__ == "__main__":
    main()
