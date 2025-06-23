import requests
import re
import os
import yaml
import concurrent.futures
import time
import subprocess
import threading
from urllib.parse import urljoin
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import xml.etree.ElementTree as ET

# --- 配置变量 ---
LOCAL_IPTV_FILE = "iptv_list.txt"
CATEGORIES_FILE = "categories.yaml"
FIRST_OUTPUT = "temp1.list.txt"
SECOND_OUTPUT = "temp2.list.txt"
FINAL_OUTPUT = "tv.list.txt"
MAX_WORKERS = 4  # 低并发，适合 GitHub Actions
PRESCREEN_WORKERS = 20  # 预筛选并发
FFMPEG_PATH = "ffmpeg"
RETRY_INTERVAL = 2
LOG_FILE = "test_errors.log"
BATCH_SIZE = 1000  # 每批次处理 1000 个 URL
log_lock = threading.Lock()

# --- 日志记录 ---
def log(message: str, to_console: bool = True):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    with log_lock:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"[{timestamp}] {message}\n")
    if to_console:
        print(f"[{timestamp}] {message}")

# --- 预筛选 ---
def pre_check_url(url: str) -> bool:
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124'}
    try:
        log(f"预筛选: {url}", to_console=False)
        response = requests.head(url, timeout=2, headers=headers, allow_redirects=True)
        if 200 <= response.status_code < 400:
            return True
        response = requests.get(url, timeout=2, stream=True, headers=headers)
        return 200 <= response.status_code < 400
    except Exception as e:
        log(f"预筛选失败: {url} - {type(e).__name__}: {e}", to_console=False)
        return False

# --- FFmpeg 播放测试 ---
def check_ffmpeg_playback(url: str) -> bool:
    log(f"FFmpeg测试: {url}", to_console=False)
    null_device = "NUL" if os.name == 'nt' else "/dev/null"
    command = [
        FFMPEG_PATH, "-i", url, "-c", "copy", "-map", "0:v?", "-map", "0:a?",
        "-f", "null", "-t", "5", "-y", null_device
    ]
    try:
        process = subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=10
        )
        if process.returncode == 0:
            error_indicators = [
                "Input/output error", "Connection refused", "Protocol not found",
                "No such file or directory", "Invalid data found when processing input",
                "failed to open"
            ]
            if any(indicator in process.stderr for indicator in error_indicators):
                log(f"FFmpeg ({url}): 无效数据 - {process.stderr.strip()}", to_console=False)
                return False
            return True
        log(f"FFmpeg ({url}): 非零返回码 - {process.stderr.strip()}", to_console=False)
        return False
    except subprocess.TimeoutExpired:
        log(f"FFmpeg ({url}): 测试超时", to_console=False)
        return False
    except FileNotFoundError:
        log(f"FFmpeg 未找到: {FFMPEG_PATH}")
        return False
    except Exception as e:
        log(f"FFmpeg ({url}): 异常 - {type(e).__name__}: {e}", to_console=False)
        return False

# --- 解析 SMIL 文件 ---
def parse_smil(content: str) -> str:
    try:
        root = ET.fromstring(content)
        for video in root.findall('.//video'):
            src = video.get('src')
            if src and '.m3u8' in src:
                return src
        return None
    except:
        return None

# --- 单次连通性检查（无 FFmpeg） ---
def check_link_connectivity_no_ffmpeg(channel_data: dict) -> tuple:
    name = channel_data['name']
    url = channel_data['url']
    log(f"检查: {name} - {url}", to_console=False)
    if not url.startswith("http"):
        log(f"{name}: {url} - 无效URL格式")
        return (channel_data, False)
    
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124'}
    session = requests.Session()
    retries = Retry(total=2, backoff_factor=0.1, status_forcelist=[500, 502, 503, 504])
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))
    
    try:
        response = session.get(url, timeout=5, stream=True, headers=headers)
        if not (200 <= response.status_code < 400):
            log(f"{name}: {url} - HTTP不可达")
            return (channel_data, False)

        if '.m3u8' in url or '.smil' in url:
            m3u8_content_first = ""
            content_limit = 10 * 1024
            downloaded_size = 0
            for chunk in response.iter_content(chunk_size=1024):
                m3u8_content_first += chunk.decode('utf-8', errors='ignore')
                downloaded_size += len(chunk)
                if downloaded_size >= content_limit:
                    break
            
            if not m3u8_content_first:
                log(f"{name}: {url} - 内容为空")
                return (channel_data, False)
            
            smil_url = parse_smil(m3u8_content_first)
            if smil_url:
                log(f"{name}: {url} - 检测到SMIL，重定向到 {smil_url}")
                url = urljoin(url, smil_url)
                channel_data['url'] = url
                return check_link_connectivity_no_ffmpeg(channel_data)
            
            sub_m3u8_match = re.search(r'(https?://[^"\s]+?\.m3u8)', m3u8_content_first)
            if sub_m3u8_match:
                sub_m3u8_url = sub_m3u8_match.group(0)
                log(f"{name}: {url} - 检测到嵌套M3U8，检查 {sub_m3u8_url}")
                channel_data['url'] = sub_m3u8_url
                return check_link_connectivity_no_ffmpeg(channel_data)
            
            if "#EXT-X-ENDLIST" in m3u8_content_first or "EXT-X-PLAYLIST-TYPE:VOD" in m3u8_content_first:
                log(f"{name}: {url} - 非直播流")
                return (channel_data, False)

            target_duration_match = re.search(r'#EXT-X-TARGETDURATION:(\d+)', m3u8_content_first)
            wait_time = min(6, int(target_duration_match.group(1))) if target_duration_match else 3
            log(f"{name}: {url} - 等待 {wait_time} 秒进行M3U8动态性检查", to_console=False)
            time.sleep(wait_time)

            response_second = session.get(url, timeout=5, stream=True, headers=headers)
            if not (200 <= response_second.status_code < 400):
                log(f"{name}: {url} - 第二次获取失败")
                return (channel_data, False)
            
            m3u8_content_second = ""
            downloaded_size = 0
            for chunk in response_second.iter_content(chunk_size=1024):
                m3u8_content_second += chunk.decode('utf-8', errors='ignore')
                downloaded_size += len(chunk)
                if downloaded_size >= content_limit:
                    break
            
            if not m3u8_content_second:
                log(f"{name}: {url} - 第二次M3U8内容为空")
                return (channel_data, False)
            
            ts1 = re.findall(r'\S+\.ts', m3u8_content_first)
            ts2 = re.findall(r'\S+\.ts', m3u8_content_second)
            seq1 = re.search(r'#EXT-X-MEDIA-SEQUENCE:(\d+)', m3u8_content_first)
            if seq1 or ts1 != ts2:
                return (channel_data, True)
            log(f"{name}: {url} - M3U8未更新")
            return (channel_data, False)

        return (channel_data, True)
    except requests.exceptions.Timeout:
        log(f"{name}: {url} - 请求超时")
        return (channel_data, False)
    except requests.exceptions.ConnectionError:
        log(f"{name}: {url} - 连接错误")
        return (channel_data, False)
    except requests.exceptions.RequestException:
        log(f"{name}: {url} - 请求异常")
        return (channel_data, False)
    except Exception as e:
        log(f"{name}: {url} - 意外错误: {type(e).__name__}: {e}")
        return (channel_data, False)

# --- 第三次测试（包含 FFmpeg） ---
def check_link_connectivity_with_ffmpeg(channel_data: dict) -> tuple:
    result = check_link_connectivity_no_ffmpeg(channel_data)
    if not result[1]:
        return result
    if not check_ffmpeg_playback(channel_data['url']):
        log(f"{channel_data['name']}: {channel_data['url']} - FFmpeg测试失败")
        return (channel_data, False)
    return (channel_data, True)

# --- 解析 tv.list.txt 或临时文件 ---
def parse_tv_list_content(content: str) -> dict:
    categorized_channels = {}
    current_category = None
    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if line.endswith(':'):
            current_category = line[:-1]
            categorized_channels[current_category] = []
        elif line.startswith('  - ') and current_category is not None:
            if line == '  - []':
                continue
            match = re.match(r'\s*-\s*([^,]+),(.*)', line)
            if match:
                name = match.group(1).strip()
                url = match.group(2).strip()
                if url != '#NoAvailableURLFound#':
                    categorized_channels[current_category].append({"name": name, "url": url})
    return categorized_channels

# --- 辅助函数 ---
def load_categories_config():
    try:
        if os.path.exists(CATEGORIES_FILE):
            with open(CATEGORIES_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                return yaml.safe_load(f)
        log(f"警告: {CATEGORIES_FILE} 文件未找到，使用默认空分类配置。")
        return {"新闻": [], "电影": [], "卡通": [], "综艺": [], "其他": []}
    except Exception as e:
        log(f"加载 {CATEGORIES_FILE} 失败: {type(e).__name__}: {e}")
        return {"新闻": [], "电影": [], "卡通": [], "综艺": [], "其他": []}

def parse_iptv_content(content: str) -> list:
    parsed_channels = []
    lines = content.splitlines()
    for line in lines:
        match = re.match(r'([^,]+),(https?://.*)', line)
        if match:
            name = match.group(1).strip()
            url = match.group(2).strip()
            parsed_channels.append({"name": name, "url": url})
    return parsed_channels

def save_tv_list(categorized_channel_names: dict, channel_urls_map: dict, output_file: str):
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            for category, channel_names in sorted(categorized_channel_names.items()):
                f.write(f"{category}:\n")
                if channel_names:
                    for name in sorted(channel_names):
                        if name in channel_urls_map and channel_urls_map[name]:
                            for available_url in channel_urls_map[name]:
                                f.write(f"  - {name},{available_url}\n")
                        else:
                            f.write(f"  - {name},#NoAvailableURLFound#\n")
                else:
                    f.write("  - []\n")
                f.write("\n")
        log(f"保存结果到 {output_file}")
    except Exception as e:
        log(f"保存 {output_file} 失败: {type(e).__name__}: {e}")

# --- 单次测试逻辑 ---
def run_test(channels: list, output_file: str, test_round: int, use_ffmpeg: bool = False) -> list:
    log(f"开始第 {test_round} 次测试，处理 {len(channels)} 个频道...")
    channel_name_to_working_urls = {}
    total_checked_urls = 0
    total_working_urls = 0
    check_func = check_link_connectivity_with_ffmpeg if use_ffmpeg else check_link_connectivity_no_ffmpeg

    for batch_start in range(0, len(channels), BATCH_SIZE):
        batch_channels = channels[batch_start:batch_start + BATCH_SIZE]
        log(f"处理第 {test_round} 次测试，第 {batch_start // BATCH_SIZE + 1} 批，{len(batch_channels)} 个URL")
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_channel_data = {executor.submit(check_func, channel_data): channel_data 
                                      for channel_data in batch_channels}
            for future in concurrent.futures.as_completed(future_to_channel_data):
                channel_data_original = future_to_channel_data[future]
                name = channel_data_original['name']
                url = channel_data_original['url']
                try:
                    channel_data_result, is_working = future.result()
                    total_checked_urls += 1
                    if is_working:
                        if name not in channel_name_to_working_urls:
                            channel_name_to_working_urls[name] = []
                        channel_name_to_working_urls[name].append(url)
                        total_working_urls += 1
                    if total_checked_urls % 500 == 0 or total_checked_urls == len(channels):
                        log(f"第 {test_round} 次测试进度: {total_checked_urls}/{len(channels)} URL已测试")
                except Exception as exc:
                    total_checked_urls += 1
                    log(f"{name}: {url} - 测试异常: {type(exc).__name__}: {exc}")

    log(f"第 {test_round} 次测试完成：检查 {total_checked_urls} 个URL，{total_working_urls} 个通过。")

    defined_categories = load_categories_config()
    final_categorized_output_names = {category: [] for category in defined_categories.keys()}
    for category_name, expected_channel_names in defined_categories.items():
        for expected_name in expected_channel_names:
            if expected_name in channel_name_to_working_urls and channel_name_to_working_urls[expected_name]:
                final_categorized_output_names[category_name].append(expected_name)
    
    all_explicitly_listed_names = set()
    for names_list in defined_categories.values():
        all_explicitly_listed_names.update(names_list)
    other_channels_found = [name for name in channel_name_to_working_urls.keys() if name not in all_explicitly_listed_names]
    if '其他' not in final_categorized_output_names:
        final_categorized_output_names['其他'] = []
    final_categorized_output_names['其他'].extend(other_channels_found)

    save_tv_list(final_categorized_output_names, channel_name_to_working_urls, output_file)
    return [{"name": name, "url": url} for name, urls in channel_name_to_working_urls.items() for url in urls]

# --- 主执行逻辑 ---
def main():
    log("开始处理 IPTV 列表（三次逐次筛选测试）...")

    try:
        subprocess.run([FFMPEG_PATH, "-version"], capture_output=True, check=True)
        log("FFmpeg 检查通过")
    except (FileNotFoundError, subprocess.CalledProcessError):
        log(f"错误: FFmpeg 未安装或路径 '{FFMPEG_PATH}' 无效。")
        exit(1)

    if os.path.exists(LOCAL_IPTV_FILE):
        try:
            log(f"读取 {LOCAL_IPTV_FILE}...")
            with open(LOCAL_IPTV_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                local_content = f.read()
            channels = parse_iptv_content(local_content)
            log(f"成功解析 {len(channels)} 个频道条目。")
        except Exception as e:
            log(f"读取 {LOCAL_IPTV_FILE} 失败: {type(e).__name__}: {e}")
            exit(1)
    else:
        log(f"错误: {LOCAL_IPTV_FILE} 未找到。")
        exit(1)

    if not channels:
        log("未找到任何频道。脚本退出。")
        exit(0)

    log("开始预筛选（快速HTTP检查）...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=PRESCREEN_WORKERS) as executor:
        future_to_channel = {executor.submit(pre_check_url, channel['url']): channel for channel in channels}
        channels = [future_to_channel[future] for future in concurrent.futures.as_completed(future_to_channel) if future.result()]
    log(f"预筛选完成：保留 {len(channels)} 个URL。")

    channels = run_test(channels, FIRST_OUTPUT, 1, use_ffmpeg=False)
    time.sleep(RETRY_INTERVAL)
    if channels:
        channels = run_test(channels, SECOND_OUTPUT, 2, use_ffmpeg=False)
        time.sleep(RETRY_INTERVAL)
    else:
        log("第一次测试后无有效频道，退出。")
        return
    if channels:
        run_test(channels, FINAL_OUTPUT, 3, use_ffmpeg=True)
    else:
        log("第二次测试后无有效频道，退出。")

if __name__ == "__main__":
    main()
