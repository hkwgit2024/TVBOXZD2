import requests
import re
import os
import yaml
import concurrent.futures
import time
import subprocess
import multiprocessing
import threading
from urllib.parse import urljoin

# --- 配置变量 ---
LOCAL_IPTV_FILE = "iptv_list.txt"
CATEGORIES_FILE = "categories.yaml"
FIRST_OUTPUT = "temp1.list.txt"
SECOND_OUTPUT = "temp2.list.txt"
FINAL_OUTPUT = "tv.list.txt"
MAX_WORKERS = 8  # 固定为8，适合GitHub Actions
FFMPEG_PATH = "ffmpeg"
RETRY_INTERVAL = 2
M3U8_WAIT = 2
LOG_FILE = "test_errors.log"
log_lock = threading.Lock()

# --- 日志记录 ---
def log_error(message: str):
    with log_lock:
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")

# --- 预筛选 ---
def pre_check_url(url: str) -> bool:
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124'}
    try:
        response = requests.head(url, timeout=5, headers=headers, allow_redirects=True)
        if 200 <= response.status_code < 400:
            return True
        response = requests.get(url, timeout=5, stream=True, headers=headers)
        return 200 <= response.status_code < 400
    except:
        return False

# --- FFmpeg 播放测试 ---
def check_ffmpeg_playback(url: str) -> bool:
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
                log_error(f"FFmpeg ({url}): 无效数据 - {process.stderr.strip()}")
                return False
            return True
        log_error(f"FFmpeg ({url}): 非零返回码 - {process.stderr.strip()}")
        return False
    except subprocess.TimeoutExpired:
        log_error(f"FFmpeg ({url}): 测试超时")
        return False
    except FileNotFoundError:
        log_error(f"FFmpeg 未找到: {FFMPEG_PATH}")
        return False
    except Exception as e:
        log_error(f"FFmpeg ({url}): 异常 - {type(e).__name__}: {e}")
        return False

# --- 单次连通性检查（无 FFmpeg） ---
def check_link_connectivity_no_ffmpeg(channel_data: dict) -> tuple:
    name = channel_data['name']
    url = channel_data['url']
    if not url.startswith("http"):
        log_error(f"{name}: {url} - 无效URL格式")
        return (channel_data, False)
    
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124'}
    try:
        response = requests.get(url, timeout=10, stream=True, headers=headers)
        if not (200 <= response.status_code < 400):
            log_error(f"{name}: {url} - HTTP不可达")
            return (channel_data, False)

        if '.m3u8' in url:
            m3u8_content_first = ""
            content_limit = 10 * 1024
            downloaded_size = 0
            for chunk in response.iter_content(chunk_size=1024):
                m3u8_content_first += chunk.decode('utf-8', errors='ignore')
                downloaded_size += len(chunk)
                if downloaded_size >= content_limit:
                    break
            
            if not m3u8_content_first:
                log_error(f"{name}: {url} - M3U8内容为空")
                return (channel_data, False)
            
            if "#EXT-X-ENDLIST" in m3u8_content_first or "EXT-X-PLAYLIST-TYPE:VOD" in m3u8_content_first:
                log_error(f"{name}: {url} - 非直播流")
                return (channel_data, False)

            target_duration_match = re.search(r'#EXT-X-TARGETDURATION:(\d+)', m3u8_content_first)
            wait_time = max(2, int(target_duration_match.group(1)) // 2) if target_duration_match else 2
            time.sleep(wait_time)

            response_second = requests.get(url, timeout=10, stream=True, headers=headers)
            if not (200 <= response_second.status_code < 400):
                log_error(f"{name}: {url} - 第二次获取失败")
                return (channel_data, False)
            
            m3u8_content_second = ""
            downloaded_size = 0
            for chunk in response_second.iter_content(chunk_size=1024):
                m3u8_content_second += chunk.decode('utf-8', errors='ignore')
                downloaded_size += len(chunk)
                if downloaded_size >= content_limit:
                    break
            
            if not m3u8_content_second:
                log_error(f"{name}: {url} - 第二次M3U8内容为空")
                return (channel_data, False)
            
            ts1 = re.findall(r'\S+\.ts', m3u8_content_first)
            ts2 = re.findall(r'\S+\.ts', m3u8_content_second)
            if ts1 == ts2:
                log_error(f"{name}: {url} - M3U8未更新")
                return (channel_data, False)

            sub_link_match = re.search(r'(https?://[^"\s]+?\.m3u8|\S+\.ts)', m3u8_content_second)
            if sub_link_match:
                sub_link = sub_link_match.group(0)
                full_sub_link = urljoin(url, sub_link)
                try:
                    sub_response = requests.get(full_sub_link, timeout=5, stream=True, headers=headers)
                    if not (200 <= sub_response.status_code < 400):
                        log_error(f"{name}: {url} - 子链接不可达")
                        return (channel_data, False)
                except requests.exceptions.RequestException as e:
                    log_error(f"{name}: {url} - 子链接请求失败: {type(e).__name__}: {e}")
                    return (channel_data, False)
            else:
                log_error(f"{name}: {url} - 无有效子链接")
                return (channel_data, False)
        
        return (channel_data, True)
    except requests.exceptions.Timeout:
        log_error(f"{name}: {url} - 请求超时")
        return (channel_data, False)
    except requests.exceptions.ConnectionError:
        log_error(f"{name}: {url} - 连接错误")
        return (channel_data, False)
    except requests.exceptions.RequestException:
        log_error(f"{name}: {url} - 请求异常")
        return (channel_data, False)
    except Exception as e:
        log_error(f"{name}: {url} - 意外错误: {type(e).__name__}: {e}")
        return (channel_data, False)

# --- 第三次测试（包含 FFmpeg） ---
def check_link_connectivity_with_ffmpeg(channel_data: dict) -> tuple:
    result = check_link_connectivity_no_ffmpeg(channel_data)
    if not result[1]:
        return result
    if not check_ffmpeg_playback(channel_data['url']):
        log_error(f"{channel_data['name']}: {channel_data['url']} - FFmpeg测试失败")
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
    if os.path.exists(CATEGORIES_FILE):
        with open(CATEGORIES_FILE, 'r', encoding='utf-8', errors='ignore') as f:
            return yaml.safe_load(f)
    print(f"警告: {CATEGORIES_FILE} 文件未找到，使用默认空分类配置。")
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

# --- 单次测试逻辑 ---
def run_test(channels: list, output_file: str, test_round: int, use_ffmpeg: bool = False) -> list:
    print(f"开始第 {test_round} 次测试，处理 {len(channels)} 个频道...")
    channel_name_to_working_urls = {}
    total_checked_urls = 0
    total_working_urls = 0
    check_func = check_link_connectivity_with_ffmpeg if use_ffmpeg else check_link_connectivity_no_ffmpeg

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_channel_data = {executor.submit(check_func, channel_data): channel_data 
                                  for channel_data in channels}
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
                if total_checked_urls % 1000 == 0 or total_checked_urls == len(channels):
                    print(f"  进度: {total_checked_urls}/{len(channels)} URL已测试。")
            except Exception as exc:
                total_checked_urls += 1
                log_error(f"{name}: {url} - 测试异常: {type(exc).__name__}: {exc}")

    print(f"第 {test_round} 次测试完成：检查 {total_checked_urls} 个URL，{total_working_urls} 个通过。")

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
    print(f"第 {test_round} 次测试结果已保存到 {output_file}。")

    return [{"name": name, "url": url} for name, urls in channel_name_to_working_urls.items() for url in urls]

# --- 主执行逻辑 ---
def main():
    print("开始处理 IPTV 列表（三次逐次筛选测试）...")

    # 检查 FFmpeg
    try:
        subprocess.run([FFMPEG_PATH, "-version"], capture_output=True, check=True)
    except (FileNotFoundError, subprocess.CalledProcessError):
        print(f"错误: FFmpeg 未安装或路径 '{FFMPEG_PATH}' 无效。")
        exit(1)

    # 读取初始 IPTV 列表
    if os.path.exists(LOCAL_IPTV_FILE):
        try:
            with open(LOCAL_IPTV_FILE, 'r', encoding='utf-8', errors='ignore') as f:
                local_content = f.read()
                channels = parse_iptv_content(local_content)
                print(f"成功解析 {len(channels)} 个频道条目。")
        except Exception as e:
            print(f"读取 {LOCAL_IPTV_FILE} 失败: {e}")
            exit(1)
    else:
        print(f"错误: {LOCAL_IPTV_FILE} 未找到。")
        exit(1)

    if not channels:
        print("未找到任何频道。脚本退出。")
        exit(0)

    # 预筛选
    print("开始预筛选（快速HTTP检查）...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        future_to_channel = {executor.submit(pre_check_url, channel['url']): channel for channel in channels}
        channels = [future_to_channel[future] for future in concurrent.futures.as_completed(future_to_channel) if future.result()]
    print(f"预筛选完成：保留 {len(channels)} 个URL。")

    # 三次测试
    channels = run_test(channels, FIRST_OUTPUT, 1, use_ffmpeg=False)
    time.sleep(RETRY_INTERVAL)
    if channels:
        channels = run_test(channels, SECOND_OUTPUT, 2, use_ffmpeg=False)
        time.sleep(RETRY_INTERVAL)
    else:
        print("第一次测试后无有效频道，退出。")
        return
    if channels:
        run_test(channels, FINAL_OUTPUT, 3, use_ffmpeg=True)
    else:
        print("第二次测试后无有效频道，退出。")

if __name__ == "__main__":
    main()
