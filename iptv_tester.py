# 文件名: iptv_tester.py

import requests
import re
import os
import yaml 
import concurrent.futures 
import time
import subprocess # 导入 subprocess 模块用于运行外部命令

from urllib.parse import urljoin 

# --- 配置变量 ---
LOCAL_IPTV_FILE = "iptv_list.txt"
CATEGORIES_FILE = "categories.yaml"
OUTPUT_FILE = "tv.list.txt"

MAX_WORKERS = 20 # 降低并发线程数，以应对 FFmpeg 的 CPU 和 IO 消耗
FFMPEG_PATH = "ffmpeg" # 确保 FFmpeg 已安装并位于系统 PATH 中

# --- FFmpeg 播放测试函数 ---
def check_ffmpeg_playback(url: str) -> bool:
    """
    使用 FFmpeg 模拟播放测试链接。
    尝试播放链接的前5秒，检查 FFmpeg 是否能成功启动并处理流。
    Args:
        url: 要测试的流链接。
    Returns:
        True 如果 FFmpeg 成功处理流，False 否则。
    """
    # 根据操作系统选择 null device
    null_device = "NUL" if os.name == 'nt' else "/dev/null"

    command = [
        FFMPEG_PATH,
        "-i", url,
        "-c", "copy", # 尝试复制流而不是重新编码，减少CPU开销
        "-map", "0:v?", # 尝试映射视频流（如果存在）
        "-map", "0:a?", # 尝试映射音频流（如果存在）
        "-f", "null",   # 输出到空设备
        "-t", "5",      # 测试前5秒
        "-y",           # 覆盖输出（对null设备无影响，但 good practice）
        null_device
    ]
    
    try:
        # 运行 FFmpeg 命令
        # 警告: 这将为每次调用启动一个外部 FFmpeg 进程。
        # 这是一个 CPU 和 I/O 密集型操作，将显著减慢脚本速度。
        process = subprocess.run(
            command,
            capture_output=True, # 捕获标准输出和标准错误
            text=True,           # 将输出解码为文本
            check=False,         # 不在非零返回码时抛出异常，我们手动检查
            timeout=20           # FFmpeg 最多有 20 秒时间处理流
        )

        # 检查 FFmpeg 的退出码和标准错误输出
        if process.returncode == 0:
            # 即使返回码为0，也可能在 stderr 中有警告或轻微错误
            # 检查关键的错误提示，以排除无效流
            if "Input/output error" in process.stderr or \
               "Connection refused" in process.stderr or \
               "Protocol not found" in process.stderr or \
               "No such file or directory" in process.stderr or \
               "Invalid data found when processing input" in process.stderr or \
               "failed to open" in process.stderr: # 增加更多常见错误判断
                print(f"    FFmpeg ({url}) 报告内部错误或无效数据，可能无法正常播放。")
                return False
            # 如果没有明显的错误，则认为播放成功
            return True
        else:
            # 非零返回码通常表示错误
            # print(f"    FFmpeg ({url}) 测试失败 (Exit Code: {process.returncode}). 错误信息:\n{process.stderr.strip()}")
            return False

    except subprocess.TimeoutExpired:
        print(f"    FFmpeg ({url}) 测试超时 (超过 {process.timeout} 秒)。")
        return False
    except FileNotFoundError:
        print(f"错误: FFmpeg 命令 '{FFMPEG_PATH}' 未找到。请确保 FFmpeg 已安装并位于系统 PATH 中。")
        return False
    except Exception as e:
        print(f"    FFmpeg ({url}) 测试异常: {e}")
        return False

# --- 核心连通性检查函数 ---
def check_link_connectivity(channel_data: dict) -> tuple:
    """
    检查IPTV链接的连通性。
    对于 .m3u8 链接，会尝试进一步检查其内部子链接的有效性，并判断是否为直播流。
    Args:
        channel_data: 包含 'name' 和 'url' 的字典。
    Returns:
        一个元组 (channel_data, is_working)，指示链接是否可用。
    """
    name = channel_data['name']
    url = channel_data['url']

    if not url.startswith("http"):
        return (channel_data, False)
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    try:
        # --- 阶段1: 初步链接连通性检查 ---
        response = requests.get(url, timeout=10, stream=True, headers=headers) 
        if not (200 <= response.status_code < 400):
            return (channel_data, False) # 主链接不可达

        # --- 阶段2: M3U8 特定检查 (直播判断和子链接检查) ---
        if '.m3u8' in url:
            m3u8_content_first = ""
            content_limit = 58 * 1024 # 58 KB
            downloaded_size_first = 0
            
            for chunk in response.iter_content(chunk_size=1024): 
                m3u8_content_first += chunk.decode('utf-8', errors='ignore')
                downloaded_size_first += len(chunk)
                if downloaded_size_first >= content_limit:
                    break
            
            if "#EXT-X-ENDLIST" in m3u8_content_first or "EXT-X-PLAYLIST-TYPE:VOD" in m3u8_content_first:
                return (channel_data, False) # 识别为点播或已结束的流

            # --- 模拟 "播放" 行为 (第二次测试): 等待并再次获取 M3U8 清单 ---
            time.sleep(5) # 警告：这将为每个 M3U8 链接增加 5 秒的延迟！

            response_second_fetch = requests.get(url, timeout=10, stream=True, headers=headers)
            if not (200 <= response_second_fetch.status_code < 400):
                return (channel_data, False) # M3U8 链接在第二次获取时变得不可达

            m3u8_content_second = ""
            downloaded_size_second = 0
            for chunk in response_second_fetch.iter_content(chunk_size=1024):
                m3u8_content_second += chunk.decode('utf-8', errors='ignore')
                downloaded_size_second += len(chunk)
                if downloaded_size_second >= content_limit:
                    break
            
            if m3u8_content_first == m3u8_content_second:
                return (channel_data, False) # M3U8 清单未更新，可能不是直播电视节目

            # --- 子链接连通性检查 (使用第二次获取到的最新清单中的子链接) ---
            sub_link_match = re.search(r'(https?://[^"\s]+?\.m3u8|\S+\.ts)', m3u8_content_second)
            
            if sub_link_match:
                sub_link = sub_link_match.group(0)
                full_sub_link = urljoin(url, sub_link) 
                
                try:
                    sub_response = requests.get(full_sub_link, timeout=5, stream=True, headers=headers)
                    if not (200 <= sub_response.status_code < 400):
                        return (channel_data, False) # 子链接不可达
                except requests.exceptions.RequestException:
                    return (channel_data, False) # 子链接请求失败
            else:
                return (channel_data, False) # M3U8 文件中没有找到有效的子链接，视为无效
        
        # --- 阶段3: FFmpeg 模拟播放测试 (适用于所有通过前两阶段的链接) ---
        if not check_ffmpeg_playback(url):
            return (channel_data, False)

        return (channel_data, True) # 所有检查通过，链接可用

    # --- 异常处理 ---
    except requests.exceptions.Timeout:
        return (channel_data, False)
    except requests.exceptions.ConnectionError:
        return (channel_data, False)
    except requests.exceptions.RequestException: 
        return (channel_data, False)
    except Exception as e:
        print(f"检查链接 {url} 时发生意外错误: {e}")
        return (channel_data, False)

# --- 其他辅助函数 (保持不变) ---
def load_categories_config():
    """加载分类配置文件 (YAML 格式)"""
    if os.path.exists(CATEGORIES_FILE):
        with open(CATEGORIES_FILE, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    print(f"警告: {CATEGORIES_FILE} 文件未找到，将使用默认空分类配置。")
    return {"新闻": [], "电影": [], "卡通": [], "综艺": [], "其他": []}

def parse_iptv_content(content: str) -> list:
    """
    解析 IPTV 列表内容，从每行提取频道名称和URL。
    Args:
        content: IPTV 列表的字符串内容。
    Returns:
        一个包含 {"name": ..., "url": ...} 字典的列表。
    """
    parsed_channels = []
    lines = content.splitlines()
    for line in lines:
        match = re.match(r'([^,]+),(https?://.*)', line)
        if match:
            name = match.group(1).strip()
            url = match.group(2).strip()
            parsed_channels.append({"name": name, "url": url})
    return parsed_channels

def save_tv_list(categorized_channel_names: dict, channel_urls_map: dict):
    """
    将分类后的频道名称和其对应的所有可用URL保存到tv.list.txt。
    Args:
        categorized_channel_names: 按类别分组的频道名称 {category: [name1, name2, ...]}
        channel_urls_map: 频道名称到可用URL列表的映射 {name: [url1, url2, ...]}
    """
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for category, channel_names in categorized_channel_names.items():
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

# --- 主执行逻辑 ---
def main():
    print(f"开始处理 IPTV 列表...")
    
    all_channels_to_process = []

    # 1. 尝试读取本地 IPTV 列表文件 
    if os.path.exists(LOCAL_IPTV_FILE):
        try:
            with open(LOCAL_IPTV_FILE, 'r', encoding='utf-8') as f:
                local_content = f.read()
                local_parsed = parse_iptv_content(local_content)
                all_channels_to_process.extend(local_parsed)
                print(f"成功从本地 {LOCAL_IPTV_FILE} 解析到 {len(local_parsed)} 个频道条目。")
        except Exception as e:
            print(f"读取本地 {LOCAL_IPTV_FILE} 失败: {e}")
            print("未能读取本地 IPTV 列表，脚本无法继续。退出。")
            exit(1)
    else:
        print(f"错误: 本地 {LOCAL_IPTV_FILE} 文件未找到。脚本无法继续。")
        exit(1)

    if not all_channels_to_process:
        print("未找到任何 IPTV 频道进行处理。脚本退出。")
        exit(0) 

    print(f"总共收集到 {len(all_channels_to_process)} 个频道条目待处理。")

    # 3. 加载分类配置文件
    defined_categories = load_categories_config()

    channel_name_to_working_urls = {}

    print("开始检查所有频道的连通性 (并发模式，包含 FFmpeg 测试)...")
    total_checked_urls = 0
    total_working_urls = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_channel_data = {executor.submit(check_link_connectivity, channel_data): channel_data 
                                  for channel_data in all_channels_to_process}
        
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
                
                if total_checked_urls % 50 == 0 or total_checked_urls == len(all_channels_to_process):
                    print(f"  进度: {total_checked_urls}/{len(all_channels_to_process)} URL已测试。")

            except Exception as exc:
                total_checked_urls += 1
                print(f"  [{total_checked_urls}/{len(all_channels_to_process)}] {name}: {url} -> 测试出现异常: {exc}")

    print(f"连通性检查完成。")
    print(f"总共检查了 {total_checked_urls} 个URL，其中 {total_working_urls} 个URL连通（通过所有测试）。")
    print(f"发现 {len(channel_name_to_working_urls)} 个频道名称至少有一个可用URL。")

    final_categorized_output_names = {}
    for category_name in defined_categories.keys():
        final_categorized_output_names[category_name] = []

    for category_name, expected_channel_names in defined_categories.items():
        for expected_name in expected_channel_names:
            if expected_name in channel_name_to_working_urls and channel_name_to_working_urls[expected_name]:
                final_categorized_output_names[category_name].append(expected_name)
    
    all_explicitly_listed_names = set()
    for names_list in defined_categories.values():
        all_explicitly_listed_names.update(names_list)

    other_channels_found = []
    for name in channel_name_to_working_urls.keys():
        if name not in all_explicitly_listed_names:
            other_channels_found.append(name)
    
    if '其他' not in final_categorized_output_names:
        final_categorized_output_names['其他'] = []
    
    final_categorized_output_names['其他'].extend(other_channels_found)

    save_tv_list(final_categorized_output_names, channel_name_to_working_urls)
    print(f"处理完成，连通并分类的频道已保存到 {OUTPUT_FILE}。")

if __name__ == "__main__":
    main()
