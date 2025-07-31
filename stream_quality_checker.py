import re
import subprocess
import os
import datetime
import concurrent.futures # 用于并发处理
import time

# --- 配置 ---
INPUT_FILE = 'output/iptv_list.txt'
OUTPUT_FILE = 'output/high_quality_iptv.txt'
LOG_FILE = 'output/iptv_validation.log'

# ffprobe 相关配置
FFPROBE_TIMEOUT_SECONDS = 15 # 每个 ffprobe 进程的最大运行时间
MIN_STREAM_DURATION_SECONDS = 30 # 认为有效直播流的最小持续时间（如果 ffprobe 返回具体时长的话）
MAX_WORKERS = 10 # 并发验证的线程数

# --- 辅助函数 ---

def write_log(message, log_file_handle):
    """同时打印到控制台和日志文件"""
    timestamp_message = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}"
    print(timestamp_message)
    log_file_handle.write(timestamp_message + '\n')
    log_file_handle.flush() # 确保立即写入文件

def validate_channel_with_ffprobe(url, log_f):
    """
    使用 ffprobe 验证单个 IPTV 频道 URL 的有效性和内容类型。
    返回 True 如果频道看起来有效且不是广告/重复片段，否则返回 False。
    """
    if not url or not url.startswith(('http://', 'https://')):
        write_log(f"  -> 无效URL格式或为空: {url}", log_f)
        return False

    command = [
        'ffprobe',
        '-v', 'error',
        '-show_entries', 'stream=codec_type,duration',
        '-of', 'default=noprint_wrappers=1:nokey=1',
        '-timeout', str(FFPROBE_TIMEOUT_SECONDS * 1000000), # ffprobe 接受微秒
        url
    ]

    try:
        write_log(f"    正在运行 ffprobe for: {url}", log_f)
        start_time = time.monotonic()
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=FFPROBE_TIMEOUT_SECONDS)
        end_time = time.monotonic()
        write_log(f"    ffprobe 完成 ({end_time - start_time:.2f}s) for: {url}", log_f)
        output = result.stdout

        has_video_or_audio = False
        duration_looks_valid = False

        for line in output.splitlines():
            if 'codec_type=video' in line or 'codec_type=audio' in line:
                has_video_or_audio = True
            if 'duration=' in line:
                try:
                    duration_str = line.split('duration=')[1].strip()
                    if duration_str == 'N/A': # 直播流通常显示 N/A
                        duration_looks_valid = True
                    else:
                        duration = float(duration_str)
                        if duration >= MIN_STREAM_DURATION_SECONDS: # 认为短于此值的可能是广告/短片
                            duration_looks_valid = True
                except ValueError:
                    # 无法解析时长，但如果存在流，也认为是有效的
                    duration_looks_valid = True

        if has_video_or_audio and duration_looks_valid:
            write_log(f"  -> 结果: 有效", log_f)
            return True
        else:
            write_log(f"  -> 结果: 流类型或时长不符。输出: \n{output.strip()}", log_f)
            return False

    except subprocess.CalledProcessError as e:
        write_log(f"  -> ffprobe 错误 (Exit Code {e.returncode}): {e.stderr.strip()}", log_f)
        return False
    except subprocess.TimeoutExpired:
        write_log(f"  -> ffprobe 超时 ({FFPROBE_TIMEOUT_SECONDS}s)", log_f)
        # 终止超时进程，防止残留
        if e.stdout:
            write_log(f"    ffprobe stdout (before timeout): {e.stdout}", log_f)
        if e.stderr:
            write_log(f"    ffprobe stderr (before timeout): {e.stderr}", log_f)
        if e.returncode: # 仅当进程实际被终止时才调用kill()
            e.kill()
        return False
    except FileNotFoundError:
        write_log("  -> 错误: ffprobe 未找到。请确保 FFmpeg 已安装且在系统 PATH 中。", log_f)
        return False
    except Exception as e:
        write_log(f"  -> 发生未知错误: {e}", log_f)
        return False

# --- 主处理逻辑 ---

def process_iptv_list():
    good_channels = []
    current_genre = "未知分类"
    
    # 确保 output 目录存在
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    
    with open(LOG_FILE, 'w', encoding='utf-8') as log_f:
        write_log(f"--- IPTV 频道验证开始 - {datetime.datetime.now()} ---", log_f)
        write_log(f"输入文件: {INPUT_FILE}", log_f)
        write_log(f"输出文件: {OUTPUT_FILE}", log_f)
        write_log(f"并发线程数: {MAX_WORKERS}", log_f)
        write_log(f"ffprobe 超时: {FFPROBE_TIMEOUT_SECONDS} 秒", log_f)
        write_log(f"最小直播流时长: {MIN_STREAM_DURATION_SECONDS} 秒", log_f)
        write_log("-" * 50, log_f)

        try:
            with open(INPUT_FILE, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            write_log(f"成功读取 {len(lines)} 行自 {INPUT_FILE}", log_f)
        except FileNotFoundError:
            write_log(f"错误: 输入文件 '{INPUT_FILE}' 未找到。请确认文件路径。", log_f)
            return
        except Exception as e:
            write_log(f"错误: 读取文件 '{INPUT_FILE}' 时发生异常: {e}", log_f)
            return

        # 添加文件头，包括更新时间
        good_channels.append(f"更新时间,{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        # 存储待验证的频道及其原始行号，以便后续添加
        channels_to_validate = []
        original_lines_map = {} # 存储原始行内容，包括分类行

        for i, line in enumerate(lines):
            line = line.strip()
            original_lines_map[i] = line # 记录原始行内容

            if not line:
                continue

            # 忽略文件顶部的更新时间行（如果存在）
            if i == 0 and "更新时间" in line and "#genre#" in line:
                continue

            if "#genre#" in line:
                # 这是一个分类行
                genre_match = re.match(r'^(.*?),\#genre\#', line)
                if genre_match:
                    current_genre = genre_match.group(1).strip()
                    good_channels.append(line) # 将分类行直接添加到高质量列表中
                continue

            parts = line.split(',', 1) # 只分割一次，以防URL中包含逗号
            if len(parts) == 2:
                channel_name = parts[0].strip()
                channel_url = parts[1].strip()
                channels_to_validate.append((channel_name, channel_url, i)) # 存储频道信息和原始行号

        write_log(f"识别到 {len(channels_to_validate)} 个频道待验证。", log_f)
        write_log("-" * 50, log_f)

        # 使用线程池并发验证
        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_channel = {executor.submit(validate_channel_with_ffprobe, url, log_f): (name, url, original_line_idx)
                                 for name, url, original_line_idx in channels_to_validate}
            
            for future in concurrent.futures.as_completed(future_to_channel):
                name, url, original_line_idx = future_to_channel[future]
                try:
                    is_valid = future.result()
                    results[original_line_idx] = (name, url, is_valid)
                except Exception as exc:
                    write_log(f"频道 {name} ({url}) 在验证时产生异常: {exc}", log_f)
                    results[original_line_idx] = (name, url, False) # 标记为无效

        # 根据原始顺序添加有效的频道
        processed_channel_count = 0
        for original_line_idx in sorted(results.keys()):
            name, url, is_valid = results[original_line_idx]
            if is_valid:
                # 找到原始行内容并添加
                original_line_content = original_lines_map[original_line_idx]
                good_channels.append(original_line_content)
                processed_channel_count += 1
        
        write_log(f"\n验证完成。共找到 {processed_channel_count} 个有效频道。", log_f)
        write_log("-" * 50, log_f)

        # 写入高质量列表到文件
        try:
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                for channel in good_channels:
                    f.write(channel + '\n')
            write_log(f"高质量 IPTV 列表已保存到 {OUTPUT_FILE}", log_f)
        except Exception as e:
            write_log(f"错误: 写入文件 '{OUTPUT_FILE}' 时发生异常: {e}", log_f)

    write_log(f"--- IPTV 频道验证结束 - {datetime.datetime.now()} ---", log_f)

if __name__ == "__main__":
    process_iptv_list()
