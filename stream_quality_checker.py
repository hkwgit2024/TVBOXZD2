import re
import subprocess
import os
import datetime
import concurrent.futures
import time

# --- 配置 ---
INPUT_FILE = 'output/iptv_list.txt'
OUTPUT_FILE = 'output/high_quality_iptv.txt'
LOG_FILE = 'output/iptv_validation.log'

# ffprobe 相关配置
FFPROBE_TIMEOUT_SECONDS = 15 # 每个 ffprobe 进程的最大运行时间
MIN_STREAM_DURATION_SECONDS = 30 # 认为有效直播流的最小持续持续时间（如果 ffprobe 返回具体时长的话）
MAX_WORKERS = 10 # 并发验证的线程数

# --- 全局日志句柄 (用于并发和错误处理) ---
_global_log_file_handle = None

def write_log(message):
    """同时打印到控制台和全局日志文件句柄"""
    timestamp_message = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}"
    print(timestamp_message)
    if _global_log_file_handle:
        try:
            _global_log_file_handle.write(timestamp_message + '\n')
            _global_log_file_handle.flush() # 确保立即写入文件
        except ValueError:
            # 文件可能已被关闭，不再尝试写入
            pass

# --- 频道验证函数 ---
def validate_channel_with_ffprobe(url):
    """
    使用 ffprobe 验证单个 IPTV 频道 URL 的有效性和内容类型。
    返回 True 如果频道看起来有效且不是广告/重复片段，否则返回 False。
    """
    if not url or not url.startswith(('http://', 'https://')):
        write_log(f"  -> 无效URL格式或为空: {url}")
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
        write_log(f"    正在运行 ffprobe for: {url}")
        start_time = time.monotonic()
        
        # 使用 Popen 和 communicate() 确保进程被正确等待和清理
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=FFPROBE_TIMEOUT_SECONDS)
        end_time = time.monotonic()
        
        if process.returncode != 0:
            # ffprobe 返回非零退出码，表示错误
            write_log(f"  -> ffprobe 错误 (Exit Code {process.returncode}): {stderr.strip()}")
            return False

        write_log(f"    ffprobe 完成 ({end_time - start_time:.2f}s) for: {url}")
        
        has_video_or_audio = False
        duration_looks_valid = False

        # 逐行处理 ffprobe 的标准输出
        for line in stdout.splitlines():
            # 调试输出：处理每一行
            # write_log(f"      Processing line from ffprobe stdout: '{line}'") 
            
            if 'codec_type=video' in line:
                has_video_or_audio = True
                # write_log(f"        Detected video codec type for {url}.") # 调试输出
            if 'codec_type=audio' in line:
                has_video_or_audio = True
                # write_log(f"        Detected audio codec type for {url}.") # 调试输出

            if 'duration=' in line:
                try:
                    duration_str = line.split('duration=')[1].strip()
                    # write_log(f"        Detected duration_str for {url}: '{duration_str}'") # 调试输出
                    if duration_str == 'N/A': # 对于直播流，N/A 是正常的
                        duration_looks_valid = True
                        # write_log(f"        Duration N/A, considered valid for {url}.") # 调试输出
                    else:
                        duration = float(duration_str)
                        if duration >= MIN_STREAM_DURATION_SECONDS:
                            duration_looks_valid = True
                            # write_log(f"        Duration {duration:.2f}s >= {MIN_STREAM_DURATION_SECONDS}s, considered valid for {url}.") # 调试输出
                        # else: # 调试输出
                            # write_log(f"        Duration {duration:.2f}s < {MIN_STREAM_DURATION_SECONDS}s, considered invalid for {url}.") 
                except ValueError:
                    # 如果无法解析时长（例如，非数字），但 ffprobe 确实找到了流，也认为是有效的
                    duration_looks_valid = True 
                    # write_log(f"        Could not parse duration for {url}, considered valid (assuming live/unknown duration).") # 调试输出
        
        # 调试输出：最终判断结果
        # write_log(f"    Final checks for {url}: has_video_or_audio={has_video_or_audio}, duration_looks_valid={duration_looks_valid}") 
        
        if has_video_or_audio and duration_looks_valid:
            write_log(f"  -> 结果: 有效")
            return True
        else:
            # 如果不符合有效条件，打印详细的 stdout/stderr 以供排查
            write_log(f"  -> 结果: 流类型或时长不符。stdout: \n{stdout.strip()}\nstderr: \n{stderr.strip()}")
            return False

    except subprocess.TimeoutExpired as e:
        write_log(f"  -> ffprobe 超时 ({FFPROBE_TIMEOUT_SECONDS}s) for {url}")
        # 在超时时，确保终止 ffprobe 进程，防止残留
        # communicate() 在超时时会终止进程并填充stdout/stderr，这里可以直接访问 e.stdout/e.stderr
        if e.stdout:
            write_log(f"    ffprobe stdout (before timeout): {e.stdout.strip()}")
        if e.stderr:
            write_log(f"    ffprobe stderr (before timeout): {e.stderr.strip()}")
        process.kill() # 确保进程被杀死
        process.wait() # 等待进程结束
        return False
    except FileNotFoundError:
        write_log("  -> 错误: ffprobe 未找到。请确保 FFmpeg 已安装且在系统 PATH 中。")
        return False
    except Exception as e:
        # 捕获其他所有未预料的异常
        write_log(f"  -> 发生未知错误 for {url}: {e}")
        return False

# --- 主处理逻辑 ---
def process_iptv_list():
    global _global_log_file_handle # 声明使用全局变量

    # 确保 output 目录存在
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    
    # 在函数开始时打开日志文件，并将其赋值给全局变量
    # 使用 try-finally 块确保无论发生什么，文件都能被关闭
    _global_log_file_handle = open(LOG_FILE, 'w', encoding='utf-8')

    try:
        write_log(f"--- IPTV 频道验证开始 - {datetime.datetime.now()} ---")
        write_log(f"输入文件: {INPUT_FILE}")
        write_log(f"输出文件: {OUTPUT_FILE}")
        write_log(f"并发线程数: {MAX_WORKERS}")
        write_log(f"ffprobe 超时: {FFPROBE_TIMEOUT_SECONDS} 秒")
        write_log(f"最小直播流时长: {MIN_STREAM_DURATION_SECONDS} 秒")
        write_log("-" * 50)

        try:
            with open(INPUT_FILE, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            write_log(f"成功读取 {len(lines)} 行自 {INPUT_FILE}")
        except FileNotFoundError:
            write_log(f"错误: 输入文件 '{INPUT_FILE}' 未找到。请确认文件路径。")
            return
        except Exception as e:
            write_log(f"错误: 读取文件 '{INPUT_FILE}' 时发生异常: {e}")
            return

        good_channels = []
        # 添加文件头，包括更新时间
        good_channels.append(f"更新时间,{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        channels_to_validate = []
        original_lines_map = {} # 存储原始行内容，包括分类行和频道行
        
        # 遍历输入文件，识别分类和待验证频道
        for i, line in enumerate(lines):
            line_stripped = line.strip()
            original_lines_map[i] = line_stripped # 记录原始行内容

            if not line_stripped:
                continue

            # 忽略文件顶部的更新时间行（如果存在）
            if i == 0 and "更新时间" in line_stripped and "#genre#" in line_stripped:
                continue

            if "#genre#" in line_stripped:
                # 这是一个分类行，直接添加到高质量列表中
                good_channels.append(line_stripped)
                continue

            parts = line_stripped.split(',', 1)
            if len(parts) == 2:
                channel_name = parts[0].strip()
                channel_url = parts[1].strip()
                channels_to_validate.append((channel_name, channel_url, i)) # 存储频道信息和原始行号
            else:
                write_log(f"跳过格式错误行 (行号 {i+1}): {line_stripped}")


        write_log(f"识别到 {len(channels_to_validate)} 个频道待验证。")
        write_log("-" * 50)

        results = {}
        # 使用线程池并发验证频道
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_channel = {executor.submit(validate_channel_with_ffprobe, url): (name, url, original_line_idx)
                                 for name, url, original_line_idx in channels_to_validate}
            
            # 当一个任务完成时，处理其结果
            for future in concurrent.futures.as_completed(future_to_channel):
                name, url, original_line_idx = future_to_channel[future]
                try:
                    is_valid = future.result()
                    results[original_line_idx] = (name, url, is_valid)
                except Exception as exc:
                    write_log(f"频道 {name} ({url}) 在验证时产生未知异常: {exc}")
                    results[original_line_idx] = (name, url, False)

        # 根据原始文件中的行顺序，将有效频道添加到 good_channels 列表
        processed_channel_count = 0
        for original_line_idx in sorted(original_lines_map.keys()): 
            original_line_content = original_lines_map[original_line_idx]
            
            # 如果是分类行，已经在一开始被添加到 good_channels，跳过
            if "#genre#" in original_line_content:
                continue 
            
            # 检查该行是否是频道行，并且验证结果是有效
            if original_line_idx in results and results[original_line_idx][2]:
                good_channels.append(original_line_content)
                processed_channel_count += 1
            # 否则，该行是无效频道，不添加到 good_channels

        write_log(f"\n验证完成。共找到 {processed_channel_count} 个有效频道。")
        write_log("-" * 50)

        # 将高质量列表写入输出文件
        try:
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                for channel_line in good_channels:
                    f.write(channel_line + '\n')
            write_log(f"高质量 IPTV 列表已保存到 {OUTPUT_FILE}")
        except Exception as e:
            write_log(f"错误: 写入文件 '{OUTPUT_FILE}' 时发生异常: {e}")

    finally:
        # 确保在所有操作完成后关闭日志文件句柄
        if _global_log_file_handle:
            write_log(f"--- IPTV 频道验证结束 - {datetime.datetime.now()} ---")
            _global_log_file_handle.close()
            _global_log_file_handle = None # 清除全局变量
            print(f"日志文件 '{LOG_FILE}' 已关闭。")


if __name__ == "__main__":
    process_iptv_list()
