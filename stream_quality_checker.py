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
FFPROBE_TIMEOUT_SECONDS = 30  # 增加超时时间
MIN_STREAM_DURATION_SECONDS = 30  # 保持最小持续时间
MAX_WORKERS = 10  # 并发线程数
AD_BLACKLIST = {'php.jdshipin.com', 't.me'}  # 黑名单域名

# --- 全局日志句柄 ---
_global_log_file_handle = None

def write_log(message):
    """同时打印到控制台和全局日志文件句柄"""
    timestamp_message = f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}"
    print(timestamp_message)
    if _global_log_file_handle:
        try:
            _global_log_file_handle.write(timestamp_message + '\n')
            _global_log_file_handle.flush()
        except ValueError:
            pass

# --- 频道验证函数 ---
def is_likely_ad(name, url):
    """检查频道名或 URL 是否包含广告关键词或黑名单域名"""
    ad_keywords = ['ad', 'promo', 'commercial', 'advert']
    for keyword in ad_keywords:
        if keyword.lower() in name.lower() or keyword.lower() in url.lower():
            write_log(f"  -> 疑似广告（包含关键词 {keyword}）: {name}, {url}")
            return True
    for blacklisted in AD_BLACKLIST:
        if blacklisted in url.lower():
            write_log(f"  -> 黑名单命中: {url}")
            return True
    return False

def validate_channel_with_ffprobe(url, name):
    """
    使用 ffprobe 验证单个 IPTV 频道 URL 的有效性和内容类型。
    返回 True 如果频道看起来有效，否则返回 False。
    """
    if not url or not url.startswith(('http://', 'https://')):
        write_log(f"  -> 无效URL格式或为空: {url}")
        return False

    if is_likely_ad(name, url):
        return False

    command = [
        'ffprobe',
        '-v', 'error',
        '-show_entries', 'stream=codec_type,duration',
        '-of', 'default=noprint_wrappers=1:nokey=1',
        '-timeout', str(FFPROBE_TIMEOUT_SECONDS * 1000000),
        url
    ]

    try:
        write_log(f"    正在运行 ffprobe for: {url}")
        start_time = time.monotonic()
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=FFPROBE_TIMEOUT_SECONDS)
        connect_duration = time.monotonic() - start_time

        if process.returncode != 0:
            # 忽略特定错误，如非标准 m3u8 扩展
            if "Not detecting m3u8/hls with non standard extension" in stderr:
                write_log(f"  -> 忽略非标准 m3u8 错误: {stderr.strip()}")
                return False
            write_log(f"  -> ffprobe 错误 (Exit Code {process.returncode}): {stderr.strip()}")
            return False

        if connect_duration > 15:
            write_log(f"  -> 连接时间过长 ({connect_duration:.2f}s) for {url}")
            return False

        write_log(f"    ffprobe 完成 ({connect_duration:.2f}s) for: {url}")

        has_video_or_audio = False
        duration_looks_valid = True  # 默认直播流有效

        for line in stdout.splitlines():
            if 'codec_type=video' in line or 'codec_type=audio' in line:
                has_video_or_audio = True
            if 'duration=' in line:
                duration_str = line.split('duration=')[1].strip()
                if duration_str != 'N/A':
                    try:
                        duration = float(duration_str)
                        if duration < MIN_STREAM_DURATION_SECONDS:
                            duration_looks_valid = False
                    except ValueError:
                        duration_looks_valid = True  # 无法解析时长，假设有效

        if has_video_or_audio and duration_looks_valid:
            write_log(f"  -> 结果: 有效")
            return True
        else:
            write_log(f"  -> 失败: has_video_or_audio={has_video_or_audio}, duration_looks_valid={duration_looks_valid}, stdout: \n{stdout.strip()}\nstderr: \n{stderr.strip()}")
            return False

    except subprocess.TimeoutExpired as e:
        write_log(f"  -> ffprobe 超时 ({FFPROBE_TIMEOUT_SECONDS}s) for {url}")
        if e.stdout:
            write_log(f"    ffprobe stdout (before timeout): {e.stdout.strip()}")
        if e.stderr:
            write_log(f"    ffprobe stderr (before timeout): {e.stderr.strip()}")
        process.kill()
        process.wait()
        return False
    except FileNotFoundError:
        write_log("  -> 错误: ffprobe 未找到。请确保 FFmpeg 已安装且在系统 PATH 中。")
        return False
    except Exception as e:
        write_log(f"  -> 未知错误 for {url}: {e}")
        return False

# --- 主处理逻辑 ---
def process_iptv_list():
    global _global_log_file_handle

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
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
        good_channels.append(f"更新时间,{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        channels_to_validate = []
        original_lines_map = {}

        for i, line in enumerate(lines):
            line_stripped = line.strip()
            original_lines_map[i] = line_stripped

            if not line_stripped:
                continue

            if i == 0 and "更新时间" in line_stripped and "#genre#" in line_stripped:
                continue

            if "#genre#" in line_stripped:
                good_channels.append(line_stripped)
                continue

            parts = line_stripped.split(',', 1)
            if len(parts) == 2:
                channel_name = parts[0].strip()
                channel_url = parts[1].strip()
                channels_to_validate.append((channel_name, channel_url, i))
            else:
                write_log(f"跳过格式错误行 (行号 {i+1}): {line_stripped}")

        write_log(f"识别到 {len(channels_to_validate)} 个频道待验证。")
        write_log("-" * 50)

        results = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_channel = {executor.submit(validate_channel_with_ffprobe, url, name): (name, url, original_line_idx)
                                 for name, url, original_line_idx in channels_to_validate}
            
            for future in concurrent.futures.as_completed(future_to_channel):
                name, url, original_line_idx = future_to_channel[future]
                try:
                    is_valid = future.result()
                    results[original_line_idx] = (name, url, is_valid)
                except Exception as exc:
                    write_log(f"频道 {name} ({url}) 在验证时产生未知异常: {exc}")
                    results[original_line_idx] = (name, url, False)

        processed_channel_count = 0
        for original_line_idx in sorted(original_lines_map.keys()):
            original_line_content = original_lines_map[original_line_idx]
            
            if "#genre#" in original_line_content:
                continue
            
            if original_line_idx in results and results[original_line_idx][2]:
                good_channels.append(original_line_content)
                processed_channel_count += 1

        write_log(f"\n验证完成。共找到 {processed_channel_count} 个有效频道。")
        write_log("-" * 50)

        try:
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                for channel_line in good_channels:
                    f.write(channel_line + '\n')
            write_log(f"高质量 IPTV 列表已保存到 {OUTPUT_FILE}")
        except Exception as e:
            write_log(f"错误: 写入文件 '{OUTPUT_FILE}' 时发生异常: {e}")

    finally:
        if _global_log_file_handle:
            write_log(f"--- IPTV 频道验证结束 - {datetime.datetime.now()} ---")
            _global_log_file_handle.close()
            _global_log_file_handle = None
            print(f"日志文件 '{LOG_FILE}' 已关闭。")

if __name__ == "__main__":
    process_iptv_list()
