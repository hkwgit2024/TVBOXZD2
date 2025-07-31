import re
import subprocess
import os
import datetime
import concurrent.futures
import time
import argparse

# --- 配置 ---
INPUT_FILE = 'output/iptv_list.txt'
OUTPUT_FILE = 'output/high_quality_iptv.txt'
LOG_FILE = 'output/iptv_validation.log'
BLACKLIST_FILE = 'ad_blacklist.txt'

# 默认配置
DEFAULT_FFPROBE_TIMEOUT_SECONDS = 30
DEFAULT_MIN_STREAM_DURATION_SECONDS = 30
DEFAULT_MAX_WORKERS = 10
DEFAULT_MIN_BITRATE_KBPS = 500
AD_BLACKLIST = {'php.jdshipin.com', 't.me'}
WHITELIST = {
    'chinashadt.com', 'cztvcloud.com', 'jlntv.cn', 'dztv.tv',
    'rthktv32-live.akamaized.net', 'rthktv35-live.akamaized.net',
    'cnr.cn', 'akamaized.net', 'cloudfront.net', 'voc.com.cn',
    'rednet.cn', 'cbnmtv.com', 'guihet.com', 'qtv.com.cn'
}

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

def load_blacklist():
    """从 ad_blacklist.txt 加载黑名单"""
    blacklist = set(AD_BLACKLIST)
    try:
        with open(BLACKLIST_FILE, 'r', encoding='utf-8') as f:
            blacklist.update(line.strip() for line in f if line.strip())
        write_log(f"从 {BLACKLIST_FILE} 加载了 {len(blacklist)} 个黑名单条目")
    except FileNotFoundError:
        write_log(f"黑名单文件 {BLACKLIST_FILE} 未找到，使用默认黑名单")
    return blacklist

# --- 频道验证函数 ---
def is_likely_invalid(name, url):
    """检查 URL 是否在黑名单中"""
    blacklist = load_blacklist()
    for whitelisted in WHITELIST:
        if whitelisted in url.lower():
            return False
    for blacklisted in blacklist:
        if blacklisted in url.lower():
            write_log(f"  -> 黑名单命中: {url}")
            return True
    return False

def validate_channel_with_ffprobe(url, name, timeout, min_bitrate):
    """
    使用 ffprobe 验证单个 IPTV 频道 URL 的有效性和内容类型。
    返回 True 如果频道有效（有视频或音频，满足比特率要求），否则返回 False。
    """
    if not url or not url.startswith(('http://', 'https://')):
        write_log(f"  -> 无效URL格式或为空: {url}")
        return False

    if is_likely_invalid(name, url):
        return False

    command = [
        'ffprobe',
        '-v', 'error',
        '-show_entries', 'stream=codec_type,duration,bit_rate',
        '-of', 'default=noprint_wrappers=1:nokey=1',
        '-timeout', str(timeout * 1000000),
        url
    ]

    try:
        write_log(f"    正在运行 ffprobe for: {url}")
        start_time = time.monotonic()
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate(timeout=timeout)
        connect_duration = time.monotonic() - start_time

        if process.returncode != 0:
            if any(err in stderr for err in [
                "Not detecting m3u8/hls with non standard extension",
                "Invalid data found",
                "Server returned 404 Not Found",
                "Input/output error"
            ]):
                write_log(f"  -> 无效流或格式错误: {stderr.strip()}")
                return False
            write_log(f"  -> ffprobe 错误 (Exit Code {process.returncode}): {stderr.strip()}")
            return False

        if connect_duration > 20:
            write_log(f"  -> 连接时间过长 ({connect_duration:.2f}s) for {url}")
            return False

        write_log(f"    ffprobe 完成 ({connect_duration:.2f}s) for: {url}")

        has_video = False
        has_audio = False
        duration_looks_valid = True
        bit_rate_valid = True
        max_bit_rate = 0

        for line in stdout.splitlines():
            if 'codec_type=video' in line:
                has_video = True
            if 'codec_type=audio' in line:
                has_audio = True
            if 'duration=' in line:
                duration_str = line.split('duration=')[1].strip()
                if duration_str != 'N/A':
                    try:
                        duration = float(duration_str)
                        if duration < MIN_STREAM_DURATION_SECONDS:
                            duration_looks_valid = False
                    except ValueError:
                        duration_looks_valid = True
            if 'bit_rate=' in line:
                try:
                    bit_rate = float(line.split('bit_rate=')[1].strip()) / 1000  # 转换为 kbps
                    max_bit_rate = max(max_bit_rate, bit_rate)
                    if bit_rate < min_bitrate:
                        bit_rate_valid = False
                        write_log(f"  -> 比特率 {bit_rate:.2f}kbps 过低（要求 {min_bitrate}kbps） for {url}")
                except ValueError:
                    bit_rate_valid = True  # 忽略无法解析的比特率

        if (has_video or has_audio) and duration_looks_valid and bit_rate_valid:
            write_log(f"  -> 结果: 有效 (video={has_video}, audio={has_audio}, max_bit_rate={max_bit_rate:.2f}kbps)")
            return True
        else:
            write_log(f"  -> 失败: has_video={has_video}, has_audio={has_audio}, duration_looks_valid={duration_looks_valid}, bit_rate_valid={bit_rate_valid}, stdout: \n{stdout.strip()}\nstderr: \n{stderr.strip()}")
            return False

    except subprocess.TimeoutExpired as e:
        write_log(f"  -> ffprobe 超时 ({timeout}s) for {url}")
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
def process_iptv_list(args):
    global _global_log_file_handle

    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    _global_log_file_handle = open(LOG_FILE, 'w', encoding='utf-8')

    try:
        write_log(f"--- IPTV 频道验证开始 - {datetime.datetime.now()} ---")
        write_log(f"输入文件: {INPUT_FILE}")
        write_log(f"输出文件: {OUTPUT_FILE}")
        write_log(f"并发线程数: {args.max_workers}")
        write_log(f"ffprobe 超时: {args.timeout} 秒")
        write_log(f"最小直播流时长: {args.min_duration} 秒")
        write_log(f"最小比特率: {args.min_bitrate} kbps")
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
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.max_workers) as executor:
            future_to_channel = {
                executor.submit(validate_channel_with_ffprobe, url, name, args.timeout, args.min_bitrate): 
                (name, url, original_line_idx)
                for name, url, original_line_idx in channels_to_validate
            }
            
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
    parser = argparse.ArgumentParser(description='IPTV Channel Validator')
    parser.add_argument('--timeout', type=int, default=DEFAULT_FFPROBE_TIMEOUT_SECONDS, 
                        help='ffprobe timeout in seconds')
    parser.add_argument('--min-duration', type=int, default=DEFAULT_MIN_STREAM_DURATION_SECONDS, 
                        help='Minimum stream duration in seconds')
    parser.add_argument('--max-workers', type=int, default=DEFAULT_MAX_WORKERS, 
                        help='Maximum number of concurrent workers')
    parser.add_argument('--min-bitrate', type=int, default=DEFAULT_MIN_BITRATE_KBPS, 
                        help='Minimum bitrate in kbps')
    args = parser.parse_args()
    process_iptv_list(args)

# --- 可选：视频流广告检测（未启用） ---
# def check_ad_content(url):
#     test_file = f"temp_{time.time()}.ts"
#     command = [
#         'ffmpeg',
#         '-i', url,
#         '-t', '30',
#         '-vf', 'select=eq(pict_type\\,I)',
#         '-vsync', 'vfr',
#         '-f', 'null', '-'
#     ]
#     try:
#         process = subprocess.run(command, timeout=40, capture_output=True, text=True)
#         stderr_lines = process.stderr.splitlines()
#         frame_count = sum(1 for line in stderr_lines if 'frame=' in line)
#         if frame_count < 5:
#             write_log(f"  -> 疑似广告流（I 帧数量异常） for {url}")
#             return False
#         return True
#     except Exception as e:
#         write_log(f"  -> 广告检测错误 for {url}: {e}")
#         return True
#     finally:
#         if os.path.exists(test_file):
#             os.remove(test_file)
