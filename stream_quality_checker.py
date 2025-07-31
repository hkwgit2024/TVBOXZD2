import re
import subprocess
import os
import datetime

# 输入和输出文件路径
INPUT_FILE = 'output/iptv_list.txt'
OUTPUT_FILE = 'output/high_quality_iptv.txt'
LOG_FILE = 'output/iptv_validation.log' # 用于记录验证结果和错误

# 频道验证函数
def validate_channel(url):
    """
    使用 ffprobe 验证 IPTV 频道 URL 的有效性和内容类型。
    返回 True 如果频道看起来有效且不是广告/重复片段，否则返回 False。
    """
    if not url.startswith(('http://', 'https://')):
        return False # 仅处理 HTTP/HTTPS 链接

    # ffprobe 命令
    # -v error: 只输出错误信息
    # -show_entries stream=codec_type,duration,nb_frames: 显示流的编解码类型、时长和帧数
    # -of default=noprint_wrappers=1:nokey=1: 输出格式为键值对，不打印包裹器和键名
    # -timeout 5000000: 设置超时为5秒（微秒）
    # -i: 指定输入URL
    command = [
        'ffprobe',
        '-v', 'error',
        '-show_entries', 'stream=codec_type,duration', # 检查编解码类型和时长
        '-of', 'default=noprint_wrappers=1:nokey=1',
        '-timeout', '5000000', # 5秒超时
        url
    ]

    try:
        # 运行 ffprobe 命令并捕获输出
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=10)
        output = result.stdout

        # 检查输出中是否有视频或音频流
        has_video_or_audio = False
        duration_valid = False

        for line in output.splitlines():
            if 'codec_type=video' in line or 'codec_type=audio' in line:
                has_video_or_audio = True
            if 'duration=' in line:
                try:
                    duration_str = line.split('duration=')[1].strip()
                    duration = float(duration_str)
                    # 对于直播流，duration 通常会显示为 "N/A" 或一个非常大的数字
                    # 如果 duration 很小，比如小于 30 秒，可能是一个短片或广告
                    if duration > 30 or duration_str == 'N/A': # 设定一个阈值，直播流不会有明确短时长
                        duration_valid = True
                except ValueError:
                    duration_valid = True # 无法解析时长，但如果流存在，也认为是有效的

        # 简单的判断逻辑：有视频或音频流且时长看起来有效
        return has_video_or_audio and duration_valid

    except subprocess.CalledProcessError as e:
        print(f"Error validating {url}: {e.stderr.strip()}")
        return False
    except subprocess.TimeoutExpired:
        print(f"Timeout validating {url}")
        return False
    except FileNotFoundError:
        print("Error: ffprobe not found. Please ensure FFmpeg is installed and in your system's PATH.")
        return False
    except Exception as e:
        print(f"An unexpected error occurred for {url}: {e}")
        return False

# 主处理逻辑
def process_iptv_list():
    good_channels = []
    current_genre = "未知分类"
    
    # 确保 output 目录存在
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
    
    # 打开日志文件
    with open(LOG_FILE, 'w', encoding='utf-8') as log_f:
        log_f.write(f"IPTV 频道验证日志 - {datetime.datetime.now()}\n\n")

        with open(INPUT_FILE, 'r', encoding='utf-8') as f:
            lines = f.readlines()

        # 添加文件头，包括更新时间
        good_channels.append(f"更新时间,{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue

            # 忽略文件顶部的更新时间行
            if i == 0 and "更新时间" in line and "#genre#" in line:
                continue

            if "#genre#" in line:
                # 这是一个分类行
                genre_match = re.match(r'^(.*?),\#genre\#', line)
                if genre_match:
                    current_genre = genre_match.group(1).strip()
                    good_channels.append(line) # 将分类行也添加到高质量列表中
                continue

            parts = line.split(',', 1) # 只分割一次，以防URL中包含逗号
            if len(parts) == 2:
                channel_name = parts[0].strip()
                channel_url = parts[1].strip()

                log_f.write(f"正在验证 [{current_genre}] {channel_name}: {channel_url}\n")
                print(f"正在验证 [{current_genre}] {channel_name}: {channel_url}")

                if validate_channel(channel_url):
                    good_channels.append(line)
                    log_f.write(f"  -> 有效\n")
                    print(f"  -> 有效")
                else:
                    log_f.write(f"  -> 无效或低质量\n")
                    print(f"  -> 无效或低质量")
            else:
                log_f.write(f"跳过格式错误行: {line}\n")
                print(f"跳过格式错误行: {line}")

        # 写入高质量列表到文件
        with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
            for channel in good_channels:
                f.write(channel + '\n')

    print(f"\n高质量 IPTV 列表已保存到 {OUTPUT_FILE}")
    print(f"验证日志已保存到 {LOG_FILE}")

if __name__ == "__main__":
    process_iptv_list()
