import os
import subprocess
import re
import datetime
import time # 导入time模块用于计算耗时

def test_stream(url, output_dir="output", timeout_seconds=5): # timeout_seconds默认为5秒
    """
    测试单个视频流，使用ffprobe并保存输出结果。
    Tests a single video stream using ffprobe and saves the output.
    """
    # 清理URL以创建一个有效的文件名
    # Sanitize URL to create a valid filename
    filename = re.sub(r'[^a-zA-Z0-9.-]', '_', url).replace('__', '_')
    if len(filename) > 200: # 限制文件名长度
        filename = filename[:200] + "_hash" + str(hash(url) % 10000)

    output_path = os.path.join(output_dir, f"{filename}.json")
    error_path = os.path.join(output_dir, f"{filename}_error.log")

    try:
        command = [
            "ffprobe",
            "-v", "quiet",           # -v quiet: 设置日志级别为静默，不显示不重要的信息
            "-print_format", "json", # -print_format json: 以JSON格式打印输出
            "-show_format",          # -show_format: 显示多媒体文件的格式信息
            "-show_streams",         # -show_streams: 显示多媒体文件中的所有流信息（视频、音频、字幕等）
            "-stimeout", "5000000",  # -stimeout 5000000: 设置流读取超时时间为5秒（5000000微秒），用于连接和读取初始数据
            url
        ]
        
        # 通过subprocess.run的timeout参数设置命令执行超时时间
        # 同时ffprobe内部也设置了-stimeout，确保在网络连接层面也快速超时
        # Set command execution timeout via subprocess.run's timeout parameter
        # ffprobe's internal -stimeout is also set for faster network connection timeout
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=timeout_seconds)
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(result.stdout)
        print(f"成功测试 {url}。输出已保存到 {output_path}")

    except subprocess.CalledProcessError as e:
        with open(error_path, "w", encoding="utf-8") as f:
            f.write(f"测试 {url} 时出错:\n")
            f.write(f"命令: {' '.join(e.cmd)}\n")
            f.write(f"返回码: {e.returncode}\n")
            f.write(f"标准输出:\n{e.stdout}\n")
            f.write(f"标准错误:\n{e.stderr}\n")
        print(f"测试 {url} 时出错。错误日志已保存到 {error_path}")
    except subprocess.TimeoutExpired as e: # 捕获超时异常
        with open(error_path, "w", encoding="utf-8") as f:
            f.write(f"测试 {url} 超时 ({timeout_seconds} 秒):\n")
            f.write(f"命令: {' '.join(e.cmd)}\n")
            f.write(f"标准输出:\n{e.stdout}\n")
            f.write(f"标准错误:\n{e.stderr}\n")
        print(f"测试 {url} 超时。错误日志已保存到 {error_path}")
    except Exception as e:
        with open(error_path, "w", encoding="utf-8") as f:
            f.write(f"测试 {url} 时发生意外错误:\n")
            f.write(str(e))
        print(f"测试 {url} 时发生意外错误。错误日志已保存到 {error_path}")

def parse_iptv_list(file_content):
    """
    解析IPTV列表内容，提取频道名称和URL。
    Parses the IPTV list content and extracts channel names and URLs.
    """
    channels = []
    lines = file_content.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith(('#', '更新时间')): # 忽略空行或以'#'、'更新时间'开头的行
            continue
        
        parts = line.split(',', 1) # 仅在第一个逗号处分割
        if len(parts) == 2:
            channel_name = parts[0].strip()
            url = parts[1].strip()
            # 基础URL验证
            if url.startswith(('http://', 'https://', 'rtp://', 'udp://')):
                channels.append((channel_name, url))
    return channels

def main():
    script_dir = os.path.dirname(__file__)
    iptv_list_path = os.path.join(script_dir, "iptv_list.txt")
    output_dir = os.path.join(script_dir, "output")

    os.makedirs(output_dir, exist_ok=True) # 创建输出目录（如果不存在）

    try:
        with open(iptv_list_path, "r", encoding="utf-8") as f:
            iptv_content = f.read()
    except FileNotFoundError:
        print(f"错误: 未找到 {iptv_list_path}。请确保 iptv_list.txt 文件与脚本在同一目录下。")
        return

    channels = parse_iptv_list(iptv_content)
    total_channels = len(channels)

    if not channels:
        print("在 iptv_list.txt 中未找到有效的视频源。")
        return

    print(f"找到 {total_channels} 个频道需要测试。")
    
    start_time_overall = time.time() # 记录整体开始时间

    for i, (name, url) in enumerate(channels):
        current_channel_index = i + 1
        print(f"\n--- 正在测试频道 {current_channel_index}/{total_channels}: {name} - {url} ---")
        
        # 默认超时时间为5秒，如果需要为某个特定流设置不同超时，可以在这里修改
        test_stream(url, output_dir, timeout_seconds=5) 
        
        # 计算并显示进度
        elapsed_time_overall = time.time() - start_time_overall # 已运行时间
        avg_time_per_channel = elapsed_time_overall / current_channel_index if current_channel_index > 0 else 0
        remaining_channels = total_channels - current_channel_index
        estimated_remaining_time = avg_time_per_channel * remaining_channels # 预计剩余时间

        # 格式化时间显示
        def format_time(seconds):
            m, s = divmod(int(seconds), 60)
            h, m = divmod(m, 60)
            return f"{h:02d}小时{m:02d}分钟{s:02d}秒" if h > 0 else f"{m:02d}分钟{s:02d}秒"

        progress_percentage = (current_channel_index / total_channels) * 100
        print(f"进度: {progress_percentage:.2f}% | 已运行: {format_time(elapsed_time_overall)} | 预计剩余: {format_time(estimated_remaining_time)}")

    print("\n测试完成。")
    final_elapsed_time = time.time() - start_time_overall
    print(f"所有频道测试完毕。总耗时: {format_time(final_elapsed_time)}")

if __name__ == "__main__":
    main()
