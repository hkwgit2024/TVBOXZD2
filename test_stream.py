import os
import subprocess
import re
import datetime
import time
from concurrent.futures import ThreadPoolExecutor, as_completed # 导入并发相关模块
import threading # 导入threading模块用于锁

# 使用锁来保护打印输出，避免多线程同时打印导致混乱
print_lock = threading.Lock()

def test_stream(url, output_dir="output", timeout_seconds=5):
    """
    测试单个视频流，使用ffprobe并保存输出结果。
    同时增加了超时处理。
    """
    # 清理URL以创建一个有效的文件名
    filename = re.sub(r'[^a-zA-Z0-9.-]', '_', url).replace('__', '_')
    if len(filename) > 200:
        filename = filename[:200] + "_hash" + str(hash(url) % 10000)

    output_path = os.path.join(output_dir, f"{filename}.json")
    error_path = os.path.join(output_dir, f"{filename}_error.log")

    test_result = {"url": url, "status": "failed", "message": "未知错误"}

    try:
        command = [
            "ffprobe",
            "-v", "quiet",
            "-print_format", "json",
            "-show_format",
            "-show_streams",
            "-stimeout", "5000000",  # 设置流读取超时时间为5秒（5000000微秒）
            url
        ]
        
        result = subprocess.run(command, capture_output=True, text=True, check=True, timeout=timeout_seconds)
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(result.stdout)
        
        test_result["status"] = "success"
        test_result["message"] = f"成功测试 {url}。输出已保存到 {output_path}"
        with print_lock:
            print(f"成功测试 {url}. 输出已保存到 {output_path}")

    except subprocess.CalledProcessError as e:
        with open(error_path, "w", encoding="utf-8") as f:
            f.write(f"测试 {url} 时出错:\n")
            f.write(f"命令: {' '.join(e.cmd)}\n")
            f.write(f"返回码: {e.returncode}\n")
            f.write(f"标准输出:\n{e.stdout}\n")
            f.write(f"标准错误:\n{e.stderr}\n")
        test_result["message"] = f"测试 {url} 时出错。错误日志已保存到 {error_path}"
        with print_lock:
            print(f"测试 {url} 时出错。错误日志已保存到 {error_path}")
    except subprocess.TimeoutExpired as e:
        with open(error_path, "w", encoding="utf-8") as f:
            f.write(f"测试 {url} 超时 ({timeout_seconds} 秒):\n")
            f.write(f"命令: {' '.join(e.cmd)}\n")
            f.write(f"标准输出:\n{e.stdout}\n")
            f.write(f"标准错误:\n{e.stderr}\n")
        test_result["message"] = f"测试 {url} 超时。错误日志已保存到 {error_path}"
        with print_lock:
            print(f"测试 {url} 超时。错误日志已保存到 {error_path}")
    except Exception as e:
        with open(error_path, "w", encoding="utf-8") as f:
            f.write(f"测试 {url} 时发生意外错误:\n")
            f.write(str(e))
        test_result["message"] = f"测试 {url} 时发生意外错误。错误日志已保存到 {error_path}"
        with print_lock:
            print(f"测试 {url} 时发生意外错误。错误日志已保存到 {error_path}")
    
    return test_result

def parse_iptv_list(file_content):
    """
    解析IPTV列表内容，提取频道名称和URL。
    """
    channels = []
    lines = file_content.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith(('#', '更新时间')):
            continue
        
        parts = line.split(',', 1)
        if len(parts) == 2:
            channel_name = parts[0].strip()
            url = parts[1].strip()
            if url.startswith(('http://', 'https://', 'rtp://', 'udp://')):
                channels.append({"name": channel_name, "url": url})
    return channels

def format_time(seconds):
    """格式化秒数为 H小时M分钟S秒"""
    m, s = divmod(int(seconds), 60)
    h, m = divmod(m, 60)
    return f"{h:02d}小时{m:02d}分钟{s:02d}秒" if h > 0 else f"{m:02d}分钟{s:02d}秒"

def main():
    script_dir = os.path.dirname(__file__)
    iptv_list_path = os.path.join(script_dir, "iptv_list.txt")
    output_dir = os.path.join(script_dir, "output")

    os.makedirs(output_dir, exist_ok=True)

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
    
    start_time_overall = time.time()
    
    # 用于统计结果
    success_count = 0
    failed_channels = []

    # 设置最大工作线程数，可以根据系统资源调整，例如CPU核心数*2
    # Setting max workers, can adjust based on system resources, e.g., CPU cores * 2
    max_workers = min(32, total_channels) # 避免创建过多线程，最多32个或频道总数

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务
        futures = {executor.submit(test_stream, channel["url"], output_dir): channel for channel in channels}
        
        # 跟踪完成的任务数，用于进度显示
        completed_tasks = 0
        for future in as_completed(futures):
            completed_tasks += 1
            channel_info = futures[future]
            try:
                result = future.result() # 获取测试结果
                if result["status"] == "success":
                    success_count += 1
                else:
                    failed_channels.append(channel_info["name"])
            except Exception as e:
                # 捕获线程执行时的异常，通常不应该发生，因为test_stream内部已处理
                with print_lock:
                    print(f"处理 {channel_info['name']} ({channel_info['url']}) 的结果时发生异常: {e}")
                failed_channels.append(channel_info["name"])
            
            # 计算并显示进度
            elapsed_time_overall = time.time() - start_time_overall
            
            # 这里的平均耗时计算会更准确，因为它基于实际完成任务的时间
            avg_time_per_channel = elapsed_time_overall / completed_tasks if completed_tasks > 0 else 0
            remaining_tasks = total_channels - completed_tasks
            estimated_remaining_time = avg_time_per_channel * remaining_tasks

            progress_percentage = (completed_tasks / total_channels) * 100
            
            with print_lock: # 使用锁确保打印输出的原子性
                print(f"\n--- 进度: {progress_percentage:.2f}% ({completed_tasks}/{total_channels} 完成) ---")
                print(f"已运行: {format_time(elapsed_time_overall)} | 预计剩余: {format_time(estimated_remaining_time)}")

    print("\n--- 测试完成总结 ---")
    final_elapsed_time = time.time() - start_time_overall
    print(f"总耗时: {format_time(final_elapsed_time)}")
    print(f"成功测试的频道数: {success_count}")
    print(f"失败测试的频道数: {len(failed_channels)}")
    if failed_channels:
        print("以下频道测试失败:")
        for name in failed_channels:
            print(f"- {name}")
    print("\n请检查 'output/' 目录中的JSON文件和错误日志以获取详细信息。")

if __name__ == "__main__":
    main()
