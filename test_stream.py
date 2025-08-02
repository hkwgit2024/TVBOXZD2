import os
import subprocess
import re
import datetime
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

# 使用锁来保护打印输出，避免多线程同时打印导致混乱
print_lock = threading.Lock()

def test_stream(channel_name, url, output_dir="output", timeout_seconds=5): # 增加 channel_name 参数
    """
    测试单个视频流，使用ffprobe并保存输出结果。
    同时增加了超时处理。
    """
    # 清理URL以创建一个有效的文件名
    filename = re.sub(r'[^a-zA-Z0-9.-]', '_', url).replace('__', '_')
    if len(filename) > 200:
        filename = filename[:200] + "_hash" + str(hash(url) % 10000)

    output_json_path = os.path.join(output_dir, f"{filename}.json")
    error_log_path = os.path.join(output_dir, f"{filename}_error.log")

    test_result = {"name": channel_name, "url": url, "status": "failed", "message": "未知错误"} # 返回结果包含名称和URL

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
        
        with open(output_json_path, "w", encoding="utf-8") as f:
            f.write(result.stdout)
        
        test_result["status"] = "success"
        test_result["message"] = f"成功测试 {url}。JSON输出已保存到 {output_json_path}"
        with print_lock:
            print(f"成功测试 {url}. JSON输出已保存到 {output_json_path}")

    except subprocess.CalledProcessError as e:
        with open(error_log_path, "w", encoding="utf-8") as f:
            f.write(f"测试 {url} 时出错:\n")
            f.write(f"命令: {' '.join(e.cmd)}\n")
            f.write(f"返回码: {e.returncode}\n")
            f.write(f"标准输出:\n{e.stdout}\n")
            f.write(f"标准错误:\n{e.stderr}\n")
        test_result["message"] = f"测试 {url} 时出错。错误日志已保存到 {error_log_path}"
        with print_lock:
            print(f"测试 {url} 时出错。错误日志已保存到 {error_log_path}")
    except subprocess.TimeoutExpired as e:
        with open(error_log_path, "w", encoding="utf-8") as f:
            f.write(f"测试 {url} 超时 ({timeout_seconds} 秒):\n")
            f.write(f"命令: {' '.join(e.cmd)}\n")
            f.write(f"标准输出:\n{e.stdout}\n")
            f.write(f"标准错误:\n{e.stderr}\n")
        test_result["message"] = f"测试 {url} 超时。错误日志已保存到 {error_log_path}"
        with print_lock:
            print(f"测试 {url} 超时。错误日志已保存到 {error_log_path}")
    except Exception as e:
        with open(error_log_path, "w", encoding="utf-8") as f:
            f.write(f"测试 {url} 时发生意外错误:\n")
            f.write(str(e))
        test_result["message"] = f"测试 {url} 时发生意外错误。错误日志已保存到 {error_log_path}"
        with print_lock:
            print(f"测试 {url} 时发生意外错误。错误日志已保存到 {error_log_path}")
    
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
    output_list_path = os.path.join(output_dir, "list.txt") # 新增输出列表文件路径

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
    
    # 用于统计结果和保存成功频道数据
    success_count = 0
    failed_channels = []
    successful_channels_data = [] # 新增：存储成功频道的名称和URL

    max_workers = min(32, total_channels)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有任务，future映射到原始的频道信息
        futures = {executor.submit(test_stream, channel["name"], channel["url"], output_dir): channel for channel in channels}
        
        completed_tasks = 0
        for future in as_completed(futures):
            completed_tasks += 1
            # 从future的返回值中获取完整的测试结果，包括状态
            test_result = future.result() 

            if test_result["status"] == "success":
                success_count += 1
                successful_channels_data.append({"name": test_result["name"], "url": test_result["url"]}) # 收集成功频道
            else:
                failed_channels.append(test_result["name"]) # 失败频道只记录名称
            
            # 计算并显示进度
            elapsed_time_overall = time.time() - start_time_overall
            
            avg_time_per_channel = elapsed_time_overall / completed_tasks if completed_tasks > 0 else 0
            remaining_tasks = total_channels - completed_tasks
            estimated_remaining_time = avg_time_per_channel * remaining_tasks

            progress_percentage = (completed_tasks / total_channels) * 100
            
            with print_lock:
                print(f"\n--- 进度: {progress_percentage:.2f}% ({completed_tasks}/{total_channels} 完成) ---")
                print(f"已运行: {format_time(elapsed_time_overall)} | 预计剩余: {format_time(estimated_remaining_time)}")

    # 所有任务完成后，将成功频道写入 output/list.txt
    if successful_channels_data:
        try:
            with open(output_list_path, "w", encoding="utf-8") as f:
                # 写入更新时间行，可以根据需要调整格式
                f.write(f"更新时间,{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')},url\n") 
                for channel in successful_channels_data:
                    f.write(f"{channel['name']},{channel['url']}\n")
            print(f"\n成功测试的频道已保存到 {output_list_path}")
        except Exception as e:
            print(f"\n写入 {output_list_path} 失败: {e}")
    else:
        print(f"\n没有成功测试的频道，未生成 {output_list_path}。")


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
