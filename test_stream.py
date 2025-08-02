import os
import subprocess
import re
import datetime
import time
import threading
import hashlib
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# 定义线程锁以保护打印输出，避免多线程打印混乱
print_lock = threading.Lock()

def test_stream(channel_name, url, output_dir="output", timeout_seconds=15):
    """
    测试单个视频流，使用 ffprobe 并保存输出结果。
    参数:
        channel_name: 频道名称
        url: 视频流 URL
        output_dir: 输出目录
        timeout_seconds: 测试超时时间（秒）
    返回:
        包含测试结果的字典（名称、URL、状态、消息）
    """
    # 使用 MD5 哈希生成短文件名，结合频道名称
    filename = f"{channel_name}_{hashlib.md5(url.encode()).hexdigest()[:16]}"
    output_json_path = os.path.join(output_dir, f"{filename}.json")
    error_log_path = os.path.join(output_dir, f"{filename}_error.log")

    test_result = {
        "name": channel_name,
        "url": url,
        "status": "failed",
        "message": "未知错误"
    }

    try:
        # 构建 ffprobe 命令，超时时间与 subprocess 一致
        command = [
            "ffprobe",
            "-v", "quiet",
            "-print_format", "json",
            "-show_format",
            "-show_streams",
            "-stimeout", str(timeout_seconds * 1000000),  # 转换为微秒
            url
        ]
        
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout_seconds
        )
        
        # 保存 JSON 输出
        with open(output_json_path, "w", encoding="utf-8") as f:
            f.write(result.stdout)

        test_result["status"] = "success"
        test_result["message"] = f"成功测试 {url}。JSON 输出已保存到 {output_json_path}"
        with print_lock:
            print(f"成功测试 {url}. JSON 输出已保存到 {output_json_path}")

    except subprocess.CalledProcessError as e:
        with open(error_log_path, "w", encoding="utf-8") as f:
            f.write(f"测试 {url} 时出错:\n")
            f.write(f"命令: {' '.join(e.cmd)}\n")
            f.write(f"返回码: {e.returncode}\n")
            f.write(f"标准输出:\n{e.stdout or '无'}\n")
            f.write(f"标准错误:\n{e.stderr or '无'}\n")
        test_result["message"] = f"测试 {url} 时出错。错误日志已保存到 {error_log_path}"
        with print_lock:
            print(f"测试 {url} 时出错。错误日志已保存到 {error_log_path}")
    
    except subprocess.TimeoutExpired as e:
        with open(error_log_path, "w", encoding="utf-8") as f:
            f.write(f"测试 {url} 超时 ({timeout_seconds} 秒):\n")
            f.write(f"可能原因：网络连接慢、服务器无响应或流不可用\n")
            f.write(f"命令: {' '.join(e.cmd)}\n")
            f.write(f"标准输出:\n{e.stdout or '无'}\n")
            f.write(f"标准错误:\n{e.stderr or '无'}\n")
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
    解析 IPTV 列表内容，提取频道名称和 URL。
    参数:
        file_content: IPTV 列表文件内容
    返回:
        包含频道名称和 URL 的列表
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
    """主函数，执行 IPTV 视频流测试"""
    # 解析命令行参数
    parser = argparse.ArgumentParser(description="测试 IPTV 视频流")
    parser.add_argument("--workers", type=int, default=32, help="最大并行线程数")
    args = parser.parse_args()

    # 获取脚本所在目录和文件路径
    script_dir = os.path.dirname(__file__)
    iptv_list_path = os.path.join(script_dir, "iptv_list.txt")
    output_dir = os.path.join(script_dir, "output")
    output_list_path = os.path.join(output_dir, "list.txt")

    # 创建输出目录
    os.makedirs(output_dir, exist_ok=True)

    # 读取 IPTV 列表
    try:
        with open(iptv_list_path, "r", encoding="utf-8") as f:
            iptv_content = f.read()
    except FileNotFoundError:
        print(f"错误: 未找到 {iptv_list_path}。请确保 iptv_list.txt 文件与脚本在同一目录下。")
        return

    # 解析频道列表
    channels = parse_iptv_list(iptv_content)
    total_channels = len(channels)

    if not channels:
        print("在 iptv_list.txt 中未找到有效的视频源。")
        return

    print(f"找到 {total_channels} 个频道需要测试。")
    
    start_time_overall = time.time()
    
    # 统计结果和成功频道数据
    success_count = 0
    failed_channels = []
    successful_channels_data = []

    # 设置最大线程数
    max_workers = min(args.workers, total_channels)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有测试任务
        futures = {executor.submit(test_stream, channel["name"], channel["url"], output_dir): channel for channel in channels}
        
        completed_tasks = 0
        for future in as_completed(futures):
            completed_tasks += 1
            test_result = future.result()

            if test_result["status"] == "success":
                success_count += 1
                successful_channels_data.append(test_result)
            else:
                failed_channels.append(test_result["name"])
            
            # 计算并显示进度
            elapsed_time_overall = time.time() - start_time_overall
            avg_time_per_channel = elapsed_time_overall / completed_tasks if completed_tasks > 0 else 0
            remaining_tasks = total_channels - completed_tasks
            estimated_remaining_time = avg_time_per_channel * remaining_tasks

            progress_percentage = (completed_tasks / total_channels) * 100
            
            with print_lock:
                print(f"\n--- 进度: {progress_percentage:.2f}% ({completed_tasks}/{total_channels} 完成) ---")
                print(f"已运行: {format_time(elapsed_time_overall)} | 预计剩余: {format_time(estimated_remaining_time)}")

    # 保存成功频道到 output/list.txt
    if successful_channels_data:
        try:
            with open(output_list_path, "w", encoding="utf-8") as f:
                for channel in successful_channels_data:
                    f.write(f"{channel['name']},{channel['url']}\n")
            print(f"\n成功测试的频道已保存到 {output_list_path}")
        except Exception as e:
            print(f"\n写入 {output_list_path} 失败: {e}")
    else:
        print(f"\n没有成功测试的频道，未生成 {output_list_path}。")

    # 打印测试总结
    print("\n--- 测试完成总结 ---")
    final_elapsed_time = time.time() - start_time_overall
    print(f"总耗时: {format_time(final_elapsed_time)}")
    print(f"成功测试的频道数: {success_count}")
    print(f"失败测试的频道数: {len(failed_channels)}")
    if failed_channels:
        print("以下频道测试失败:")
        for name in failed_channels:
            print(f"- {name}")
    print("\n请检查 'output/' 目录中的 JSON 文件和错误日志以获取详细信息。")

if __name__ == "__main__":
    main()
