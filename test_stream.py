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

def test_stream(channel_name, url, output_dir="output", timeout_seconds=15, response_threshold=5):
    """
    测试单个视频流，使用 ffprobe 并检查流可用性。
    参数:
        channel_name: 频道名称
        url: 视频流 URL
        output_dir: 输出目录
        timeout_seconds: 测试总超时时间（秒）
        response_threshold: 响应时间阈值（秒），用于判断缓冲速度
    返回:
        包含测试结果的字典（名称、URL、状态、可用性、消息、详细错误信息）
    """
    # 使用 MD5 哈希生成短文件名，结合频道名称
    filename = f"{channel_name}_{hashlib.md5(url.encode()).hexdigest()[:16]}"
    output_json_path = os.path.join(output_dir, f"{filename}.json")

    test_result = {
        "name": channel_name,
        "url": url,
        "status": "failed",
        "availability": "不可用",
        "message": "未知错误",
        "full_error_details": ""
    }

    start_time = time.time()
    try:
        # 构建 ffprobe 命令，恢复 JSON 输出
        command = [
            "ffprobe",
            "-v", "quiet",
            "-print_format", "json",
            "-show_format",
            "-show_streams",
            "-read_intervals", "%+5",  # 读取前 5 秒数据
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
        
        # 计算响应时间
        response_time = time.time() - start_time

        # 检查是否有有效的视频流（包含视频流且编码格式为常见类型）
        # 这里的判断逻辑重新基于 JSON 输出
        valid_codecs = ["h264", "h265", "hevc", "mpeg4", "vp8", "vp9"]
        if ("streams" not in result.stdout or 
            '"codec_type": "video"' not in result.stdout or
            not any(codec in result.stdout.lower() for codec in valid_codecs)):
            test_result["message"] = f"测试 {url} 成功但无有效视频流或不支持的编码格式。JSON 输出已保存到 {output_json_path}"
            test_result["availability"] = "不可用"
            with print_lock:
                print(f"测试 {url} 成功但无有效视频流或不支持的编码格式。JSON 输出已保存到 {output_json_path}")
            test_result["full_error_details"] = (
                f"--- 频道: {channel_name} (URL: {url}) ---\n"
                f"状态: 成功但无有效视频流或不支持的编码格式\n"
                f"消息: {test_result['message']}\n"
                f"响应时间: {response_time:.2f}秒\n"
                f"ffprobe stdout:\n{result.stdout or '无'}\n"
                f"ffprobe stderr:\n{result.stderr or '无'}\n"
                f"----------------------------------------\n\n"
            )
        else:
            # 检查响应时间是否过长
            if response_time > response_threshold:
                test_result["message"] = f"测试 {url} 成功但缓冲过慢（{response_time:.2f}秒）。JSON 输出已保存到 {output_json_path}"
                test_result["availability"] = "缓冲过慢"
                with print_lock:
                    print(f"测试 {url} 成功但缓冲过慢（{response_time:.2f}秒）。JSON 输出已保存到 {output_json_path}")
                test_result["full_error_details"] = (
                    f"--- 频道: {channel_name} (URL: {url}) ---\n"
                    f"状态: 缓冲过慢\n"
                    f"消息: {test_result['message']}\n"
                    f"响应时间: {response_time:.2f}秒\n"
                    f"ffprobe stdout:\n{result.stdout or '无'}\n"
                    f"ffprobe stderr:\n{result.stderr or '无'}\n"
                    f"----------------------------------------\n\n"
                )
            else:
                test_result["status"] = "success"
                test_result["availability"] = "完全可用"
                test_result["message"] = f"成功测试 {url}（响应时间 {response_time:.2f}秒）。JSON 输出已保存到 {output_json_path}"
                with print_lock:
                    print(f"成功测试 {url}（响应时间 {response_time:.2f}秒）。JSON 输出已保存到 {output_json_path}")

        # 重新保存 JSON 输出
        with open(output_json_path, "w", encoding="utf-8") as f:
            f.write(result.stdout)

    except subprocess.CalledProcessError as e:
        test_result["message"] = f"测试 {url} 时出错。"
        test_result["full_error_details"] = (
            f"--- 频道: {channel_name} (URL: {url}) ---\n"
            f"状态: 命令执行错误\n"
            f"消息: {test_result['message']}\n"
            f"命令: {' '.join(e.cmd)}\n"
            f"返回码: {e.returncode}\n"
            f"ffprobe stdout:\n{e.stdout or '无'}\n"
            f"ffprobe stderr:\n{e.stderr or '无'}\n"
            f"----------------------------------------\n\n"
        )
        with print_lock:
            print(f"测试 {url} 时出错。")
    
    except subprocess.TimeoutExpired as e:
        test_result["message"] = f"测试 {url} 超时 ({timeout_seconds} 秒)。"
        test_result["full_error_details"] = (
            f"--- 频道: {channel_name} (URL: {url}) ---\n"
            f"状态: 超时\n"
            f"消息: {test_result['message']}\n"
            f"可能原因：网络连接慢、服务器无响应或流不可用\n"
            f"命令: {' '.join(e.cmd)}\n"
            f"ffprobe stdout:\n{e.stdout or '无'}\n"
            f"ffprobe stderr:\n{e.stderr or '无'}\n"
            f"----------------------------------------\n\n"
        )
        with print_lock:
            print(f"测试 {url} 超时。")
    
    except Exception as e:
        test_result["message"] = f"测试 {url} 时发生意外错误。"
        test_result["full_error_details"] = (
            f"--- 频道: {channel_name} (URL: {url}) ---\n"
            f"状态: 意外错误\n"
            f"消息: {test_result['message']}\n"
            f"错误详情: {str(e)}\n"
            f"----------------------------------------\n\n"
        )
        with print_lock:
            print(f"测试 {url} 时发生意外错误。")
    
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
    parser.add_argument("--timeout", type=int, default=15, help="单个流测试总超时时间（秒）")
    parser.add_argument("--response-threshold", type=int, default=5, help="响应时间阈值（秒），用于判断缓冲速度")
    args = parser.parse_args()

    # 验证命令行参数
    if args.timeout < 1:
        print("错误: 超时时间 (--timeout) 必须大于 0。")
        return
    if args.response_threshold < 1 or args.response_threshold >= args.timeout:
        print(f"错误: 响应时间阈值 (--response-threshold) 必须在 1 到 {args.timeout-1} 秒之间。")
        return
    if args.workers < 1:
        print("错误: 线程数 (--workers) 必须大于 0。")
        return

    # 获取脚本所在目录和文件路径
    script_dir = os.path.dirname(__file__)
    iptv_list_path = os.path.join(script_dir, "iptv_list.txt")
    output_dir = os.path.join(script_dir, "output")
    output_list_path = os.path.join(output_dir, "list.txt")
    all_errors_log_path = os.path.join(output_dir, "all_errors.log")

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
    all_channels = parse_iptv_list(iptv_content)
    total_initial_channels = len(all_channels)

    channels_to_test = []
    excluded_channels_count = 0
    excluded_urls = ["https://epg.pw/"]

    # 过滤频道
    for channel in all_channels:
        is_excluded = False
        for prefix in excluded_urls:
            if channel["url"].startswith(prefix):
                is_excluded = True
                excluded_channels_count += 1
                break
        if not is_excluded:
            channels_to_test.append(channel)

    total_channels_to_test = len(channels_to_test)

    if not channels_to_test:
        print("未找到需要测试的有效视频源。")
        if excluded_channels_count > 0:
            print(f"已排除 {excluded_channels_count} 个频道 (URL 以 {', '.join(excluded_urls)} 开头)。")
        return

    print(f"找到 {total_initial_channels} 个频道。")
    if excluded_channels_count > 0:
        print(f"已排除 {excluded_channels_count} 个频道 (URL 以 {', '.join(excluded_urls)} 开头)。")
    print(f"将测试 {total_channels_to_test} 个频道。")
    
    start_time_overall = time.time()
    
    # 统计结果和成功频道数据
    success_fully_available_count = 0
    slow_channels = []
    failed_channels = []
    successful_channels_data = []
    all_error_details = []

    # 设置最大线程数
    max_workers = min(args.workers, total_channels_to_test)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 提交所有测试任务
        futures = {executor.submit(test_stream, channel["name"], channel["url"], output_dir, args.timeout, args.response_threshold): channel for channel in channels_to_test}
        
        completed_tasks = 0
        for future in as_completed(futures):
            completed_tasks += 1
            test_result = future.result()

            if test_result["status"] == "success":
                if test_result["availability"] == "完全可用":
                    success_fully_available_count += 1
                    successful_channels_data.append(test_result)
                elif test_result["availability"] == "缓冲过慢":
                    slow_channels.append(test_result["name"])
                    if test_result["full_error_details"]:
                        all_error_details.append(test_result["full_error_details"])
            else:
                failed_channels.append(test_result["name"])
                if test_result["full_error_details"]:
                    all_error_details.append(test_result["full_error_details"])
            
            # 计算并显示进度
            elapsed_time_overall = time.time() - start_time_overall
            avg_time_per_channel = elapsed_time_overall / completed_tasks if completed_tasks > 0 else 0
            remaining_tasks = total_channels_to_test - completed_tasks
            estimated_remaining_time = avg_time_per_channel * remaining_tasks

            progress_percentage = (completed_tasks / total_channels_to_test) * 100
            
            with print_lock:
                print(f"\n--- 进度: {progress_percentage:.2f}% ({completed_tasks}/{total_channels_to_test} 完成) ---")
                print(f"已运行: {format_time(elapsed_time_overall)} | 预计剩余: {format_time(estimated_remaining_time)}")

    # 保存完全可用的频道到 output/list.txt
    if successful_channels_data:
        try:
            with open(output_list_path, "w", encoding="utf-8") as f:
                f.write(f"更新时间,{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')},url\n")
                for channel in successful_channels_data:
                    f.write(f"{channel['name']},{channel['url']}\n")
            print(f"\n完全可用的频道已保存到 {output_list_path}")
        except Exception as e:
            print(f"\n写入 {output_list_path} 失败: {e}")
    else:
        print(f"\n没有完全可用的频道，未生成 {output_list_path}。")

    # 写入所有错误到 all_errors.log
    if all_error_details:
        try:
            with open(all_errors_log_path, "w", encoding="utf-8") as f:
                f.write(f"--- IPTV 视频流测试错误汇总 ({datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}) ---\n\n")
                for error_detail in all_error_details:
                    f.write(error_detail)
            print(f"所有错误详情已保存到 {all_errors_log_path}")
        except Exception as e:
            print(f"\n写入 {all_errors_log_path} 失败: {e}")
    else:
        print("\n没有记录到任何错误详情。")

    # 打印测试总结
    print("\n--- 测试完成总结 ---")
    final_elapsed_time = time.time() - start_time_overall
    print(f"总耗时: {format_time(final_elapsed_time)}")
    print(f"原始频道总数: {total_initial_channels}")
    print(f"已排除频道数 (URL 以 {', '.join(excluded_urls)} 开头): {excluded_channels_count}")
    print(f"实际测试频道数: {total_channels_to_test}")
    print(f"完全可用的频道数: {success_fully_available_count}")
    print(f"缓冲过慢的频道数: {len(slow_channels)}")
    print(f"不可用的频道数: {len(failed_channels)}")
    if slow_channels:
        print("以下频道缓冲过慢:")
        for name in slow_channels:
            print(f"- {name}")
    if failed_channels:
        print("以下频道不可用:")
        for name in failed_channels:
            print(f"- {name}")
    print(f"\n请检查 'output/' 目录中的 JSON 文件和 {all_errors_log_path} 以获取详细信息。")

if __name__ == "__main__":
    main()
