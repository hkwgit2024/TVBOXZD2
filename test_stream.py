import os
import subprocess
import json
import datetime
import time
import threading
import hashlib
import argparse
import requests # This is already imported
from concurrent.futures import ThreadPoolExecutor, as_completed

# 定义线程锁以保护打印输出，避免多线程打印混乱
print_lock = threading.Lock()

def test_stream(channel_name, url, output_dir="output", timeout_seconds=15, response_threshold=5, retries=1):
    """
    测试单个视频流，首先进行 HTTP HEAD 请求筛选，然后使用 ffprobe 并检查流可用性。
    参数:
        channel_name: 频道名称
        url: 视频流 URL
        output_dir: 输出目录
        timeout_seconds: 测试总超时时间（秒）
        response_threshold: 响应时间阈值（秒），用于判断缓冲速度
        retries: 重试次数
    返回:
        包含测试结果的字典（名称、URL、状态、可用性、消息、详细错误信息）
    """
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

    # --- Step 1: Initial HTTP HEAD request pre-screening ---
    for attempt_head in range(retries + 1): # 增加重试机制
        try:
            head_start_time = time.time()
            # 使用 requests.head 进行快速检查。对 HEAD 请求设置较短的超时时间。
            headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
            head_response = requests.head(url, timeout=5, allow_redirects=True, headers=headers)
            head_response_time = time.time() - head_start_time

            if head_response.status_code in [404, 403]:
                test_result["message"] = f"URL 返回 HTTP 状态码 {head_response.status_code}，标记为不可用 (尝试 {attempt_head + 1}/{retries + 1})。"
                test_result["full_error_details"] = (
                    f"--- 频道: {channel_name} (URL: {url}) ---\n"
                    f"状态: HTTP HEAD 检查失败\n"
                    f"消息: {test_result['message']}\n"
                    f"HTTP 状态码: {head_response.status_code}\n"
                    f"响应时间: {head_response_time:.2f}秒\n"
                    f"----------------------------------------\n\n"
                )
                with print_lock:
                    print(f"URL: {url} 返回 HTTP 状态码 {head_response.status_code}，标记为不可用。")
                return test_result # 直接返回失败

            # 如果 HEAD 请求成功 (2xx) 或其他状态，则继续 ffprobe
            if head_response.status_code >= 200 and head_response.status_code < 300:
                with print_lock:
                    print(f"URL: {url} HEAD 检查通过 (状态码: {head_response.status_code})。继续 ffprobe 测试...")
                break # 退出 HEAD 重试循环，继续 ffprobe 测试
            else:
                test_result["message"] = f"URL 返回非 2xx 状态码 {head_response.status_code}，但不是 404/403 (尝试 {attempt_head + 1}/{retries + 1})。"
                test_result["full_error_details"] = (
                    f"--- 频道: {channel_name} (URL: {url}) ---\n"
                    f"状态: HTTP HEAD 非 2xx 状态\n"
                    f"消息: {test_result['message']}\n"
                    f"HTTP 状态码: {head_response.status_code}\n"
                    f"响应时间: {head_response_time:.2f}秒\n"
                    f"----------------------------------------\n\n"
                )
                if attempt_head == retries:
                    with print_lock:
                        print(f"URL: {url} 返回非 2xx 状态码 {head_response.status_code}，标记为不可用。")
                    return test_result # 在所有 HEAD 重试后返回失败
                else:
                    time.sleep(1) # 短暂延迟后重试 HEAD
                    continue

        except requests.exceptions.Timeout:
            test_result["message"] = f"HEAD 请求超时 ({5} 秒，尝试 {attempt_head + 1}/{retries + 1})。"
            test_result["full_error_details"] = (
                f"--- 频道: {channel_name} (URL: {url}) ---\n"
                f"状态: HEAD 请求超时\n"
                f"消息: {test_result['message']}\n"
                f"可能原因：网络连接慢、服务器无响应\n"
                f"----------------------------------------\n\n"
            )
            with print_lock:
                print(f"HEAD 请求 {url} 超时。")
            if attempt_head == retries:
                return test_result # 在所有 HEAD 重试后返回失败
            else:
                time.sleep(1) # 短暂延迟后重试 HEAD
                continue
        except requests.exceptions.RequestException as e:
            test_result["message"] = f"HEAD 请求发生网络错误（尝试 {attempt_head + 1}/{retries + 1}）。"
            test_result["full_error_details"] = (
                f"--- 频道: {channel_name} (URL: {url}) ---\n"
                f"状态: HEAD 请求网络错误\n"
                f"消息: {test_result['message']}\n"
                f"错误详情: {str(e)}\n"
                f"----------------------------------------\n\n"
            )
            with print_lock:
                print(f"HEAD 请求 {url} 发生网络错误。")
            if attempt_head == retries:
                return test_result # 在所有 HEAD 重试后返回失败
            else:
                time.sleep(1) # 短暂延迟后重试 HEAD
                continue
    
    # --- Step 2: Proceed with ffprobe if HEAD request passed ---
    # 现有的 ffprobe 逻辑从这里开始。
    for attempt in range(retries + 1):
        start_time = time.time()
        try:
            command = [
                "ffprobe",
                "-v", "quiet",
                "-print_format", "json",
                "-show_format",
                "-show_streams",
                "-read_intervals", "%+5",
                "-stimeout", str(timeout_seconds * 1000000),
                "-headers", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                url
            ]
            
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True,
                timeout=timeout_seconds
            )
            
            response_time = time.time() - start_time
            json_data = json.loads(result.stdout) if result.stdout else {}

            valid_codecs = ["h264", "h265", "hevc", "mpeg4", "vp8", "vp9"]
            has_valid_video = False
            for stream in json_data.get("streams", []):
                if stream.get("codec_type") == "video" and stream.get("codec_name") in valid_codecs:
                    has_valid_video = True
                    break

            # 如果没有有效视频流，尝试解析 .m3u8 文件 (original logic)
            if not has_valid_video and url.endswith(".m3u8"):
                try:
                    m3u8_response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=5)
                    m3u8_response.raise_for_status()
                    m3u8_content = m3u8_response.text
                    m3u8_lines = m3u8_content.splitlines()
                    for line in m3u8_lines:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            sub_url = line if line.startswith("http") else url.rsplit("/", 1)[0] + "/" + line
                            sub_command = command[:-1] + [sub_url]
                            try:
                                sub_result = subprocess.run(
                                    sub_command,
                                    capture_output=True,
                                    text=True,
                                    check=True,
                                    timeout=timeout_seconds
                                )
                                sub_json = json.loads(sub_result.stdout) if sub_result.stdout else {}
                                for stream in sub_json.get("streams", []):
                                    if stream.get("codec_type") == "video" and stream.get("codec_name") in valid_codecs:
                                        has_valid_video = True
                                        result = sub_result
                                        break
                                if has_valid_video:
                                    break
                            except Exception:
                                continue
                except Exception as m3u8_e:
                    test_result["full_error_details"] += f"m3u8 解析错误: {str(m3u8_e)}\n"

            if not has_valid_video:
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

            with open(output_json_path, "w", encoding="utf-8") as f:
                f.write(result.stdout)
            break

        except subprocess.CalledProcessError as e:
            test_result["message"] = f"测试 {url} 时出错（尝试 {attempt + 1}/{retries + 1}）。"
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
                print(f"测试 {url} 时出错（尝试 {attempt + 1}/{retries + 1}）。")
            if attempt == retries:
                test_result["full_error_details"] = test_result["full_error_details"].replace(
                    f"尝试 {attempt + 1}/{retries + 1}", f"最终失败（共 {retries + 1} 次尝试）"
                )

        except subprocess.TimeoutExpired as e:
            test_result["message"] = f"测试 {url} 超时 ({timeout_seconds} 秒，尝试 {attempt + 1}/{retries + 1})。"
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
                print(f"测试 {url} 超时（尝试 {attempt + 1}/{retries + 1}）。")
            if attempt == retries:
                test_result["full_error_details"] = test_result["full_error_details"].replace(
                    f"尝试 {attempt + 1}/{retries + 1}", f"最终失败（共 {retries + 1} 次尝试）"
                )

        except Exception as e:
            test_result["message"] = f"测试 {url} 时发生意外错误（尝试 {attempt + 1}/{retries + 1}）。"
            test_result["full_error_details"] = (
                f"--- 频道: {channel_name} (URL: {url}) ---\n"
                f"状态: 意外错误\n"
                f"消息: {test_result['message']}\n"
                f"错误详情: {str(e)}\n"
                f"----------------------------------------\n\n"
            )
            with print_lock:
                print(f"测试 {url} 时发生意外错误（尝试 {attempt + 1}/{retries + 1}）。")
            if attempt == retries:
                test_result["full_error_details"] = test_result["full_error_details"].replace(
                    f"尝试 {attempt + 1}/{retries + 1}", f"最终失败（共 {retries + 1} 次尝试）"
                )

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
    parser = argparse.ArgumentParser(description="测试 IPTV 视频流")
    parser.add_argument("--workers", type=int, default=min(32, os.cpu_count() or 1), help="最大并行线程数")
    parser.add_argument("--timeout", type=int, default=15, help="单个流测试总超时时间（秒）")
    parser.add_argument("--response-threshold", type=int, default=5, help="响应时间阈值（秒），用于判断缓冲速度")
    parser.add_argument("--retries", type=int, default=1, help="失败重试次数")
    parser.add_argument("--encoding", default="utf-8", help="输入文件编码，默认为 utf-8")
    parser.add_argument("--exclude-urls", default="https://epg.pw/", help="逗号分隔的排除 URL 前缀列表")
    args = parser.parse_args()

    if args.timeout < 1:
        print("错误: 超时时间 (--timeout) 必须大于 0。")
        return
    if args.response_threshold < 1 or args.response_threshold >= args.timeout:
        print(f"错误: 响应时间阈值 (--response-threshold) 必须在 1 到 {args.timeout-1} 秒之间。")
        return
    if args.workers < 1:
        print("错误: 线程数 (--workers) 必须大于 0。")
        return
    if args.retries < 0:
        print("错误: 重试次数 (--retries) 必须大于或等于 0。")
        return

    script_dir = os.path.dirname(__file__)
    iptv_list_path = os.path.join(script_dir, "iptv_list.txt")
    output_dir = os.path.join(script_dir, "output")
    output_list_path = os.path.join(output_dir, "list.txt")
    slow_list_path = os.path.join(output_dir, "slow_list.txt")
    all_errors_log_path = os.path.join(output_dir, "all_errors.log")

    try:
        with open(iptv_list_path, "r", encoding=args.encoding) as f:
            iptv_content = f.read()
    except FileNotFoundError:
        print(f"错误: 未找到 {iptv_list_path}。请确保 iptv_list.txt 文件与脚本在同一目录下。")
        return
    except UnicodeDecodeError:
        print(f"错误: 无法使用编码 {args.encoding} 读取 {iptv_list_path}。请检查文件编码或通过 --encoding 指定正确的编码。")
        return

    all_channels = parse_iptv_list(iptv_content)
    total_initial_channels = len(all_channels)

    excluded_urls = [url.strip() for url in args.exclude_urls.split(",") if url.strip()]
    channels_to_test = []
    excluded_channels_count = 0

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
    
    success_fully_available_count = 0
    slow_channels = []
    failed_channels = []
    successful_channels_data = []
    slow_channels_data = []
    all_error_details = []

    max_workers = min(args.workers, total_channels_to_test)

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(test_stream, channel["name"], channel["url"], output_dir, args.timeout, args.response_threshold, args.retries): channel for channel in channels_to_test}
        
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
                    slow_channels_data.append(test_result)
                    if test_result["full_error_details"]:
                        all_error_details.append(test_result["full_error_details"])
            else:
                failed_channels.append(test_result["name"])
                if test_result["full_error_details"]:
                    all_error_details.append(test_result["full_error_details"])
            
            elapsed_time_overall = time.time() - start_time_overall
            avg_time_per_channel = elapsed_time_overall / completed_tasks if completed_tasks > 0 else 0
            remaining_tasks = total_channels_to_test - completed_tasks
            estimated_remaining_time = avg_time_per_channel * remaining_tasks

            progress_percentage = (completed_tasks / total_channels_to_test) * 100
            
            with print_lock:
                print(f"\n--- 进度: {progress_percentage:.2f}% ({completed_tasks}/{total_channels_to_test} 完成) ---")
                print(f"已运行: {format_time(elapsed_time_overall)} | 预计剩余: {format_time(estimated_remaining_time)}")

    if successful_channels_data:
        try:
            with open(output_list_path, "w", encoding="utf-8") as f:
                f.write(f"更新时间,{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')},url\n")
                for channel in successful_channels_data:
                    f.write(f"{channel['name']},{channel['url']}\n")
            print(f"\n完全可用的频道已保存到 {output_list_path}")
        except Exception as e:
            print(f"\n写入 {output_list_path} 失败: {e}")

    if slow_channels_data:
        try:
            with open(slow_list_path, "w", encoding="utf-8") as f:
                f.write(f"更新时间,{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')},url\n")
                for channel in slow_channels_data:
                    f.write(f"{channel['name']},{channel['url']}\n")
            print(f"缓冲过慢的频道已保存到 {slow_list_path}")
        except Exception as e:
            print(f"\n写入 {slow_list_path} 失败: {e}")
    else:
        print(f"\n没有缓冲过慢的频道，未生成 {slow_list_path}。")

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
