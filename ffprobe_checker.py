import subprocess
import os
import re
import sys # 导入 sys 模块
from concurrent.futures import ThreadPoolExecutor, as_completed

# 可以根据你的GitHub Actions runner的CPU核心数和网络带宽调整
# 对于I/O密集型任务，线程数可以适当调高
MAX_WORKERS = 20 # 假设同时进行20个并发连接，可以根据实际情况调整

def check_stream(url, timeout_seconds=5):
    """
    使用 ffprobe 检查流的有效性。
    timeout_seconds: ffprobe 超时时间，单位秒。
    """
    # 打印正在检查的URL，并立即刷新
    # print(f"DEBUG: Checking URL: {url}", flush=True) # 调试时可以取消注释，但会产生大量日志

    try:
        command = [
            'ffprobe',
            '-v', 'quiet', # 保持安静模式，只在出错时输出
            '-print_format', 'json',
            '-show_streams',
            '-show_format',
            '-timeout', str(timeout_seconds * 1_000_000), # 转换为微秒
            url
        ]
        
        # subprocess.run 捕获标准输出和标准错误
        # check=True 会在非零退出码时抛出 CalledProcessError
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        # 如果 ffprobe 成功，并且没有错误输出，则认为是有效的
        # ffprobe -v quiet 正常运行时不会有stderr，但为了保险起见，检查一下
        if result.stderr:
            # 即使返回0，如果stderr有内容，可能表示警告或非致命错误
            # 对于准确性，我们严格一点，认为有stderr就是有问题
            print(f"WARNING: ffprobe for {url} returned warnings/errors to stderr: {result.stderr.strip()}", flush=True)
            return False # 视为失败
        return True # 视为成功
        
    except subprocess.CalledProcessError as e:
        # ffprobe 返回非零退出码，表示链接有问题
        print(f"ERROR: ffprobe failed for {url} with exit code {e.returncode}. Stderr: {e.stderr.strip()}", flush=True)
        return False
    except FileNotFoundError:
        print(f"ERROR: ffprobe command not found. Ensure FFmpeg is installed and in PATH.", flush=True)
        return False
    except Exception as e:
        # 捕获所有其他意外错误
        print(f"UNEXPECTED ERROR: An exception occurred for {url}: {e}", flush=True)
        return False

def main():
    # 强制所有print语句立即刷新
    print("Starting ffprobe_checker.py script...", flush=True)

    list_file = 'list.txt'
    failed_links_file = 'failed_links.txt'
    output_file = 'ff.txt'

    # 检查 list.txt 是否存在
    if not os.path.exists(list_file):
        print(f"ERROR: '{list_file}' not found. Please ensure it's in the repository root.", flush=True)
        sys.exit(1) # 退出脚本

    print(f"Attempting to load failed links from '{failed_links_file}'...", flush=True)
    failed_links = set()
    if os.path.exists(failed_links_file):
        try:
            with open(failed_links_file, 'r', encoding='utf-8') as f:
                for line in f:
                    failed_links.add(line.strip())
            print(f"Successfully loaded {len(failed_links)} previously failed links.", flush=True)
        except Exception as e:
            print(f"WARNING: Could not load '{failed_links_file}': {e}. Starting with empty failed links.", flush=True)
    else:
        print(f"'{failed_links_file}' not found. Starting with no previously failed links.", flush=True)


    lines_to_process = []
    original_structure = [] # 存储原始文件的结构，包括genre和非链接行

    print(f"Reading '{list_file}' to prepare links for processing...", flush=True)
    try:
        with open(list_file, 'r', encoding='utf-8') as infile:
            for line_num, line in enumerate(infile):
                line = line.strip()
                original_structure.append(line) # 保留原始行，用于后续重构

                if not line or '#genre#' in line:
                    continue

                parts = line.split(',', 1)
                if len(parts) == 2:
                    name = parts[0].strip()
                    url = parts[1].strip()
                    if url and url not in failed_links:
                        lines_to_process.append((line_num, name, url))
                    # else: print(f"Skipping previously failed or invalid line: {line}", flush=True) # 调试信息
                else:
                    # 对于格式不正确的行，我们不进行测试，但依然记录在 original_structure 中
                    pass
        print(f"Prepared {len(lines_to_process)} links for checking from '{list_file}'.", flush=True)
    except Exception as e:
        print(f"ERROR: Could not read '{list_file}': {e}", flush=True)
        sys.exit(1) # 退出脚本

    successful_urls = set()
    # 继承之前的失败链接，并在当前运行中更新
    current_failed_links = set(failed_links) 

    if not lines_to_process:
        print("No new links to process or all links were previously failed. Exiting.", flush=True)
        # 即使没有链接处理，也应该尝试更新ff.txt和failed_links.txt，以防万一
        update_files(output_file, failed_links_file, original_structure, successful_urls, current_failed_links)
        return

    print(f"Starting {len(lines_to_process)} links check with {MAX_WORKERS} concurrent workers...", flush=True)

    # 使用ThreadPoolExecutor进行并发检查
    processed_count = 0
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_link = {
            executor.submit(check_stream, url): (line_num, name, url)
            for line_num, name, url in lines_to_process
        }

        for future in as_completed(future_to_link):
            processed_count += 1
            line_num, name, url = future_to_link[future]
            try:
                is_successful = future.result()
                if is_successful:
                    successful_urls.add(url)
                    # print(f"Success ({processed_count}/{len(lines_to_process)}): {name} - {url}", flush=True) # 调试时可以取消注释，会产生大量日志
                else:
                    current_failed_links.add(url)
                    # print(f"Failed ({processed_count}/{len(lines_to_process)}): {name} - {url}", flush=True) # 调试时可以取消注释，会产生大量日志
            except Exception as exc:
                print(f"Link {url} generated an unexpected exception during execution: {exc}", flush=True)
                current_failed_links.add(url)
            
            # 打印进度，每处理一定数量的链接打印一次
            if (processed_count % 100 == 0) or (processed_count == len(lines_to_process)):
                print(f"Processed {processed_count}/{len(lines_to_process)} links...", flush=True)

    print("\nAll link checks completed. Updating output files...", flush=True)
    update_files(output_file, failed_links_file, original_structure, successful_urls, current_failed_links)

    print("Processing complete.", flush=True)
    print(f"Successful links written to {output_file}", flush=True)
    print(f"Failed links updated in {failed_links_file}", flush=True)

def update_files(output_file, failed_links_file, original_structure, successful_urls, current_failed_links):
    """辅助函数，用于将结果写入文件"""
    # 构建 ff.txt 的内容，保持原始格式
    final_ff_content = []
    for line in original_structure:
        if '#genre#' in line or ',' not in line:
            final_ff_content.append(line)
        else:
            parts = line.split(',', 1)
            if len(parts) == 2:
                url = parts[1].strip()
                if url in successful_urls:
                    final_ff_content.append(line)
            else:
                final_ff_content.append(line) # 格式不正确的行也保留

    print(f"Writing successful links to '{output_file}'...", flush=True)
    try:
        with open(output_file, 'w', encoding='utf-8') as outfile:
            outfile.write('\n'.join(final_ff_content))
    except Exception as e:
        print(f"ERROR: Could not write to '{output_file}': {e}", flush=True)

    print(f"Updating failed links in '{failed_links_file}'...", flush=True)
    try:
        with open(failed_links_file, 'w', encoding='utf-8') as f:
            for link in sorted(list(current_failed_links)): # 排序以便文件内容稳定
                f.write(f"{link}\n")
    except Exception as e:
        print(f"ERROR: Could not write to '{failed_links_file}': {e}", flush=True)


if __name__ == "__main__":
    main()
