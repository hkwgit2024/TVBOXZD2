import subprocess
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed

# 可以根据你的GitHub Actions runner的CPU核心数和网络带宽调整
# 对于I/O密集型任务，线程数可以适当调高
MAX_WORKERS = 20 # 假设同时进行20个并发连接，可以根据实际情况调整

def check_stream(url, timeout_seconds=5):
    """
    使用 ffprobe 检查流的有效性。
    timeout_seconds: ffprobe 超时时间，单位秒。
    """
    try:
        command = [
            'ffprobe',
            '-v', 'quiet',
            '-print_format', 'json',
            '-show_streams',
            '-show_format',
            '-timeout', str(timeout_seconds * 1_000_000), # 转换为微秒
            url
        ]
        # capture_output=True 捕获标准输出和标准错误
        # text=True 表示输出是文本
        # check=True 表示如果命令返回非零退出码则抛出 CalledProcessError
        subprocess.run(command, capture_output=True, text=True, check=True)
        return True
    except subprocess.CalledProcessError as e:
        # ffprobe 返回非零退出码，表示链接有问题
        # print(f"Error checking {url}: {e.stderr.strip()}") # 调试时可以取消注释
        return False
    except Exception as e:
        # print(f"An unexpected error occurred for {url}: {e}") # 调试时可以取消注释
        return False

def main():
    list_file = 'list.txt'
    failed_links_file = 'failed_links.txt'
    output_file = 'ff.txt'

    failed_links = set()
    if os.path.exists(failed_links_file):
        with open(failed_links_file, 'r', encoding='utf-8') as f:
            for line in f:
                failed_links.add(line.strip())

    lines_to_process = []
    # 存储原始文件的结构，包括genre和非链接行
    original_structure = []

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
                # else: print(f"Skipping previously failed or invalid line: {line}") # 调试信息

    successful_urls = set()
    current_failed_links = set(failed_links) # 继承之前的失败链接

    print(f"Starting {len(lines_to_process)} links check with {MAX_WORKERS} concurrent workers...")

    # 使用ThreadPoolExecutor进行并发检查
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # {future: (line_num, name, url)} 映射
        future_to_link = {
            executor.submit(check_stream, url): (line_num, name, url)
            for line_num, name, url in lines_to_process
        }

        for i, future in enumerate(as_completed(future_to_link)):
            line_num, name, url = future_to_link[future]
            try:
                is_successful = future.result()
                if is_successful:
                    successful_urls.add(url)
                    # print(f"Success ({i+1}/{len(lines_to_process)}): {name} - {url}") # 调试时可以取消注释
                else:
                    current_failed_links.add(url)
                    # print(f"Failed ({i+1}/{len(lines_to_process)}): {name} - {url}") # 调试时可以取消注释
            except Exception as exc:
                print(f"Link {url} generated an exception: {exc}")
                current_failed_links.add(url)
            
            # 打印进度，每处理一定数量的链接打印一次
            if (i + 1) % 100 == 0 or (i + 1) == len(lines_to_process):
                print(f"Processed {i + 1}/{len(lines_to_process)} links...")

    # 构建 ff.txt 的内容，保持原始格式
    final_ff_content = []
    for line in original_structure:
        if '#genre#' in line or ',' not in line:
            final_ff_content.append(line)
        else:
            parts = line.split(',', 1)
            if len(parts) == 2:
                name = parts[0].strip()
                url = parts[1].strip()
                if url in successful_urls:
                    final_ff_content.append(line)
            else:
                final_ff_content.append(line) # 格式不正确的行也保留

    # 将成功的链接写入 ff.txt
    with open(output_file, 'w', encoding='utf-8') as outfile:
        outfile.write('\n'.join(final_ff_content))

    # 更新 failed_links.txt
    with open(failed_links_file, 'w', encoding='utf-8') as f:
        for link in sorted(list(current_failed_links)): # 排序以便文件内容稳定
            f.write(f"{link}\n")

    print("\nProcessing complete.")
    print(f"Successful links written to {output_file}")
    print(f"Failed links updated in {failed_links_file}")

if __name__ == "__main__":
    main()
