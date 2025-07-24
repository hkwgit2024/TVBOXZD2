import subprocess
import os
import re

def check_stream(url):
    """
    使用 ffprobe 检查流的有效性。
    """
    try:
        # 使用ffprobe检查流，-v quiet 减少输出，-print_format json 格式化输出，
        # -show_streams -show_format 显示流和格式信息，-timeout 5000000 微秒 (5秒)
        # 如果 ffprobe 成功返回0，否则返回非0
        command = [
            'ffprobe',
            '-v', 'quiet',
            '-print_format', 'json',
            '-show_streams',
            '-show_format',
            '-timeout', '5000000', # 5秒超时
            url
        ]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        # 如果ffprobe成功执行，且没有错误输出，我们认为链接是有效的
        return True
    except subprocess.CalledProcessError as e:
        # ffprobe 返回非零退出码，表示链接有问题
        print(f"Error checking {url}: {e.stderr.strip()}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred for {url}: {e}")
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

    successful_entries = []
    current_failed_links = set()

    with open(list_file, 'r', encoding='utf-8') as infile:
        lines = infile.readlines()

    genre = None
    for i, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue

        if '#genre#' in line:
            genre = line
            successful_entries.append(genre)
        elif ',' in line:
            parts = line.split(',', 1)
            if len(parts) == 2:
                name = parts[0].strip()
                url = parts[1].strip()

                if url in failed_links:
                    print(f"Skipping previously failed link: {name} - {url}")
                    # 如果是之前失败的链接，添加到当前失败列表，不添加到成功列表
                    current_failed_links.add(url)
                    continue

                print(f"Checking: {name} - {url}")
                if check_stream(url):
                    print(f"Success: {name} - {url}")
                    if genre:
                        # 确保添加到ff.txt时，前面有对应的genre
                        if i > 0 and '#genre#' not in lines[i-1]:
                            # 如果前一行不是genre，并且当前genre是之前记录的，说明该genre已经添加到successful_entries
                            # 避免重复添加genre，如果该genre是本轮新添加的，则已经加过了
                            pass
                        elif genre not in successful_entries:
                            successful_entries.append(genre) # 确保genre在频道之前
                    successful_entries.append(f"{name},{url}")
                else:
                    print(f"Failed: {name} - {url}")
                    current_failed_links.add(url)
            else:
                # 格式不正确的行也添加到成功列表，因为它们不是链接
                successful_entries.append(line)
        else:
            # 非 genre 非链接的行，直接添加到成功列表
            successful_entries.append(line)


    # 将成功的链接写入 ff.txt，保持原始格式
    with open(output_file, 'w', encoding='utf-8') as outfile:
        # 写入时去除重复的genre行
        written_genres = set()
        final_output_lines = []
        for entry in successful_entries:
            if '#genre#' in entry:
                if entry not in written_genres:
                    final_output_lines.append(entry)
                    written_genres.add(entry)
            else:
                final_output_lines.append(entry)
        
        outfile.write('\n'.join(final_output_lines))

    # 更新 failed_links.txt
    with open(failed_links_file, 'w', encoding='utf-8') as f:
        for link in current_failed_links:
            f.write(f"{link}\n")

    print("\nProcessing complete.")
    print(f"Successful links written to {output_file}")
    print(f"Failed links updated in {failed_links_file}")

if __name__ == "__main__":
    main()
