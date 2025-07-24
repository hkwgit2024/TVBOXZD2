import os
import re
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

# 设置超时时间（秒）
TIMEOUT = 5
# 设置读取数据的时间（秒），用于模拟播放
READ_DURATION = 2
# 最大重试次数
MAX_RETRIES = 2

# 排除的域名列表，包含这些域名的链接将被直接跳过，不进行测试
# 您可以根据需要添加更多要排除的域名
EXCLUDE_DOMAINS = ["epg.pw"]

# 全局列表，用于存储测试结果
# playable_links 存储 (genre_header, response_time, channel_name, url)
playable_links = [] 
# failed_links_data 存储 (genre_header, channel_name, url)
failed_links_data = [] 
# original_links_with_genre 存储 (genre_header, channel_name, url) 从原始文件读取的所有链接
# genre_header 为 None, None 表示这是一个 genre 头部行
# channel_name 为行内容, url 为 "MALFORMED_LINE" 表示这是一个格式错误的行
original_links_with_genre = [] 

def is_excluded_url(url):
    """
    检查URL的域名是否在排除列表中。
    """
    parsed_url = urlparse(url)
    domain = parsed_url.hostname
    if domain:
        for exclude_domain in EXCLUDE_DOMAINS:
            # 检查是否是完全匹配的域名或子域名
            if exclude_domain == domain or domain.endswith('.' + exclude_domain):
                print(f"URL {url} excluded due to domain: {exclude_domain}")
                return True
    return False

def is_link_playable(url, channel_name):
    """
    检查链接是否可播放，并返回响应时间。
    通过尝试连接并读取数据来判断，检查 MIME 类型以确保是视频流。
    """
    # 在进行任何网络请求之前，首先检查是否为排除链接
    if is_excluded_url(url):
        return False, 0.0 # 返回 False 和 0 响应时间，表示已排除

    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    valid_types = ['video/mp4', 'application/x-mpegurl', 'application/vnd.apple.mpegurl', 'video/']
    
    for attempt in range(MAX_RETRIES):
        try:
            start_time = time.time()
            print(f"Checking {channel_name}: {url} (Attempt {attempt + 1}/{MAX_RETRIES})")
            with requests.get(url, stream=True, timeout=TIMEOUT, headers=headers) as r:
                r.raise_for_status()  # 检查HTTP状态码
                # 检查 Content-Type
                content_type = r.headers.get('Content-Type', '').lower()
                if not any(vt in content_type for vt in valid_types):
                    print(f"Invalid content type for {channel_name}: {url} - {content_type}")
                    return False, time.time() - start_time
                bytes_read = 0
                # 尝试读取数据，模拟播放
                for chunk in r.iter_content(chunk_size=8192):
                    if time.time() - start_time > READ_DURATION:
                        break
                    bytes_read += len(chunk)
                response_time = time.time() - start_time
                if bytes_read > 0:
                    print(f"Successfully connected to {channel_name}: {url} (read {bytes_read} bytes, took {response_time:.2f}s)")
                    return True, response_time
                else:
                    print(f"Failed to read data from {channel_name}: {url}")
                    return False, response_time
        except requests.exceptions.RequestException as e:
            response_time = time.time() - start_time
            print(f"Error checking {channel_name}: {url} - {e}")
            if attempt == MAX_RETRIES - 1:
                return False, response_time
            time.sleep(1)  # 等待 1 秒后重试
        except Exception as e:
            response_time = time.time() - start_time
            print(f"An unexpected error occurred for {channel_name}: {url} - {e}")
            return False, response_time

def update_source_file(input_file, playable_links, original_links_with_genre):
    """
    根据测试结果和URL规则更新源文件 (iptv_list.txt)。
    保留可播放的链接和URL中包含"20"的链接。
    """
    print(f"\nUpdating source file: {input_file}...")
    
    # 构建可播放链接的集合，用于快速查找 (channel_name, url)
    playable_set = set((c, u) for _, _, c, u in playable_links)

    # 用于构建最终更新内容的列表
    final_updated_lines = []
    
    # 临时存储每个 genre 下符合条件的链接
    current_genre_buffer = []
    current_genre_header_to_write = None

    # 遍历原始链接，决定哪些应该保留
    for item in original_links_with_genre:
        # item 是 (genre_header, channel_name, url)
        # 如果 channel_name 和 url 都是 None，则表示这是一个 genre 头部行
        if item[1] is None and item[2] is None: 
            # 在处理新的 genre 头部之前，如果前一个 genre 有缓冲的链接，则将其写入
            if current_genre_header_to_write and current_genre_buffer:
                final_updated_lines.append(current_genre_header_to_write)
                final_updated_lines.extend(current_genre_buffer)
            
            # 为新的 genre 重置缓冲区
            current_genre_header_to_write = item[0] # 实际的 genre 头部字符串
            current_genre_buffer = []
        elif item[2] == "MALFORMED_LINE": # 这是一个格式错误的行
            # 格式错误的行不写入更新后的文件
            continue
        else: # 这是一个正常的频道链接
            channel_name = item[1]
            url = item[2]
            
            should_keep = False
            # 1. 如果链接可播放，保留
            if (channel_name, url) in playable_set:
                should_keep = True
            # 2. 如果URL包含"20"，保留
            if "20" in url:
                should_keep = True
            
            if should_keep:
                current_genre_buffer.append(f"{channel_name},{url}")
    
    # 循环结束后，写入最后一个 genre 的任何剩余缓冲链接
    if current_genre_header_to_write and current_genre_buffer:
        final_updated_lines.append(current_genre_header_to_write)
        final_updated_lines.extend(current_genre_buffer)

    # 写入更新后的内容到源文件
    with open(input_file, 'w', encoding='utf-8') as f:
        for line in final_updated_lines:
            f.write(line + '\n')
    print(f"Source file {input_file} updated successfully.")


def write_failed_links(output_file, failed_links_data):
    """
    将测试不成功的链接写入指定文件。
    """
    print(f"Writing failed links to {output_file}...")
    with open(output_file, 'w', encoding='utf-8') as f:
        if not failed_links_data:
            f.write("# No failed links found.\n")
            print("No failed links to write.")
            return

        # 按 genre 分组并写入
        failed_genre_groups = {}
        for genre_header, channel_name, url in failed_links_data:
            failed_genre_groups.setdefault(genre_header, []).append(f"{channel_name},{url}")
        
        for genre_header in failed_genre_groups:
            f.write(genre_header + '\n')
            for link_entry in failed_genre_groups[genre_header]:
                f.write(link_entry + '\n')
    print(f"Successfully wrote {len(failed_links_data)} failed links to {output_file}.")

def load_previously_failed_urls(file_path):
    """
    从 failed_list.txt 文件中加载之前测试失败的URL。
    """
    failed_urls = set()
    if not os.path.exists(file_path):
        return failed_urls
    
    print(f"Loading previously failed URLs from {file_path}...")
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#') or line.endswith(',#genre#'):
                continue
            
            match = re.match(r'^(.*?),(http[s]?://.*)$', line)
            if match:
                url = match.group(2).strip()
                failed_urls.add(url)
    print(f"Loaded {len(failed_urls)} previously failed URLs.")
    return failed_urls

def main():
    input_file = 'iptv_list.txt'
    output_file = 'list.txt' # 成功可播放链接输出文件
    failed_output_file = 'failed_list.txt' # 测试不成功链接输出文件
    
    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found.")
        return

    # 加载之前测试失败的URL
    previously_failed_urls = load_previously_failed_urls(failed_output_file)

    # 读取 iptv_list.txt 文件并填充 original_links_with_genre
    current_genre_header = None # 这将存储实际的 genre 头部字符串
    links_to_check_for_threading = [] # 仅用于线程池检查的列表

    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.endswith(',#genre#'):
                current_genre_header = line
                # 存储 genre 头部本身，以保留其确切形式和顺序
                original_links_with_genre.append((current_genre_header, None, None)) 
            else:
                match = re.match(r'^(.*?),(http[s]?://.*)$', line)
                if match:
                    channel_name = match.group(1).strip()
                    url = match.group(2).strip()
                    
                    # 存储链接及其关联的 genre 头部
                    original_links_with_genre.append((current_genre_header, channel_name, url))
                    
                    # 只有未排除且未在之前失败的链接才添加到 links_to_check_for_threading 进行实际的网络检查
                    if not is_excluded_url(url) and url not in previously_failed_urls:
                        links_to_check_for_threading.append((current_genre_header, channel_name, url))
                    elif url in previously_failed_urls:
                        print(f"Skipping previously failed URL: {url}")
                else:
                    print(f"Skipping malformed line: {line}")
                    # 存储格式错误的行及其关联的 genre 头部
                    original_links_with_genre.append((current_genre_header, line, "MALFORMED_LINE")) 


    if not links_to_check_for_threading and not original_links_with_genre:
        print("No links or genres found in iptv_list.txt.")
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("")
        with open(failed_output_file, 'w', encoding='utf-8') as f:
            f.write("")
        return
    
    if not links_to_check_for_threading:
        print("No non-excluded or previously failed links found in iptv_list.txt to check.")
        # 即使没有要检查的链接，也需要根据规则更新源文件
        update_source_file(input_file, playable_links, original_links_with_genre)
        write_failed_links(failed_output_file, failed_links_data) # 确保即使没有新失败的链接也更新文件
        # 清空 list.txt
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("")
        return


    # 使用线程池并发检查链接
    with ThreadPoolExecutor(max_workers=20) as executor:
        # future_to_link 存储 (genre, channel, url) 以便在结果返回时关联
        future_to_link = {executor.submit(is_link_playable, url, channel): (genre, channel, url) for genre, channel, url in links_to_check_for_threading}
        
        for future in as_completed(future_to_link):
            genre, channel_name, url = future_to_link[future]
            try:
                is_playable, response_time = future.result()
                if is_playable:
                    playable_links.append((genre, response_time, channel_name, url))
                else:
                    # 如果链接被排除，is_link_playable 会返回 False, 0.0，但我们不应该将其视为“失败”并写入 failed_list.txt
                    # 因为它已经被明确跳过了。只有实际尝试连接后失败的才算失败。
                    # is_link_playable 内部已经处理了排除逻辑，如果返回 False 则表示非排除链接的检查失败。
                    failed_links_data.append((genre, channel_name, url))
            except Exception as exc:
                print(f'{channel_name}: {url} generated an exception: {exc}')
                failed_links_data.append((genre, channel_name, url)) # 将异常的链接也视为失败

    # 写入 list.txt (成功可播放链接)
    with open(output_file, 'w', encoding='utf-8') as f:
        total_playable_links = 0
        # 存储按 genre 分组的可用链接，用于写入 list.txt
        genre_groups_for_output = {}
        for genre_header, response_time, channel_name, url in playable_links:
            genre_groups_for_output.setdefault(genre_header, []).append((response_time, f"{channel_name},{url}"))

        for genre_header in genre_groups_for_output:
            links = genre_groups_for_output[genre_header]
            if links:
                f.write(genre_header + '\n')
                # 按响应时间升序排序
                for _, link_entry in sorted(links, key=lambda x: x[0]):
                    f.write(link_entry + '\n')
                    total_playable_links += 1
        
        if total_playable_links > 0:
            print(f"Successfully wrote {total_playable_links} playable links to {output_file}, sorted by response time")
        else:
            print(f"No playable links found. {output_file} will be empty.")
            f.write("")

    # 更新源文件 iptv_list.txt
    update_source_file(input_file, playable_links, original_links_with_genre)

    # 写入测试不成功的链接到 failed_list.txt
    write_failed_links(failed_output_file, failed_links_data)

if __name__ == '__main__':
    main()
