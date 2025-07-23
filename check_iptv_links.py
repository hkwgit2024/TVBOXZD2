import os
import re
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse # 导入 urlparse 用于提取域名

# 设置超时时间（秒）
TIMEOUT = 5
# 设置读取数据的时间（秒），用于模拟播放
READ_DURATION = 2
# 最大重试次数
MAX_RETRIES = 2

# 排除的域名列表，包含这些域名的链接将被直接跳过，不进行测试
# 您可以根据需要添加更多要排除的域名
EXCLUDE_DOMAINS = ["epg.pw"]

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

def main():
    input_file = 'iptv_list.txt'
    output_file = 'list.txt'
    
    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found.")
        return

    # 存储按 genre 分组的可用链接
    genre_groups = {}
    current_genre = None
    links_to_check = []

    # 读取 iptv_list.txt 文件
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:  # 跳过空行
                continue
            if line.endswith(',#genre#'):
                current_genre = line
                genre_groups[current_genre] = []
                continue
            if current_genre is None:
                continue  # 忽略没有 genre 的行
            # 使用正则表达式匹配频道名和链接
            match = re.match(r'^(.*?),(http[s]?://.*)$', line)
            if match:
                channel_name = match.group(1).strip()
                url = match.group(2).strip()
                
                # 在将链接添加到检查列表之前，检查是否为排除链接
                if is_excluded_url(url):
                    print(f"Skipping excluded URL in input file: {url}")
                    continue # 跳过此链接，不添加到 links_to_check
                
                links_to_check.append((current_genre, channel_name, url))
            else:
                print(f"Skipping malformed line: {line}")

    if not links_to_check:
        print("No links found in iptv_list.txt to check.")
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("")  # 清空 list.txt
        return

    # 使用线程池并发检查链接
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_link = {executor.submit(is_link_playable, url, channel): (genre, channel, url) for genre, channel, url in links_to_check}
        for future in as_completed(future_to_link):
            genre, channel_name, url = future_to_link[future]
            try:
                is_playable, response_time = future.result()
                if is_playable:
                    genre_groups.setdefault(genre, []).append((response_time, f"{channel_name},{url}"))
            except Exception as exc:
                print(f'{channel_name}: {url} generated an exception: {exc}')

    # 按响应时间排序并写入 list.txt
    with open(output_file, 'w', encoding='utf-8') as f:
        total_links = 0
        for genre in genre_groups:
            links = genre_groups[genre]
            if links:  # 只有当该 genre 下有可用链接时才写入 genre 标记
                f.write(genre + '\n')
                # 按响应时间升序排序
                for _, link_entry in sorted(links, key=lambda x: x[0]):
                    f.write(link_entry + '\n')
                    total_links += 1
        if total_links > 0:
            print(f"Successfully wrote {total_links} playable links to {output_file}, sorted by response time")
        else:
            print(f"No playable links found. {output_file} will be empty.")
            f.write("")  # 确保文件被清空

if __name__ == '__main__':
    main()
