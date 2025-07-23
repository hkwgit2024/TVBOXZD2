import os
import re
import requests
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

# 设置超时时间（秒）
TIMEOUT = 10
# 设置读取数据的时间（秒），用于模拟播放
READ_DURATION = 5

def is_link_playable(url, channel_name):
    """
    检查链接是否可播放。
    通过尝试连接并读取数据来判断。
    """
    try:
        print(f"Checking {channel_name}: {url}")
        with requests.get(url, stream=True, timeout=TIMEOUT) as r:
            r.raise_for_status()  # 检查HTTP状态码
            start_time = time.time()
            bytes_read = 0
            # 尝试读取数据，模拟播放
            for chunk in r.iter_content(chunk_size=8192):
                if time.time() - start_time > READ_DURATION:
                    break
                bytes_read += len(chunk)
            if bytes_read > 0:
                print(f"Successfully connected to {channel_name}: {url} (read {bytes_read} bytes)")
                return True
            else:
                print(f"Failed to read data from {channel_name}: {url}")
                return False
    except requests.exceptions.RequestException as e:
        print(f"Error checking {channel_name}: {url} - {e}")
        return False
    except Exception as e:
        print(f"An unexpected error occurred for {channel_name}: {url} - {e}")
        return False

def main():
    input_file = 'iptv_list.txt'
    output_file = 'list.txt'
    
    if not os.path.exists(input_file):
        print(f"Error: {input_file} not found.")
        return

    playable_links = set()
    links_to_check = []

    # 读取iptv_list.txt文件
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):  # 跳过空行和注释行
                continue
            
            # 使用正则表达式匹配频道名和链接
            match = re.match(r'^(.*?),(http[s]?://.*)$', line)
            if match:
                channel_name = match.group(1).strip()
                url = match.group(2).strip()
                links_to_check.append((channel_name, url))
            else:
                print(f"Skipping malformed line: {line}")

    if not links_to_check:
        print("No links found in iptv_list.txt to check.")
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("") # 清空list.txt
        return

    # 使用线程池并发检查链接
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_link = {executor.submit(is_link_playable, url, channel): (channel, url) for channel, url in links_to_check}
        for future in as_completed(future_to_link):
            channel_name, url = future_to_link[future]
            try:
                if future.result():
                    playable_links.add(f"{channel_name},{url}")
            except Exception as exc:
                print(f'{channel_name}: {url} generated an exception: {exc}')

    # 将去重后的可用链接写入list.txt
    with open(output_file, 'w', encoding='utf-8') as f:
        if playable_links:
            for link_entry in sorted(list(playable_links)):
                f.write(link_entry + '\n')
            print(f"Successfully wrote {len(playable_links)} playable links to {output_file}")
        else:
            print(f"No playable links found. {output_file} will be empty.")
            f.write("") # 确保文件被清空

if __name__ == '__main__':
    main()
