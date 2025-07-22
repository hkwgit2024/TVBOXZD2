import urllib.request
from urllib.parse import urlparse
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
import subprocess
import socket
import time
from datetime import datetime

# 读取文本方法
def read_txt_to_array(file_name):
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            lines = file.readlines()
            lines = [line.strip() for line in lines if line.strip()]  # 移除空行
            return lines
    except FileNotFoundError:
        print(f"File '{file_name}' not found.")
        return []
    except Exception as e:
        print(f"An error occurred: {e}")
        return []

# 准备支持 m3u 格式
def get_url_file_extension(url):
    parsed_url = urlparse(url)
    path = parsed_url.path
    extension = os.path.splitext(path)[1]
    return extension

def convert_m3u_to_txt(m3u_content):
    lines = m3u_content.split('\n')
    txt_lines = []
    channel_name = ""
    for line in lines:
        if line.startswith("#EXTM3U"):
            continue
        if line.startswith("#EXTINF"):
            channel_name = line.split(',')[-1].strip()
        elif line.startswith("http") or line.startswith("rtmp") or line.startswith("p3p"):
            txt_lines.append(f"{channel_name},{line.strip()}")
    return '\n'.join(txt_lines)

# 处理带 $ 的 URL
def clean_url(url):
    last_dollar_index = url.rfind('$')
    if last_dollar_index != -1:
        return url[:last_dollar_index]
    return url

# 处理所有 URL
def process_url(url, timeout=10, max_fetch_time=10):
    try:
        start_time = time.time()
        with urllib.request.urlopen(url, timeout=timeout) as response:
            data = response.read()
            text = data.decode('utf-8')
            elapsed_time = time.time() - start_time

            # 检查是否超过最大获取时间
            if elapsed_time > max_fetch_time:
                print(f"URL: {url} 内容获取时间过长 ({elapsed_time:.2f}秒)，超过{max_fetch_time}秒，跳过处理。")
                return []

            # 检查内容是否符合频道列表格式
            if not re.search(r',.*://', text):
                print(f"URL: {url} 的内容不符合频道列表格式，跳过处理。")
                return []

            # 处理 m3u 和 m3u8
            if get_url_file_extension(url) in [".m3u", ".m3u8"]:
                text = convert_m3u_to_txt(text)

            lines = text.split('\n')
            channels_from_url = []
            for line in lines:
                if "#genre#" not in line and "," in line and "://" in line:
                    parts = line.split(',')
                    channel_name = parts[0]
                    channel_address = parts[1]
                    if "#" not in channel_address:
                        channels_from_url.append((channel_name, clean_url(channel_address)))
                    else:
                        url_list = channel_address.split('#')
                        for channel_url in url_list:
                            channels_from_url.append((channel_name, clean_url(channel_url)))

            print(f"正在读取URL: {url} (耗时: {elapsed_time:.2f}秒)")
            print(f"获取到频道列表: {len(channels_from_url)} 条")
            return channels_from_url

    except Exception as e:
        print(f"处理 URL 时发生错误：{url}: {e}")
        return []

# 过滤和替换频道名称
def filter_and_modify_sources(corrections):
    filtered_corrections = []
    name_dict = ['购物', '理财', '导视', '指南', '测试', '芒果', 'CGTN']
    url_dict = []

    for name, url in corrections:
        if any(word.lower() in name.lower() for word in name_dict) or any(word in url for word in url_dict):
            print(f"过滤频道: {name},{url}")
        else:
            name = name.replace("FHD", "").replace("HD", "").replace("hd", "").replace("频道", "").replace("高清", "") \
                .replace("超清", "").replace("20M", "").replace("-", "").replace("4k", "").replace("4K", "") \
                .replace("4kR", "")
            filtered_corrections.append((name, url))
    return filtered_corrections

# 删除目录内所有 .txt 文件
def clear_txt_files(directory):
    for filename in os.listdir(directory):
        if filename.endswith('.txt'):
            file_path = os.path.join(directory, filename)
            try:
                os.remove(file_path)
            except Exception as e:
                print(f"删除文件时发生错误: {e}")

# 主函数
def main():
    urls_file_path = os.path.join(os.getcwd(), 'config/urls.txt')
    urls = read_txt_to_array(urls_file_path)

    all_channels = []
    successful_urls = set()
    for url in urls:
        channels_from_current_url = process_url(url, max_fetch_time=10)  # 设置最大获取时间为10秒
        if len(channels_from_current_url) >= 20:
            all_channels.extend(channels_from_current_url)
            successful_urls.add(url)
        else:
            print(f"URL: {url} 获取到的有效频道数量少于20个 ({len(channels_from_current_url)}条)，已排除。")

    with open(urls_file_path, 'w', encoding='utf-8') as f:
        for url in sorted(list(successful_urls)):
            f.write(url + '\n')
    print(f"\n已更新 {urls_file_path} 文件，保留了 {len(successful_urls)} 个有效URL源。")

    filtered_channels = filter_and_modify_sources(all_channels)
    unique_channels = list(set(filtered_channels))
    unique_channels_str = [f"{name},{url}" for name, url in unique_channels]

    iptv_file_path = os.path.join(os.getcwd(), 'iptv.txt')
    with open(iptv_file_path, 'w', encoding='utf-8') as f:
        for line in unique_channels_str:
            f.write(line + '\n')

    with open(iptv_file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        total_channels = len(lines)
        print(f"\n所有频道已保存到文件: {iptv_file_path}，共采集到频道数量: {total_channels} 条\n")

    def check_url(url, channel_name, timeout=6):
        start_time = time.time()
        elapsed_time = None
        success = False
        try:
            if url.startswith("http"):
                response = urllib.request.urlopen(url, timeout=timeout)
                if response.status == 200:
                    success = True
            elif url.startswith("p3p"):
                success = check_p3p_url(url, timeout)
            elif url.startswith("rtmp"):
                success = check_rtmp_url(url, timeout)
            elif url.startswith("rtp"):
                success = check_rtp_url(url, timeout)
            else:
                return None, False
            elapsed_time = (time.time() - start_time) * 1000
        except Exception:
            pass
        return elapsed_time, success

    def check_rtmp_url(url, timeout):
        try:
            result = subprocess.run(['ffprobe', '-v', 'error', '-rtmp_transport', 'tcp', '-i', url],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)
            return result.returncode == 0
        except:
            return False

    def check_rtp_url(url, timeout):
        try:
            parsed_url = urlparse(url)
            host = parsed_url.hostname
            port = parsed_url.port
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.connect((host, port))
                s.sendto(b'', (host, port))
                s.recv(1)
            return True
        except:
            return False

    def check_p3p_url(url, timeout):
        try:
            parsed_url = urlparse(url)
            host = parsed_url.hostname
            port = parsed_url.port
            path = parsed_url.path
            with socket.create_connection((host, port), timeout=timeout) as s:
                request = f"GET {path} P3P/1.0\r\nHost: {host}\r\n\r\n"
                s.sendall(request.encode())
                response = s.recv(1024)
                return b"P3P" in response
        except:
            return False

    def process_line(line):
        if "://" not in line:
            return None, None
        line = line.split('$')[0]
        parts = line.split(',')
        if len(parts) == 2:
            name, url = parts
            elapsed_time, is_valid = check_url(url.strip(), name)
            if is_valid:
                return elapsed_time, f"{name},{url}"
        return None, None

    def process_urls_multithreaded(lines, max_workers=200):
        results = []
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {executor.submit(process_line, line): line for line in lines}
            for future in as_completed(futures):
                elapsed_time, result = future.result()
                if elapsed_time is not None:
                    results.append((elapsed_time, result))
        results.sort()
        return results

    results = process_urls_multithreaded(unique_channels_str)

    def write_list(file_path, data_list):
        with open(file_path, 'w', encoding='utf-8') as file:
            for item in data_list:
                elapsed_time, result = item
                channel_name, channel_url = result.split(',')
                file.write(f"{channel_name},{channel_url}\n")

    iptv_speed_file_path = os.path.join(os.getcwd(), 'iptv_speed.txt')
    write_list(iptv_speed_file_path, results)

    for elapsed_time, result in results:
        channel_name, channel_url = result.split(',')
        print(f"检测成功  {channel_name},{channel_url}  响应时间 ：{elapsed_time:.0f} 毫秒")

    local_channels_directory = os.path.join(os.getcwd(), '地方频道')
    if not os.path.exists(local_channels_directory):
        os.makedirs(local_channels_directory)
        print(f"目录 '{local_channels_directory}' 已创建。")
    else:
        clear_txt_files(local_channels_directory)

    template_directory = os.path.join(os.getcwd(), '频道模板')
    if not os.path.exists(template_directory):
        os.makedirs(template_directory)
        print(f"目录 '{template_directory}' 已创建。")
    template_files = [f for f in os.listdir(template_directory) if f.endswith('.txt')]

    iptv_speed_channels = read_txt_to_array(iptv_speed_file_path)

    for template_file in template_files:
        template_channels = read_txt_to_array(os.path.join(template_directory, template_file))
        template_name = os.path.splitext(template_file)[0]
        matched_channels = [channel for channel in iptv_speed_channels if
                            channel.split(',')[0] in template_channels]
        def channel_key(channel_name):
            match = re.search(r'\d+', channel_name)
            if match:
                return int(match.group())
            else:
                return float('inf')
        matched_channels.sort(key=lambda x: channel_key(x.split(',')[0]))
        output_file_path = os.path.join(local_channels_directory, f"{template_name}_iptv.txt")
        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(f"{template_name},#genre#\n")
            for channel in matched_channels:
                f.write(channel + '\n')
        print(f"频道列表已写入: {template_name}_iptv.txt")

    def merge_iptv_files():
        merged_content = ""
        iptv_files = [f for f in os.listdir(local_channels_directory) if f.endswith('_iptv.txt')]
        central_channel_file = "央视频道_iptv.txt"
        satellite_channel_file = "卫视频道_iptv.txt"
        hunan_channel_file = "湖南频道_iptv.txt"
        hk_taiwan_channel_file = "港台频道_iptv.txt"
        ordered_files = [central_channel_file, satellite_channel_file, hunan_channel_file, hk_taiwan_channel_file]
        for file_name in ordered_files:
            if file_name in iptv_files:
                file_path = os.path.join(local_channels_directory, file_name)
                with open(file_path, "r", encoding="utf-8") as file:
                    merged_content += file.read() + "\n"
                iptv_files.remove(file_name)
        for file_name in sorted(iptv_files):
            file_path = os.path.join(local_channels_directory, file_name)
            with open(file_path, "r", encoding="utf-8") as file:
                merged_content += file.read() + "\n"
        now = datetime.now()
        update_time_line = f"更新时间,#genre#\n{now.strftime('%Y-%m-%d')},url\n{now.strftime('%H:%M:%S')},url\n"
        iptv_list_file_path = "iptv_list.txt"
        with open(iptv_list_file_path, "w", encoding="utf-8") as iptv_list_file:
            iptv_list_file.write(update_time_line)
            channels_grouped = {}
            for line in merged_content.split('\n'):
                if line:
                    parts = line.split(',')
                    channel_name = parts[0]
                    channel_url = parts[1]
                    if channel_name not in channels_grouped:
                        channels_grouped[channel_name] = []
                    channels_grouped[channel_name].append(line)
            for channel_name in channels_grouped:
                channels_grouped[channel_name] = channels_grouped[channel_name][:200]
            for channel_name in channels_grouped:
                for channel_line in channels_grouped[channel_name]:
                    iptv_list_file.write(channel_line + '\n')
        try:
            os.remove('iptv.txt')
            os.remove('iptv_speed.txt')
            print(f"临时文件 iptv.txt 和 iptv_speed.txt 已删除。")
        except OSError as e:
            print(f"删除临时文件时发生错误: {e}")
        print(f"\n所有地区频道列表文件合并完成，文件保存为：{iptv_list_file_path}")

    merge_iptv_files()

if __name__ == "__main__":
    main()
