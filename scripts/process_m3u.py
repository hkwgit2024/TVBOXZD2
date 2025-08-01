import os
import re
import requests
from urllib.parse import urlparse
from tqdm import tqdm
import time
import hashlib
import json
import datetime # 导入datetime模块用于获取当前时间

# 定义文件路径
CONFIG_URLS_FILE = 'config/urls.txt'
OUTPUT_LIST_FILE = 'output/list.txt'
FAILED_URLS_FILE = 'output/failed_urls.txt'
SUCCESS_URLS_FILE = 'output/successful_urls.txt' # 用于保存所有成功处理的URL
URL_HASHES_FILE = 'output/url_hashes.json' # 用于存储URL及其内容的哈希值

# 扩展正则表达式以匹配更多视频链接格式，例如 .m3u8, .mp4, .flv, .ctv
# 注意：这个正则只匹配URL的最后一部分，如果需要更复杂的匹配，可能需要调整
VIDEO_URL_REGEX = re.compile(
    r'^(http(s)?://)?([\w-]+\.)+[\w-]+(/[\w. /?%&=-]*?)((\.m3u8|\.mp4|\.flv|\.ctv|\.ts|\.mpd|\.webm|\.ogg|\.avi|\.mov|\.wmv))$',
    re.IGNORECASE
)

# 新增的分类标识正则表达式
GENRE_REGEX = re.compile(r'^(.*?),\#genre\#$')

def read_urls_with_categories(filepath):
    """
    从文件中读取带有分类的URL列表。
    返回一个字典，键是分类名，值是该分类下的 (描述, URL) 元组列表。
    """
    categorized_urls = {}
    current_category = "未分类" # 默认分类
    
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'): # 忽略空行和注释
                    continue

                genre_match = GENRE_REGEX.match(line)
                if genre_match:
                    current_category = genre_match.group(1).strip()
                    # 初始化该分类，如果它还不存在
                    if current_category not in categorized_urls:
                        categorized_urls[current_category] = []
                else:
                    # 尝试按逗号分割，提取描述和URL
                    parts = line.rsplit(',', 1) 
                    if len(parts) == 2:
                        description = parts[0].strip()
                        url = parts[1].strip()
                    else:
                        # 如果没有逗号，将整行作为URL，描述为空
                        description = ""
                        url = line.strip()
                    
                    if url: # 确保URL不为空
                        # 如果当前分类还没有列表，初始化它
                        if current_category not in categorized_urls:
                            categorized_urls[current_category] = []
                        categorized_urls[current_category].append((description, url))
    return categorized_urls


def read_urls(filepath):
    """
    从文件中读取纯URL列表，用于 failed_urls 和 successful_urls
    （因为这些文件只存储URL，不包含描述和分类）。
    """
    urls = set()
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                url = line.strip()
                if url and not url.startswith('#'):
                    urls.add(url)
    return urls

def write_urls(filepath, urls):
    """将URL列表写入文件"""
    with open(filepath, 'w', encoding='utf-8') as f:
        for url in sorted(list(urls)):
            f.write(url + '\n')

def read_url_hashes(filepath):
    """从文件中读取URL哈希字典"""
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}

def write_url_hashes(filepath, url_hashes):
    """将URL哈希字典写入文件"""
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(url_hashes, f, indent=4, ensure_ascii=False)

def calculate_content_hash(content):
    """计算内容的SHA256哈希值"""
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def fetch_m3u_content(url):
    """
    从URL获取M3U内容。
    增加超时和错误处理。
    """
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()  # 检查HTTP请求是否成功
        return response.text
    except requests.exceptions.RequestException as e:
        # print(f"Error fetching {url}: {e}") # 过于频繁的错误日志可酌情注释
        return None

def extract_video_links(content):
    """
    从内容中提取符合 VIDEO_URL_REGEX 的链接，包括 M3U8 和 MP4 等。
    """
    extracted_links = set()
    lines = content.splitlines()
    for line in lines:
        line = line.strip()
        if VIDEO_URL_REGEX.match(line):
            extracted_links.add(line)
    return extracted_links

def get_domain(url):
    """从URL中获取域名"""
    return urlparse(url).netloc

def main():
    # 确保输出目录存在
    os.makedirs('output', exist_ok=True)
    os.makedirs('config', exist_ok=True) 

    # 读取带有分类的初始URL
    initial_categorized_urls = read_urls_with_categories(CONFIG_URLS_FILE)
    
    # 将所有URL（不含描述和分类）提取出来，用于过滤失败列表
    all_initial_urls_flat = set()
    for category, url_list in initial_categorized_urls.items():
        for desc, url in url_list:
            all_initial_urls_flat.add(url)

    failed_urls = read_urls(FAILED_URLS_FILE)
    prev_url_hashes = read_url_hashes(URL_HASHES_FILE) 

    # 用于存储最终的分类结果 (分类: [(描述, URL), ...])
    final_categorized_channels = {} 
    
    current_failed_urls = set()
    current_successful_urls = set() # 记录本次运行中成功处理的URL（包括内容未变的）
    updated_url_hashes = prev_url_hashes.copy() # 更新哈希值字典

    # 准备一个扁平的待处理URL列表 for tqdm
    urls_to_process_flat = []
    # 使用一个集合来避免重复处理同一个URL，即使它出现在不同分类下
    processed_urls_set = set() 

    # 将所有待处理的URL（包括描述和分类）扁平化，并过滤掉已知的失败URL
    for category, items in initial_categorized_urls.items():
        for description, url in items:
            if url not in failed_urls and url not in processed_urls_set:
                urls_to_process_flat.append((category, description, url))
                processed_urls_set.add(url) # 标记为已添加到待处理列表

    print(f"开始处理 {len(urls_to_process_flat)} 个URL...")

    start_time = time.time()
    total_urls = len(urls_to_process_flat)

    # 迭代扁平化的URL列表
    for i, (original_category, original_description, url) in enumerate(tqdm(urls_to_process_flat, unit="url", ncols=100, desc="处理URL", disable=False)): # 保持tqdm实时显示
        
        content = fetch_m3u_content(url)
        
        if content:
            current_hash = calculate_content_hash(content)
            
            # 检查内容是否更新
            if url in prev_url_hashes and prev_url_hashes[url] == current_hash:
                current_successful_urls.add(url)
                updated_url_hashes[url] = current_hash 
                # 如果内容未更新，直接将原始的描述和URL添加到最终列表
                if original_category not in final_categorized_channels:
                    final_categorized_channels[original_category] = []
                final_categorized_channels[original_category].append((original_description, url))
                continue # 跳过当前URL的后续处理

            # 内容已更新或首次获取
            extracted_links = extract_video_links(content) # 使用新的提取函数
            
            # 无论是否提取到新的子链接，只要原始内容成功且哈希更新，就将原始URL本身作为节目源
            # 并且将提取到的子链接也加入到该分类下
            if extracted_links:
                if original_category not in final_categorized_channels:
                    final_categorized_channels[original_category] = []
                
                # 先添加原始的URL (描述, URL)
                final_categorized_channels[original_category].append((original_description, url))

                # 再添加从内容中提取出的所有子链接，描述为空
                for link in extracted_links:
                    final_categorized_channels[original_category].append(("", link))
                
                current_successful_urls.add(url)
                updated_url_hashes[url] = current_hash 
            elif VIDEO_URL_REGEX.match(url): # 如果URL本身是视频链接，但内容中没有提取到其他链接，也认为是成功的
                 if original_category not in final_categorized_channels:
                    final_categorized_channels[original_category] = []
                 final_categorized_channels[original_category].append((original_description, url))
                 current_successful_urls.add(url)
                 updated_url_hashes[url] = current_hash 
            else: # 既不是视频链接，内容也无法提取链接
                current_failed_urls.add(url)
                if url in updated_url_hashes:
                    del updated_url_hashes[url]
        else: # 内容获取失败
            current_failed_urls.add(url)
            if url in updated_url_hashes:
                del updated_url_hashes[url]

        # 每处理 1000 个 URL 打印一次详细进度
        if (i + 1) % 1000 == 0:
            elapsed_time = time.time() - start_time
            avg_time_per_url = elapsed_time / (i + 1)
            remaining_urls = total_urls - (i + 1)
            estimated_remaining_time = avg_time_per_url * remaining_urls
            
            percentage = ((i + 1) / total_urls) * 100
            
            print(f"\n进度: {percentage:.2f}% ({i + 1}/{total_urls} 个URL)。 预计剩余时间: {estimated_remaining_time:.2f} 秒 ({estimated_remaining_time / 60:.2f} 分钟)")

    # 排序分类键，然后写入 output/list.txt
    with open(OUTPUT_LIST_FILE, 'w', encoding='utf-8') as f_out:
        # 添加更新时间
        f_out.write(f"更新时间,#genre#\n")
        f_out.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        for category in sorted(final_categorized_channels.keys()):
            f_out.write(f"{category},#genre#\n")
            # 对每个分类下的 (描述, URL) 对进行排序（按描述，然后按URL）
            sorted_items = sorted(list(set(final_categorized_channels[category])), key=lambda x: (x[0], x[1]))
            for description, link in sorted_items:
                if description:
                    f_out.write(f"{description},{link}\n")
                else: # 如果没有描述，只写入链接
                    f_out.write(f"{link}\n")
            f_out.write('\n') # 每个分类之间空一行

    # 更新失败和成功的URL列表
    # successful_urls.txt 和 failed_urls.txt 只保存纯URL
    write_urls(FAILED_URLS_FILE, failed_urls.union(current_failed_urls))
    
    # 重新生成 config/urls.txt，保持原始格式，只保留成功的URL
    # 这里需要根据成功列表重新构建分类结构
    rebuild_config_urls = {}
    for original_category, original_items in initial_categorized_urls.items():
        for original_description, original_url in original_items:
            if original_url in current_successful_urls:
                if original_category not in rebuild_config_urls:
                    rebuild_config_urls[original_category] = []
                rebuild_config_urls[original_category].append((original_description, original_url))

    with open(CONFIG_URLS_FILE, 'w', encoding='utf-8') as f_config:
        for category in sorted(rebuild_config_urls.keys()):
            f_config.write(f"{category},#genre#\n")
            for description, url in rebuild_config_urls[category]:
                 f_config.write(f"{description},{url}\n")
            f_config.write('\n')
            
    # successful_urls.txt 应该只包含本次运行中实际成功（获取到内容且未被标记为失败）的那些原始 URL，
    # 避免它变得无限大。
    # 这里我们只写入本次成功处理的URL集合，而不是累积所有历史成功的URL，
    # 因为哈希文件已经处理了“跳过未更新”的逻辑。
    write_urls(SUCCESS_URLS_FILE, current_successful_urls)
    
    # 保存更新后的URL哈希值
    write_url_hashes(URL_HASHES_FILE, updated_url_hashes)

    print("\n处理完成！")
    print(f"成功提取并分类的节目源已保存到 {OUTPUT_LIST_FILE}")
    print(f"失败的URL已保存到 {FAILED_URLS_FILE}")
    print(f"更新后的 config/urls.txt 已保存。")
    print(f"URL内容哈希已保存到 {URL_HASHES_FILE}。")

if __name__ == "__main__":
    main()
