# 文件名: iptv_tester.py

import requests
import re
import os
import yaml 
import concurrent.futures 
from urllib.parse import urljoin # 导入 urljoin 用于更健壮的 URL 处理

# 定义输入和输出文件
LOCAL_IPTV_FILE = "iptv_list.txt" # 本地 IPTV 列表文件路径
CATEGORIES_FILE = "categories.yaml" # 分类配置文件路径
OUTPUT_FILE = "tv.list.txt" # 输出文件路径

# 设置并发工作线程的数量
# 请根据您的网络和目标服务器的承受能力调整，太高可能被认为是DDoS
# 一般来说，20-50 个线程对大多数情况都适用
MAX_WORKERS = 50 

def check_link_connectivity(channel_data: dict) -> tuple:
    """
    检查IPTV链接的连通性。
    对于 .m3u8 链接，会尝试进一步检查其内部子链接的有效性，并判断是否为直播流。
    Args:
        channel_data: 包含 'name' 和 'url' 的字典。
    Returns:
        一个元组 (channel_data, is_working)，指示链接是否可用。
    """
    name = channel_data['name']
    url = channel_data['url']

    # 检查URL是否以http开头，避免处理无效格式的URL
    if not url.startswith("http"):
        return (channel_data, False)
    
    # 设置User-Agent，模拟浏览器请求，避免某些服务器拒绝默认的python-requests
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    try:
        # 首先检查主链接的连通性，设置10秒超时
        response = requests.get(url, timeout=10, stream=True, headers=headers) 
        # 检查HTTP状态码，2xx 和 3xx 都视为成功
        if not (200 <= response.status_code < 400):
            return (channel_data, False) # 主链接不可用
        
        # 如果是 M3U8 链接，尝试进行更深层次的检查
        if '.m3u8' in url:
            m3u8_content = ""
            # 设置M3U8文件下载内容限制为 58KB
            content_limit = 58 * 1024 
            downloaded_size = 0
            # 迭代下载M3U8内容，每次1KB，直到达到限制
            for chunk in response.iter_content(chunk_size=1024): 
                m3u8_content += chunk.decode('utf-8', errors='ignore')
                downloaded_size += len(chunk)
                if downloaded_size >= content_limit: # 当下载内容达到58KB时停止
                    break
            
            # **新增检查1：判断是否为VOD（点播）流或已结束的流**
            # 直播M3U8通常不包含#EXT-X-ENDLIST，或EXT-X-PLAYLIST-TYPE:VOD
            if "#EXT-X-ENDLIST" in m3u8_content or "EXT-X-PLAYLIST-TYPE:VOD" in m3u8_content:
                return (channel_data, False) # 视为非直播流（点播或已结束的直播）

            # 查找M3U8文件中的第一个 .ts 或 .m3u8 子链接进行连通性验证
            # 这个子链接通常是实际的媒体片段或嵌套的播放列表
            sub_link_match = re.search(r'(https?://[^"\s]+?\.m3u8|\S+\.ts)', m3u8_content)
            
            if sub_link_match:
                sub_link = sub_link_match.group(0)
                # 使用 urljoin 稳健地处理相对路径，将其转换为完整的URL
                full_sub_link = urljoin(url, sub_link) 
                
                # 尝试检查子链接的连通性，给更短的5秒超时，因为这是内部链接
                try:
                    sub_response = requests.get(full_sub_link, timeout=5, stream=True, headers=headers)
                    if not (200 <= sub_response.status_code < 400):
                        return (channel_data, False) # 子链接不可用
                except requests.exceptions.RequestException:
                    return (channel_data, False) # 子链接请求失败
            else:
                # 如果M3U8文件中没有找到有效的子链接（例如，M3U8内容为空或格式异常）
                return (channel_data, False) 
        
        # 对于非M3U8链接（如mp4、flv等），只要主链接可用就视为可用
        return (channel_data, True) 

    # 捕获各种请求异常，任何网络问题都视为链接不可用
    except requests.exceptions.Timeout:
        return (channel_data, False)
    except requests.exceptions.ConnectionError:
        return (channel_data, False)
    except requests.exceptions.RequestException: # 捕获所有其他requests异常
        return (channel_data, False)

def load_categories_config():
    """加载分类配置文件 (YAML 格式)"""
    if os.path.exists(CATEGORIES_FILE):
        with open(CATEGORIES_FILE, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    print(f"警告: {CATEGORIES_FILE} 文件未找到，将使用默认空分类配置。")
    # 提供一个默认的空分类配置，包含“其他”类别
    return {"新闻": [], "电影": [], "卡通": [], "综艺": [], "其他": []}

def parse_iptv_content(content: str) -> list:
    """
    解析 IPTV 列表内容，从每行提取频道名称和URL。
    Args:
        content: IPTV 列表的字符串内容。
    Returns:
        一个包含 {"name": ..., "url": ...} 字典的列表。
    """
    parsed_channels = []
    lines = content.splitlines()
    for line in lines:
        # 使用正则表达式匹配“名称,URL”格式的行
        match = re.match(r'([^,]+),(https?://.*)', line)
        if match:
            name = match.group(1).strip()
            url = match.group(2).strip()
            parsed_channels.append({"name": name, "url": url})
    return parsed_channels

def save_tv_list(categorized_channel_names: dict, channel_urls_map: dict):
    """
    将分类后的频道名称和其对应的所有可用URL保存到tv.list.txt。
    Args:
        categorized_channel_names: 按类别分组的频道名称 {category: [name1, name2, ...]}
        channel_urls_map: 频道名称到可用URL列表的映射 {name: [url1, url2, ...]}
    """
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for category, channel_names in categorized_channel_names.items():
            f.write(f"{category}:\n")
            if channel_names:
                # 按照名称排序，然后查找对应的所有可用URL
                for name in sorted(channel_names):
                    # 确保在 channel_urls_map 中有对应项且有可用URL
                    if name in channel_urls_map and channel_urls_map[name]:
                        # 遍历并写入该频道名称下的所有可用URL
                        for available_url in channel_urls_map[name]:
                            f.write(f"  - {name},{available_url}\n") # 写入名称和URL，每个URL一行
                    else:
                        # 理论上，所有在 categorized_channel_names 中的频道都应该有可用URL
                        # 如果出现这种情况，可能是数据处理逻辑有误，这里作为回退
                        f.write(f"  - {name},#NoAvailableURLFound#\n") 
            else:
                # 如果某个分类下没有可用频道，则写入空列表标识
                f.write("  - []\n") 
            f.write("\n") # 每个分类后加一个空行，保持可读性

def main():
    print(f"开始处理 IPTV 列表...")
    
    all_channels_to_process = []

    # 1. 尝试读取本地 IPTV 列表文件 
    if os.path.exists(LOCAL_IPTV_FILE):
        try:
            with open(LOCAL_IPTV_FILE, 'r', encoding='utf-8') as f:
                local_content = f.read()
                local_parsed = parse_iptv_content(local_content)
                all_channels_to_process.extend(local_parsed)
                print(f"成功从本地 {LOCAL_IPTV_FILE} 解析到 {len(local_parsed)} 个频道条目。")
        except Exception as e:
            print(f"读取本地 {LOCAL_IPTV_FILE} 失败: {e}")
            print("未能读取本地 IPTV 列表，脚本无法继续。退出。")
            exit(1)
    else:
        print(f"错误: 本地 {LOCAL_IPTV_FILE} 文件未找到。脚本无法继续。")
        exit(1)

    if not all_channels_to_process:
        print("未找到任何 IPTV 频道进行处理。脚本退出。")
        exit(0) 

    print(f"总共收集到 {len(all_channels_to_process)} 个频道条目待处理。")

    # 3. 加载分类配置文件
    defined_categories = load_categories_config()

    # 4. 建立一个 name -> [working_url1, working_url2, ...] 的映射
    # 用于存储每个频道名称对应的所有可用的URL
    channel_name_to_working_urls = {}

    print("开始检查所有频道的连通性 (并发模式)...")
    total_checked_urls = 0
    total_working_urls = 0

    # 使用 ThreadPoolExecutor 进行并发测试，利用多线程加速I/O密集型任务
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # 提交所有链接测试任务，并创建一个future对象到原始频道数据的映射
        future_to_channel_data = {executor.submit(check_link_connectivity, channel_data): channel_data 
                                  for channel_data in all_channels_to_process}
        
        # 实时获取结果并更新进度
        for future in concurrent.futures.as_completed(future_to_channel_data):
            channel_data_original = future_to_channel_data[future]
            name = channel_data_original['name']
            url = channel_data_original['url']

            try:
                channel_data_result, is_working = future.result() # 获取测试结果
                total_checked_urls += 1
                if is_working:
                    # 如果链接可用，将其添加到对应频道名称的可用URL列表中
                    if name not in channel_name_to_working_urls:
                        channel_name_to_working_urls[name] = []
                    channel_name_to_working_urls[name].append(url)
                    total_working_urls += 1
                # 打印一个简要的进度，每处理一定数量的URL打印一次，避免日志过长
                if total_checked_urls % 50 == 0 or total_checked_urls == len(all_channels_to_process):
                    print(f"  进度: {total_checked_urls}/{len(all_channels_to_process)} URL已测试。")

            except Exception as exc:
                total_checked_urls += 1
                # 打印测试过程中出现的异常，通常是网络中断等问题
                print(f"  [{total_checked_urls}/{len(all_channels_to_process)}] {name}: {url} -> 测试出现异常: {exc}")
                # 即使出现异常也更新进度

    print(f"连通性检查完成。")
    print(f"总共检查了 {total_checked_urls} 个URL，其中 {total_working_urls} 个URL连通。")
    print(f"发现 {len(channel_name_to_working_urls)} 个频道名称至少有一个可用URL。")

    # 5. 根据配置文件中的分类列表生成最终输出结构
    final_categorized_output_names = {}
    
    # 初始化所有在 categories.yaml 中定义的分类
    for category_name in defined_categories.keys():
        final_categorized_output_names[category_name] = []

    # 填充明确指定分类的频道：只有当频道有可用URL时才被分类
    for category_name, expected_channel_names in defined_categories.items():
        for expected_name in expected_channel_names:
            if expected_name in channel_name_to_working_urls and channel_name_to_working_urls[expected_name]:
                final_categorized_output_names[category_name].append(expected_name)
    
    # 找出所有在 categories.yaml 中未明确列出，但在iptv_list.txt中存在且有可用URL的频道
    all_explicitly_listed_names = set()
    for names_list in defined_categories.values():
        all_explicitly_listed_names.update(names_list)

    other_channels_found = []
    for name in channel_name_to_working_urls.keys():
        if name not in all_explicitly_listed_names:
            other_channels_found.append(name)
    
    # 确保存在“其他”分类，并将未明确分类的频道添加到其中
    if '其他' not in final_categorized_output_names:
        final_categorized_output_names['其他'] = []
    
    final_categorized_output_names['其他'].extend(other_channels_found)


    # 6. 保存到文件，将分类后的频道名称和它们的可用URL列表传入保存函数
    save_tv_list(final_categorized_output_names, channel_name_to_working_urls)
    print(f"处理完成，连通并分类的频道已保存到 {OUTPUT_FILE}。")

if __name__ == "__main__":
    main()
