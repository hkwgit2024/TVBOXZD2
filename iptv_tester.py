# 文件名: iptv_tester.py

import requests
import re
import os
import yaml 

# 定义输入和输出文件
LOCAL_IPTV_FILE = "iptv_list.txt" # 本地 IPTV 列表文件路径
CATEGORIES_FILE = "categories.yaml" 
OUTPUT_FILE = "tv.list.txt"

def check_link_connectivity(url: str) -> bool:
    """
    检查IPTV链接的连通性。
    对于 .m3u8 链接，会尝试进一步检查其内部子链接的有效性。
    Args:
        url: IPTV链接。
    Returns:
        如果链接可达且返回状态码小于400，并且对于m3u8能进一步验证，则为True，否则为False。
    """
    if not url.startswith("http"):
        return False
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    try:
        # 首先检查主链接的连通性
        response = requests.get(url, timeout=10, stream=True, headers=headers) 
        if not (200 <= response.status_code < 400):
            return False # 主链接不可用
        
        # 如果是 M3U8 链接，尝试进行更深层次的检查
        if '.m3u8' in url:
            # 尝试下载部分M3U8内容，不下载完整文件以节省资源
            m3u8_content = ""
            for chunk in response.iter_content(chunk_size=1024): # 只下载前1KB
                m3u8_content += chunk.decode('utf-8', errors='ignore')
                if len(m3u8_content) >= 1024:
                    break
            
            # 查找M3U8文件中的第一个 .ts 或 .m3u8 子链接
            # 匹配相对路径或绝对路径的URL
            sub_link_match = re.search(r'(https?://[^"\s]+?\.m3u8|\S+\.ts)', m3u8_content)
            
            if sub_link_match:
                sub_link = sub_link_match.group(0)
                # 如果是相对路径，需要拼接完整URL
                if not sub_link.startswith("http"):
                    # 获取主URL的基路径
                    base_url_match = re.match(r'(https?://[^/]+(?:/[^/?#]*)*)/?', url)
                    if base_url_match:
                        base_url = base_url_match.group(0)
                        sub_link = os.path.join(base_url, sub_link).replace("\\", "/") # 拼接并处理反斜杠
                    else:
                        return False # 无法解析基路径
                
                # 尝试检查子链接的连通性，给更短的超时
                try:
                    sub_response = requests.get(sub_link, timeout=5, stream=True, headers=headers)
                    if not (200 <= sub_response.status_code < 400):
                        return False # 子链接不可用
                except requests.exceptions.RequestException:
                    return False # 子链接请求失败
            else:
                # 可能是空的M3U8或者只包含 EXTINF 而没有实际的流链接，也视为不可用
                # 或者它是一个聚合M3U，需要更复杂的解析，这里简化处理
                # print(f"  [M3U8无有效子链接] {url}") # 调试用
                return False 
        
        return True # 主链接可用，且如果是M3U8，子链接也验证通过

    except requests.exceptions.Timeout:
        return False
    except requests.exceptions.ConnectionError:
        return False
    except requests.exceptions.RequestException:
        return False

def load_categories_config():
    """加载分类配置文件 (YAML 格式)"""
    if os.path.exists(CATEGORIES_FILE):
        with open(CATEGORIES_FILE, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    print(f"警告: {CATEGORIES_FILE} 文件未找到，将使用默认空分类配置。")
    return {"新闻": [], "电影": [], "卡通": [], "综艺": [], "其他": []}

def parse_iptv_content(content: str) -> list:
    """
    解析 IPTV 列表内容。
    Args:
        content: IPTV 列表的字符串内容。
    Returns:
        一个包含 {"name": ..., "url": ...} 字典的列表。
    """
    parsed_channels = []
    lines = content.splitlines()
    for line in lines:
        match = re.match(r'([^,]+),(https?://.*)', line)
        if match:
            name = match.group(1).strip()
            url = match.group(2).strip()
            parsed_channels.append({"name": name, "url": url})
    return parsed_channels

def save_tv_list(categorized_channel_names):
    """将分类后的频道名称保存到tv.list.txt，按照指定格式"""
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for category, channel_names in categorized_channel_names.items():
            f.write(f"{category}:\n")
            if channel_names:
                for name in sorted(channel_names): # 按名称排序输出
                    f.write(f"  - {name}\n")
            else:
                f.write("  - []\n") 
            f.write("\n") 

def main():
    print(f"开始处理 IPTV 列表...")
    
    all_channels_to_process = []

    # 1. 尝试读取本地 IPTV 列表文件 (现在这是唯一的输入来源)
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
    channel_name_to_working_urls = {}

    print("开始检查所有频道的连通性...")
    total_checked_urls = 0
    total_working_urls = 0

    for channel_data in all_channels_to_process:
        name = channel_data["name"]
        url = channel_data["url"]
        
        total_checked_urls += 1
        print(f"  正在测试 [{total_checked_urls}/{len(all_channels_to_process)}] {name}: {url}")
        
        if check_link_connectivity(url):
            if name not in channel_name_to_working_urls:
                channel_name_to_working_urls[name] = []
            channel_name_to_working_urls[name].append(url)
            print(f"    -> 可用。")
        else:
            print(f"    -> 不可用。")

    print(f"连通性检查完成。")
    print(f"总共检查了 {total_checked_urls} 个URL，其中 {total_working_urls} 个URL连通。")
    print(f"发现 {len(channel_name_to_working_urls)} 个频道名称至少有一个可用URL。")

    # 5. 根据配置文件中的分类列表生成最终输出结构
    final_categorized_output_names = {}
    
    for category_name in defined_categories.keys():
        final_categorized_output_names[category_name] = []

    for category_name, expected_channel_names in defined_categories.items():
        for expected_name in expected_channel_names:
            if expected_name in channel_name_to_working_urls and channel_name_to_working_urls[expected_name]:
                final_categorized_output_names[category_name].append(expected_name)
    
    all_explicitly_listed_names = set()
    for names_list in defined_categories.values():
        all_explicitly_listed_names.update(names_list)

    other_channels_found = []
    for name in channel_name_to_working_urls.keys():
        if name not in all_explicitly_listed_names:
            other_channels_found.append(name)
    
    if '其他' not in final_categorized_output_names:
        final_categorized_output_names['其他'] = []
    
    final_categorized_output_names['其他'].extend(other_channels_found)


    # 6. 保存到文件
    save_tv_list(final_categorized_output_names)
    print(f"处理完成，连通并分类的频道已保存到 {OUTPUT_FILE}。")

if __name__ == "__main__":
    main()
