# 文件名: iptv_tester.py

import requests
import re
import json 
import os
import yaml 

# 定义输入和输出文件
# RAW_IPTV_URL = "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/iptv_list.txt"
LOCAL_IPTV_FILE = "iptv_list.txt" # 本地 IPTV 列表文件路径
CATEGORIES_FILE = "categories.yaml" 
OUTPUT_FILE = "tv.list.txt"

def check_link_connectivity(url: str) -> bool:
    """
    检查IPTV链接的连通性。
    Args:
        url: IPTV链接。
    Returns:
        如果链接可达且返回状态码小于400，则为True，否则为False。
    """
    if not url.startswith("http"):
        # print(f"  [跳过非HTTP/HTTPS] {url}") # 调试用
        return False
    try:
        # 增加超时时间，以应对网络波动，但不要太长
        response = requests.get(url, timeout=10, stream=True) # 将超时时间调整为10秒
        if 200 <= response.status_code < 400:
            # print(f"  [可用] {url} (状态码: {response.status_code})") # 调试用
            return True
        else:
            # print(f"  [不可用] {url} (状态码: {response.status_code})") # 调试用
            return False
    except requests.exceptions.Timeout:
        # print(f"  [超时] {url}") # 调试用
        return False
    except requests.exceptions.ConnectionError:
        # print(f"  [连接错误] {url}") # 调试用
        return False
    except requests.exceptions.RequestException as e:
        # print(f"  [请求异常] {url}: {e}") # 调试用
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
    else:
        print(f"本地 {LOCAL_IPTV_FILE} 文件未找到，跳过本地文件读取。")


    # 2. 下载并解析远程 IPTV 列表
    try:
        print(f"尝试从远程 {RAW_IPTV_URL} 下载 IPTV 列表...")
        response = requests.get(RAW_IPTV_URL, timeout=15) # 提高下载超时时间
        response.raise_for_status() 
        raw_content = response.text
        remote_parsed = parse_iptv_content(raw_content)
        all_channels_to_process.extend(remote_parsed)
        print(f"成功从远程 {RAW_IPTV_URL} 解析到 {len(remote_parsed)} 个频道条目。")
    except requests.exceptions.RequestException as e:
        print(f"下载远程 IPTV 列表失败: {e}")
        if not all_channels_to_process: # 如果本地和远程都失败，且没有频道，则退出
            print("未获取到任何频道数据，无法继续。")
            exit(1)
        print("将继续处理已获取的频道（如果存在）。")

    if not all_channels_to_process:
        print("未找到任何 IPTV 频道进行处理。脚本退出。")
        exit(0) # 没有频道可处理，正常退出

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
        # 打印当前正在测试的 URL，帮助调试
        print(f"  正在测试 [{total_checked_urls}/{len(all_channels_to_process)}] {name}: {url}")
        
        if check_link_connectivity(url):
            if name not in channel_name_to_working_urls:
                channel_name_to_working_urls[name] = []
            channel_name_to_working_urls[name].append(url)
            total_working_urls += 1
            print(f"    -> 可用。") # 仅在可用时打印确认信息
        else:
            print(f"    -> 不可用。") # 仅在不可用时打印确认信息

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
