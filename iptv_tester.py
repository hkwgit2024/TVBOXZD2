# 文件名: iptv_tester.py

import requests
import re
import os
import yaml 
import concurrent.futures 

# 定义输入和输出文件
LOCAL_IPTV_FILE = "iptv_list.txt" 
CATEGORIES_FILE = "categories.yaml" 
OUTPUT_FILE = "tv.list.txt"

# 设置并发工作线程的数量
MAX_WORKERS = 50 

def check_link_connectivity(channel_data: dict) -> tuple:
    """
    检查IPTV链接的连通性。
    对于 .m3u8 链接，会尝试进一步检查其内部子链接的有效性。
    Args:
        channel_data: 包含 'name' 和 'url' 的字典。
    Returns:
        一个元组 (channel_data, is_working)，指示链接是否可用。
    """
    name = channel_data['name']
    url = channel_data['url']

    if not url.startswith("http"):
        return (channel_data, False)
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }
    
    try:
        # 首先检查主链接的连通性
        response = requests.get(url, timeout=10, stream=True, headers=headers) 
        if not (200 <= response.status_code < 400):
            return (channel_data, False) # 主链接不可用
        
        # 如果是 M3U8 链接，尝试进行更深层次的检查
        if '.m3u8' in url:
            m3u8_content = ""
            for chunk in response.iter_content(chunk_size=10240): 
                m3u8_content += chunk.decode('utf-8', errors='ignore')
                if len(m3u8_content) >= 10240:
                    break
            
            # 查找M3U8文件中的第一个 .ts 或 .m3u8 子链接
            sub_link_match = re.search(r'(https?://[^"\s]+?\.m3u8|\S+\.ts)', m3u8_content)
            
            if sub_link_match:
                sub_link = sub_link_match.group(0)
                # 如果是相对路径，需要拼接完整URL
                if not sub_link.startswith("http"):
                    base_url_match = re.match(r'(https?://[^/]+(?:/[^/?#]*)*)/?', url)
                    if base_url_match:
                        base_url = base_url_match.group(0)
                        sub_link = os.path.join(base_url, sub_link).replace("\\", "/") 
                    else:
                        return (channel_data, False) # 无法解析基路径
                
                # 尝试检查子链接的连通性，给更短的超时
                try:
                    sub_response = requests.get(sub_link, timeout=5, stream=True, headers=headers)
                    if not (200 <= sub_response.status_code < 400):
                        return (channel_data, False) # 子链接不可用
                except requests.exceptions.RequestException:
                    return (channel_data, False) # 子链接请求失败
            else:
                return (channel_data, False) # M3U8无有效子链接
        
        return (channel_data, True) # 主链接可用，且如果是M3u8，子链接也验证通过

    except requests.exceptions.Timeout:
        return (channel_data, False)
    except requests.exceptions.ConnectionError:
        return (channel_data, False)
    except requests.exceptions.RequestException:
        return (channel_data, False)

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
                    # 确保在 channel_urls_map 中有对应项且有URL
                    if name in channel_urls_map and channel_urls_map[name]:
                        # 遍历并写入该频道名称下的所有可用URL
                        for available_url in channel_urls_map[name]:
                            f.write(f"  - {name},{available_url}\n") # 写入名称和URL
                    else:
                        # 理论上不会发生，因为 categorized_channel_names 只包含有可用URL的频道
                        f.write(f"  - {name},#NoAvailableURLFound#\n") 
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

    print("开始检查所有频道的连通性 (并发模式)...")
    total_checked_urls = 0
    total_working_urls = 0

    # 使用 ThreadPoolExecutor 进行并发测试
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        # 提交所有链接测试任务
        future_to_channel_data = {executor.submit(check_link_connectivity, channel_data): channel_data for channel_data in all_channels_to_process}
        
        # 实时获取结果并更新进度
        for future in concurrent.futures.as_completed(future_to_channel_data):
            channel_data_original = future_to_channel_data[future]
            name = channel_data_original['name']
            url = channel_data_original['url']

            try:
                channel_data_result, is_working = future.result() 
                total_checked_urls += 1
                if is_working:
                    if name not in channel_name_to_working_urls:
                        channel_name_to_working_urls[name] = []
                    channel_name_to_working_urls[name].append(url)
                    total_working_urls += 1
                # else:
                    # print(f"  [{total_checked_urls}/{len(all_channels_to_process)}] {name}: {url} -> 不可用。")
            except Exception as exc:
                total_checked_urls += 1
                # print(f"  [{total_checked_urls}/{len(all_channels_to_process)}] {name}: {url} -> 测试出现异常: {exc}")

            # 打印一个简要的进度，每处理一定数量的URL打印一次，避免日志过长
            if total_checked_urls % 50 == 0 or total_checked_urls == len(all_channels_to_process):
                print(f"  进度: {total_checked_urls}/{len(all_channels_to_process)} URL已测试。")


    print(f"连通性检查完成。")
    print(f"总共检查了 {total_checked_urls} 个URL，其中 {total_working_urls} 个URL连通。")
    print(f"发现 {len(channel_name_to_working_urls)} 个频道名称至少有一个可用URL。")

    # 5. 根据配置文件中的分类列表生成最终输出结构
    final_categorized_output_names = {}
    
    for category_name in defined_categories.keys():
        final_categorized_output_names[category_name] = []

    # 填充明确指定分类的频道
    for category_name, expected_channel_names in defined_categories.items():
        for expected_name in expected_channel_names:
            # 只有当这个频道名称有可用的URL时才加入最终列表
            if expected_name in channel_name_to_working_urls and channel_name_to_working_urls[expected_name]:
                final_categorized_output_names[category_name].append(expected_name)
    
    # 处理 "其他" 分类，将所有未明确分类且有可用URL的频道放入
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


    # 6. 保存到文件，并传入 channel_name_to_working_urls 映射
    save_tv_list(final_categorized_output_names, channel_name_to_working_urls)
    print(f"处理完成，连通并分类的频道已保存到 {OUTPUT_FILE}。")

if __name__ == "__main__":
    main()
