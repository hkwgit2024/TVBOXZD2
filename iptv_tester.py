import requests
import re
import json # 尽管不再直接加载config.json，但json库可能仍用于其他调试或未来功能
import os
import yaml # 导入 PyYAML 库

# 定义输入和输出文件
RAW_IPTV_URL = "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/iptv_list.txt"
CATEGORIES_FILE = "categories.yaml" # 修改为 YAML 文件名
OUTPUT_FILE = "tv.list.txt"

def check_link_connectivity(url: str) -> bool:
    """
    占位符：检查IPTV链接的连通性。
    Args:
        url: IPTV链接。
    Returns:
        如果链接可达且返回状态码小于400，则为True，否则为False。
    """
    if not url.startswith("http"):
        return False
    try:
        response = requests.get(url, timeout=5, stream=True) 
        if 200 <= response.status_code < 400:
            return True
        return False
    except requests.exceptions.RequestException:
        return False

def load_categories_config():
    """加载分类配置文件 (YAML 格式)"""
    if os.path.exists(CATEGORIES_FILE):
        with open(CATEGORIES_FILE, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    print(f"警告: {CATEGORIES_FILE} 文件未找到，将使用默认空分类配置。")
    # 提供一个默认的空配置，以确保脚本不会崩溃
    return {"新闻": [], "电影": [], "卡通": [], "综艺": [], "其他": []}

def save_tv_list(categorized_channel_names):
    """将分类后的频道名称保存到tv.list.txt，按照指定格式"""
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        for category, channel_names in categorized_channel_names.items():
            f.write(f"{category}:\n")
            if channel_names:
                for name in sorted(channel_names): # 按名称排序输出
                    f.write(f"  - {name}\n")
            else:
                f.write("  - []\n") # 如果该分类下没有频道，输出 - []
            f.write("\n") # 每个分类后空一行

def main():
    print(f"开始处理 IPTV 列表...")
    
    # 1. 下载原始 IPTV 列表
    try:
        response = requests.get(RAW_IPTV_URL, timeout=10)
        response.raise_for_status()  # 检查HTTP错误
        raw_content = response.text
        print(f"成功下载原始 IPTV 列表。")
    except requests.exceptions.RequestException as e:
        print(f"下载原始 IPTV 列表失败: {e}")
        exit(1)

    # 2. 解析原始内容
    parsed_channels = [] # List of {"name": ..., "url": ...}
    lines = raw_content.splitlines()
    for line in lines:
        # 使用正则表达式匹配 "频道名称,链接" 的模式
        match = re.match(r'([^,]+),(https?://.*)', line)
        if match:
            name = match.group(1).strip()
            url = match.group(2).strip()
            parsed_channels.append({"name": name, "url": url})

    print(f"从原始列表中解析到 {len(parsed_channels)} 个频道条目 (名称,链接对)。")

    # 3. 加载分类配置文件
    defined_categories = load_categories_config()
    # 假设 additional_channels 不再通过 categories.yaml 管理，如果需要，请告诉我如何处理

    # 4. 合并所有待处理的频道 (目前只来自原始IPTV列表)，并建立一个 name -> [working_url1, working_url2, ...] 的映射
    channel_name_to_working_urls = {}
    all_channels_to_process = parsed_channels # 此时只包含从 RAW_IPTV_URL 解析出的频道

    print("开始检查所有频道的连通性...")
    total_checked_urls = 0
    total_working_urls = 0

    for channel_data in all_channels_to_process:
        name = channel_data["name"]
        url = channel_data["url"]
        
        total_checked_urls += 1
        if check_link_connectivity(url):
            if name not in channel_name_to_working_urls:
                channel_name_to_working_urls[name] = []
            channel_name_to_working_urls[name].append(url)
            total_working_urls += 1
            # print(f"  [可用] {name}: {url}") # 调试用
        # else:
            # print(f"  [不可用] {name}: {url}") # 调试用

    print(f"总共检查了 {total_checked_urls} 个URL，其中 {total_working_urls} 个URL连通。")
    print(f"发现 {len(channel_name_to_working_urls)} 个频道名称至少有一个可用URL。")

    # 5. 根据配置文件中的分类列表生成最终输出结构
    final_categorized_output_names = {}
    
    # 初始化所有自定义分类
    for category_name in defined_categories.keys():
        final_categorized_output_names[category_name] = []

    # 填充明确指定分类的频道
    for category_name, expected_channel_names in defined_categories.items():
        for expected_name in expected_channel_names:
            if expected_name in channel_name_to_working_urls and channel_name_to_working_urls[expected_name]:
                # 只有当这个频道名称有可用的URL时才加入最终列表
                final_categorized_output_names[category_name].append(expected_name)
    
    # 处理 "其他" 分类，将所有未明确分类且有可用URL的频道放入
    # 找到所有在 categories.yaml 的 categories 中没有出现过的 channel_name，并且这些 channel_name 必须有可用的URL
    all_explicitly_listed_names = set()
    for names_list in defined_categories.values():
        all_explicitly_listed_names.update(names_list)

    other_channels_found = []
    for name in channel_name_to_working_urls.keys():
        if name not in all_explicitly_listed_names:
            other_channels_found.append(name)
    
    # 确保 '其他' 分类存在 (从 categories.yaml 加载时已经初始化了，或在默认配置中)
    if '其他' not in final_categorized_output_names:
        final_categorized_output_names['其他'] = []
    
    # 将找到的 '其他' 频道添加到 '其他' 分类中
    final_categorized_output_names['其他'].extend(other_channels_found)


    # 6. 保存到文件
    save_tv_list(final_categorized_output_names)
    print(f"处理完成，连通并分类的频道已保存到 {OUTPUT_FILE}。")

if __name__ == "__main__":
    main()
