import os
import re
from thefuzz import fuzz, process
from collections import defaultdict, OrderedDict
import logging
from datetime import datetime
import time
from tqdm import tqdm

# --- 全局配置和常量 ---
CATEGORY_CONFIG_PATH = "config/demo.txt"
INPUT_CHANNELS_PATH = "output/valid_channels_temp.txt"
FINAL_IPTV_LIST_PATH = "output/iptv_list.m3u" # 修改为 .m3u 格式
UNCATEGORIZED_CHANNELS_PATH = "output/uncategorized.txt"

SIMILARITY_THRESHOLD = 90  # 使用更高的阈值，精确匹配

# EPG 节目单链接，你可以根据需要修改
EPG_URL = "https://epg.112114.xyz/pp.xml"

# --- 辅助函数：配置加载和日志 ---
def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("function.log", "w", encoding="utf-8"),
            logging.StreamHandler()
        ]
    )

def parse_category_template(template_file):
    """
    解析模板文件，提取频道分类和频道名称。
    :param template_file: 模板文件路径
    :return: 包含频道分类和频道名称的有序字典
    """
    template_channels = OrderedDict()
    current_category = None
    ordered_categories = []

    try:
        with open(template_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if "#genre#" in line:
                    current_category = line.split(",")[0].strip()
                    if current_category not in ordered_categories:
                        ordered_categories.append(current_category)
                    template_channels[current_category] = []
                elif current_category:
                    keywords = [kw.strip() for kw in line.split('|') if kw.strip()]
                    template_channels[current_category].extend(keywords)

        logging.info("分类模板文件 demo.txt 加载成功")
        return template_channels, ordered_categories
    except FileNotFoundError:
        logging.error(f"错误：未找到分类模板文件 '{template_file}'。请检查路径。")
        return None, None
    except Exception as e:
        logging.error(f"解析分类模板文件 '{template_file}' 失败: {e}")
        return None, None

def read_channels_from_file(file_name):
    """从本地 TXT 文件读取频道内容"""
    channels = []
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            for line in file:
                line = line.strip()
                if line and ',' in line and not line.startswith('#'):
                    parts = line.split(',', 1)
                    if len(parts) == 2:
                        channels.append((parts[0].strip(), parts[1].strip()))
        logging.info(f"从 {file_name} 读取 {len(channels)} 个频道")
    except FileNotFoundError:
        logging.error(f"错误：未找到输入频道文件 '{file_name}'。请确保已运行 check_channels_validity.py。")
        return None
    except Exception as e:
        logging.error(f"读取文件 '{file_name}' 失败: {e}")
        return None
    return channels

# --- 核心业务逻辑：频道处理 ---
def categorize_channels(channels, template_channels, ordered_categories):
    """根据模板进行频道分类"""
    categorized_data = defaultdict(lambda: defaultdict(list))
    uncategorized_data = []
    
    # 提取所有模板中的关键词，供模糊匹配使用
    all_template_keywords = [
        (keyword, category, main_channel_name)
        for category, keywords in template_channels.items()
        for keyword in keywords
        for main_channel_name in [keywords[0]] # 将列表的第一个关键词作为主频道名
    ]
    
    logging.info(f"开始分类 {len(channels)} 个频道...")
    
    for name, url in tqdm(channels, desc="正在分类频道"):
        found_match = False
        
        # 尝试与所有模板关键词进行模糊匹配
        matches = process.extractOne(name, [item[0] for item in all_template_keywords], scorer=fuzz.token_set_ratio)
        
        if matches and matches[1] >= SIMILARITY_THRESHOLD:
            matched_keyword = matches[0]
            score = matches[1]
            
            # 找到匹配的关键词，根据关键词找到其对应的分类和主频道名
            for keyword, category, main_name in all_template_keywords:
                if keyword == matched_keyword:
                    # 使用主频道名作为最终归类名称
                    categorized_data[category][main_name].append((name, url))
                    found_match = True
                    break
        
        if not found_match:
            uncategorized_data.append((name, url))

    return categorized_data, uncategorized_data

# --- 结果保存模块（已修改为 M3U 格式） ---
def save_channels_to_files(categorized_data, uncategorized_data, ordered_categories, output_file, uncat_file, epg_url):
    """将分类结果保存到最终 M3U 文件"""
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    os.makedirs(os.path.dirname(uncat_file), exist_ok=True)

    # --- 保存为 M3U 格式 ---
    try:
        with open(output_file, "w", encoding='utf-8') as iptv_list_file:
            # M3U 文件必须以 #EXTM3U 开头
            # tvg-id 和 tvg-name 的值通常是频道名的拼音，以便与 EPG 节目表匹配
            iptv_list_file.write(f'#EXTM3U url-tvg="{epg_url}"\n')
            
            # 按 demo.txt 中的类别顺序进行保存
            for category in ordered_categories:
                if category in categorized_data and categorized_data[category]:
                    # #EXTGRP 是 M3U 格式中的分组标签
                    iptv_list_file.write(f'\n#EXTGRP:{category}\n')
                    
                    # 按主频道名称排序，确保输出顺序稳定
                    for main_name in sorted(categorized_data[category].keys()):
                        # 写入主频道名，并只保留一个URL
                        # 对于每个频道，写入 #EXTINF 标签和 URL
                        for original_name, url in sorted(categorized_data[category][main_name], key=lambda x: x[0]):
                            # #EXTINF 格式: #EXTINF:-1 tvg-id="频道ID" tvg-name="频道名称" group-title="分类",频道显示名称
                            # tvg-id 和 tvg-name 通常用于关联 EPG
                            iptv_list_file.write(f'#EXTINF:-1 tvg-id="{main_name}" tvg-name="{main_name}" group-title="{category}",{original_name}\n')
                            iptv_list_file.write(f'{url}\n')
            
        logging.info(f"所有有效频道已分类并保存到: {output_file}")
    except Exception as e:
        logging.error(f"写入文件 '{output_file}' 失败: {e}")

    # --- 保存未分类频道，仍使用原来的 TXT 格式 ---
    try:
        with open(uncat_file, "w", encoding='utf-8') as uncat_file:
            header = [
                f"更新日期,#genre#\n",
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')},url\n"
            ]
            uncat_file.writelines(header)
            if uncategorized_data:
                uncat_file.write(f"\n未分类频道,#genre#\n")
                # 按频道名称排序
                for name, url in sorted(uncategorized_data, key=lambda x: x[0]):
                    uncat_file.write(f"{name},{url}\n")
        logging.info(f"未分类频道已保存到: {uncat_file}")
    except Exception as e:
        logging.error(f"写入未分类文件 '{uncat_file}' 失败: {e}")

# --- 主函数 ---
def main():
    """主函数，执行 IPTV 频道分类和保存流程"""
    setup_logging()
    logging.info("开始执行 IPTV 频道分类和保存脚本...")
    total_start_time = time.time()

    if not os.path.exists('output'):
        os.makedirs('output')
    if not os.path.exists('config'):
        os.makedirs('config')

    template_channels, ordered_categories = parse_category_template(CATEGORY_CONFIG_PATH)
    if template_channels is None:
        return

    valid_channels = read_channels_from_file(INPUT_CHANNELS_PATH)
    if not valid_channels:
        logging.warning("没有可用于分类的频道，退出。")
        return

    categorized_channels, uncategorized_channels = categorize_channels(
        valid_channels, template_channels, ordered_categories
    )
    
    # 传递 EPG URL 给保存函数
    save_channels_to_files(categorized_channels, uncategorized_channels, ordered_categories, FINAL_IPTV_LIST_PATH, UNCATEGORIZED_CHANNELS_PATH, EPG_URL)

    total_elapsed_time = time.time() - total_start_time
    logging.info(f"IPTV 频道分类和保存脚本完成，总耗时 {total_elapsed_time:.2f} 秒")

if __name__ == "__main__":
    main()
