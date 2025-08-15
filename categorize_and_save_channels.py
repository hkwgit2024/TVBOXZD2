# categorize_and_save_channels.py

import os
import re
import difflib
from collections import defaultdict
import logging
from datetime import datetime
import yaml
import time
from tqdm import tqdm

# --- 全局配置和常量 ---
# 将文件路径定义为常量，提高可读性
CONFIG_PATH = "config/config.yaml"
CATEGORY_CONFIG_PATH = "config/demo.txt"
INPUT_CHANNELS_PATH = "output/valid_channels_temp.txt"
FINAL_IPTV_LIST_PATH = "output/iptv_list.txt"
UNCATEGORIZED_CHANNELS_PATH = "output/uncategorized.txt"

# 默认相似度匹配阈值
SIMILARITY_THRESHOLD = 0.85

# --- 辅助函数：配置加载和日志 ---
def setup_logging():
    """配置日志系统，便于调试"""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler()
        ]
    )

def load_config(config_path):
    """加载并解析 YAML 配置文件"""
    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file) or {}
            logging.info("配置文件 config.yaml 加载成功")
            return config
    except FileNotFoundError:
        logging.error(f"错误：未找到配置文件 '{config_path}'。")
        return None
    except yaml.YAMLError as e:
        logging.error(f"错误：配置文件 '{config_path}' 格式错误: {e}")
        return None

def load_category_config(config_path):
    """加载并解析分类配置文件，去重关键词"""
    category_config = {
        'ordered_categories': [],
        'category_keywords': defaultdict(set),
    }
    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            current_category = None
            for line in file:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if line.endswith(',#genre#'):
                    category_name = line.replace(',#genre#', '').strip()
                    current_category = category_name
                    if current_category not in category_config['ordered_categories']:
                        category_config['ordered_categories'].append(current_category)
                elif current_category:
                    keywords = [kw.strip() for kw in line.split('|') if kw.strip()]
                    category_config['category_keywords'][current_category].update(keywords)

        category_config['category_keywords'] = {k: list(v) for k, v in category_config['category_keywords'].items()}
        logging.info("分类配置文件 config/demo.txt 加载成功")
        return category_config
    except FileNotFoundError:
        logging.error(f"错误：未找到分类配置文件 '{config_path}'")
        return None
    except Exception as e:
        logging.error(f"错误：加载分类配置文件 '{config_path}' 失败: {e}")
        return None

# --- 核心业务逻辑：频道处理 ---
def normalize_name(name):
    """
    基于所有频道名称样本优化的规范化函数。
    - 移除常见的修饰词、版本和供应商标识。
    - 移除括号和方括号内的内容。
    - 统一数字格式。
    - 移除特殊符号。
    """
    cleaned = name.lower()

    # 移除国家或地区旗帜 emoji
    cleaned = re.sub(r'[\U0001F1E6-\U0001F1FF]', '', cleaned)

    # 将繁体字转换为简体字，这里使用简单的字典映射
    simplified_map = {'華': '华', '台': '台', '灣': '湾', '衛': '卫', '視': '视', '訊': '讯', '劇': '剧'}
    for traditional, simplified in simplified_map.items():
        cleaned = cleaned.replace(traditional.lower(), simplified.lower())
    
    # 移除括号和方括号内的内容，包括其中的中文、英文、数字和特殊符号
    cleaned = re.sub(r'[\(（][^)）\]]*?[\)）\]]', '', cleaned)
    cleaned = re.sub(r'\[.*?\]', '', cleaned)
    
    # 移除常见的修饰词、版本和供应商标识。此列表经过扩展。
    noise_words = [
        '高清', '超清', '流畅', '备用', '测试', '网络', '直播', '在线', 'live', 'lv', 'hd', 'uhd', '4k',
        'news', 'tv', 'radio', 'channel', 'feed', 'domestic', 'world', 'version', 'official', 'official',
        'sd', 'fhd', 'r', 'sd', 'hd', 'hq', 'lq', 'gh', 'cctv', 'iptv',
        '东联', '卫视', '少儿', '新闻', '体育', '综艺', '综合', '影视', '生活', '教育', '公共',
        '凤凰', '港澳', '海外', '央视', '央视频道', '亚洲', '剧场', '娱乐'
    ]
    
    # 使用正则表达式匹配并移除这些词汇，确保它们作为独立的词被移除
    # 添加单词边界 \b 以避免误删，例如 "news" 不会影响 "channel news"
    for word in noise_words:
        cleaned = re.sub(r'\b' + re.escape(word) + r'\b', '', cleaned, flags=re.IGNORECASE)

    # 移除特殊符号和多余的空格，包括 +、-、_、·、*、/
    cleaned = re.sub(r'[\s\-+_·*/\[\]\(\)（）]+', '', cleaned)

    # 移除重复词语，例如 "CCTV1CCTV1" -> "CCTV1"
    cleaned = re.sub(r'(?P<word>.+)(?P=word)', r'\1', cleaned)
    
    # 特殊处理数字，将01, 02 统一为 1, 2
    # 适用于 'CCTV 01' -> 'CCTV1'
    cleaned = re.sub(r'(\D)0(\d)', r'\1\2', cleaned)

    return cleaned.strip() or name.strip()

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
        logging.error(f"错误：未找到输入频道文件 '{file_name}'")
        return None
    except Exception as e:
        logging.error(f"读取文件 '{file_name}' 失败: {e}")
        return None
    return channels

def group_variants(channels):
    """使用相似度聚类频道变体，返回一个字典，键为规范化后的主名称，值为该组所有频道列表"""
    groups = defaultdict(list)
    processed_channels = set()

    for name, url in tqdm(channels, desc="聚类频道变体"):
        if (name, url) in processed_channels:
            continue

        cleaned_name = normalize_name(name)
        matched_group_key = None
        
        # 寻找最相似的现有组
        best_ratio = 0
        best_key = None
        for key in groups.keys():
            ratio = difflib.SequenceMatcher(None, cleaned_name, key).ratio()
            if ratio > best_ratio and ratio > SIMILARITY_THRESHOLD:
                best_ratio = ratio
                best_key = key
        
        if best_key:
            groups[best_key].append((name, url))
        else:
            groups[cleaned_name].append((name, url))

        processed_channels.add((name, url))

    return groups

def categorize_channels(channels):
    """根据关键字分类频道，使用相似度匹配"""
    categorized_data = defaultdict(list)
    uncategorized_data = []

    grouped_variants = group_variants(channels)

    logging.info(f"已创建 {len(grouped_variants)} 个频道组")

    with tqdm(total=len(grouped_variants), desc="分类频道") as pbar:
        for main_cleaned, group in grouped_variants.items():
            found_category = False
            
            # 优先匹配精确的分类关键词
            for category in CATEGORY_CONFIG['ordered_categories']:
                category_keywords = CATEGORY_CONFIG['category_keywords'].get(category, [])
                for kw in category_keywords:
                    # 使用 normalize_name 规范化关键词，然后进行精确匹配
                    normalized_kw = normalize_name(kw)
                    if normalized_kw == main_cleaned:
                        categorized_data[category].extend(group)
                        found_category = True
                        break
                if found_category:
                    break
            
            # 如果精确匹配失败，尝试模糊匹配
            if not found_category:
                for category in CATEGORY_CONFIG['ordered_categories']:
                    category_keywords = CATEGORY_CONFIG['category_keywords'].get(category, [])
                    for kw in category_keywords:
                        normalized_kw = normalize_name(kw)
                        if difflib.SequenceMatcher(None, main_cleaned, normalized_kw).ratio() >= SIMILARITY_THRESHOLD:
                            categorized_data[category].extend(group)
                            found_category = True
                            break
                    if found_category:
                        break

            if not found_category:
                uncategorized_data.extend(group)
            
            pbar.update(1)

    categorized_data = {k: v for k, v in categorized_data.items() if v}
    final_ordered_categories = [cat for cat in CATEGORY_CONFIG['ordered_categories'] if cat in categorized_data]
    return categorized_data, uncategorized_data, final_ordered_categories

# --- 结果保存模块 ---
def save_channels_to_files(categorized_data, uncategorized_data, ordered_categories, output_file, uncat_file):
    """将分类结果保存到最终文件"""
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    os.makedirs(os.path.dirname(uncat_file), exist_ok=True)

    header = [
        f"更新时间,#genre#\n",
        f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')},url\n"
    ]

    try:
        with open(output_file, "w", encoding='utf-8') as iptv_list_file:
            iptv_list_file.writelines(header)
            for category in ordered_categories:
                if category in categorized_data and categorized_data[category]:
                    iptv_list_file.write(f"\n{category},#genre#\n")
                    # 按频道名称排序
                    for name, url in sorted(categorized_data[category], key=lambda x: x[0]):
                        iptv_list_file.write(f"{name},{url}\n")
        logging.info(f"所有有效频道已分类并保存到: {output_file}")
    except Exception as e:
        logging.error(f"写入文件 '{output_file}' 失败: {e}")

    try:
        with open(uncat_file, "w", encoding='utf-8') as uncat_file:
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

    CONFIG = load_config(CONFIG_PATH)
    if CONFIG is None:
        return

    CATEGORY_CONFIG = load_category_config(CATEGORY_CONFIG_PATH)
    if CATEGORY_CONFIG is None:
        return

    valid_channels = read_channels_from_file(INPUT_CHANNELS_PATH)
    if not valid_channels:
        logging.warning("没有可用于分类的频道，退出。")
        return

    categorized_channels, uncategorized_channels, ordered_categories = categorize_channels(valid_channels)
    save_channels_to_files(categorized_channels, uncategorized_channels, ordered_categories, FINAL_IPTV_LIST_PATH, UNCATEGORIZED_CHANNELS_PATH)

    total_elapsed_time = time.time() - total_start_time
    logging.info(f"IPTV 频道分类和保存脚本完成，总耗时 {total_elapsed_time:.2f} 秒")

if __name__ == "__main__":
    main()
