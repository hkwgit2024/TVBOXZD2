# categorize_and_save_channels.py

import os
import re
from thefuzz import fuzz, process
from collections import defaultdict
import logging
from datetime import datetime
import time
from tqdm import tqdm
import yaml

# --- 全局配置和常量 ---
# 将文件路径定义为常量，提高可读性
CONFIG_PATH = "config/config.yaml"
CATEGORY_CONFIG_PATH = "config/demo.txt"
# 假设这个文件现在只包含有效的频道，由 check_channels_validity.py 生成
INPUT_CHANNELS_PATH = "output/valid_channels_temp.txt"
FINAL_IPTV_LIST_PATH = "output/iptv_list.txt"
UNCATEGORIZED_CHANNELS_PATH = "output/uncategorized.txt"

# 默认相似度匹配阈值
SIMILARITY_THRESHOLD = 85 # 更改为百分制，与 TheFuzz 匹配

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
def normalize_name(name, name_filter_words, name_replacements):
    """
    基于所有频道名称样本和配置文件优化的规范化函数。
    - 优先应用替换规则，然后应用通用清理和过滤规则。
    """
    cleaned = name.lower().strip()

    # 首先，应用配置文件中的精确替换规则
    if name_replacements:
        for old, new in name_replacements.items():
            cleaned = cleaned.replace(old.lower(), new.lower())
    
    # 其次，应用配置文件中的过滤规则
    if name_filter_words:
        for word in name_filter_words:
            cleaned = cleaned.replace(word.lower(), '')

    # 接着，应用一套更通用、更彻底的清理规则
    
    # 移除括号和方括号内的内容及其本身
    cleaned = re.sub(r'[\(（][^)）\]]*?[\)）\]]', '', cleaned)
    cleaned = re.sub(r'\[.*?\]', '', cleaned)
    
    # 移除常见的修饰词、版本和供应商标识（此列表经过扩展和优化）
    noise_words = [
        '高清', '超清', '流畅', '备用', '测试', '网络', '直播', '在线', 'live', 'lv', 'hd', 'uhd', '4k',
        'news', 'tv', 'radio', 'channel', 'feed', 'domestic', 'world', 'version', 'official',
        'sd', 'fhd', 'r', 'sd', 'hd', 'hq', 'lq', 'gh', 'iptv', '卫视', '少儿', '新闻', '体育', '综艺',
        '综合', '影视', '生活', '教育', '公共', '凤凰', '港澳', '海外', '亚洲', '剧场', '娱乐', '中天',
        '三立', '民视', '华视', '东森', 'tvbs', '台视', '寰宇', '经典', '靖天', '镜电视', '开电视', '龙华',
        '纬来', '中视', '星河', 'tvb' # 强化通用词汇移除
    ]
    
    # 使用正则表达式匹配并移除这些词汇，使用单词边界来避免误删
    for word in noise_words:
        # 使用更灵活的模式，同时处理中文和英文
        cleaned = re.sub(r'\b' + re.escape(word) + r'\b', '', cleaned, flags=re.IGNORECASE)

    # 统一数字格式，将 'CCTV 01' -> 'CCTV1'
    cleaned = re.sub(r'(\D)0(\d)', r'\1\2', cleaned)

    # 移除特殊符号和多余的空格，包括 +、-、_、·、*、/
    cleaned = re.sub(r'[\s\-+_·*/\[\]\(\)（）]+', '', cleaned)
    
    # 最后，再次移除可能因替换而产生的多余空格，并移除重复词语
    cleaned = re.sub(r'(?P<word>.+)(?P=word)', r'\1', cleaned)
    
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

def group_variants(channels, similarity_threshold, name_filter_words, name_replacements):
    """使用模糊匹配库聚类频道变体，返回一个字典，键为规范化后的主名称，值为该组所有频道列表"""
    groups = defaultdict(list)
    processed_channels = set()

    # 创建一个包含所有规范化名称的列表，用于模糊匹配
    normalized_names = {normalize_name(name, name_filter_words, name_replacements): [] for name, _ in channels}
    
    for name, url in tqdm(channels, desc="聚类频道变体"):
        if (name, url) in processed_channels:
            continue

        cleaned_name = normalize_name(name, name_filter_words, name_replacements)
        
        # 使用 process.extractOne 在所有规范化名称中找到最佳匹配
        match = process.extractOne(cleaned_name, normalized_names.keys(), scorer=fuzz.token_sort_ratio)
        
        if match and match[1] >= similarity_threshold:
            groups[match[0]].append((name, url))
        else:
            # 如果没有找到高相似度的匹配，则创建一个新组
            groups[cleaned_name].append((name, url))

        processed_channels.add((name, url))

    return groups


def categorize_channels(channels, category_config, name_filter_words, name_replacements):
    """根据关键字分类频道，使用相似度匹配"""
    categorized_data = defaultdict(list)
    uncategorized_data = []

    # 确保将配置参数传递给 group_variants
    grouped_variants = group_variants(channels, SIMILARITY_THRESHOLD, name_filter_words, name_replacements)

    logging.info(f"已创建 {len(grouped_variants)} 个频道组")

    with tqdm(total=len(grouped_variants), desc="分类频道") as pbar:
        for main_cleaned, group in grouped_variants.items():
            found_category = False
            
            # 优先匹配精确的分类关键词
            for category in category_config['ordered_categories']:
                category_keywords = category_config['category_keywords'].get(category, [])
                for kw in category_keywords:
                    # 使用 normalize_name 规范化关键词，然后进行精确匹配
                    normalized_kw = normalize_name(kw, name_filter_words, name_replacements)
                    if normalized_kw == main_cleaned:
                        categorized_data[category].extend(group)
                        found_category = True
                        break
                if found_category:
                    break
            
            # 如果精确匹配失败，尝试模糊匹配
            if not found_category:
                for category in category_config['ordered_categories']:
                    category_keywords = category_config['category_keywords'].get(category, [])
                    for kw in category_keywords:
                        normalized_kw = normalize_name(kw, name_filter_words, name_replacements)
                        # 使用 token_sort_ratio 进行模糊匹配，更加健壮
                        score = fuzz.token_sort_ratio(main_cleaned, normalized_kw)
                        if score >= SIMILARITY_THRESHOLD:
                            categorized_data[category].extend(group)
                            found_category = True
                            break
                    if found_category:
                        break

            if not found_category:
                uncategorized_data.extend(group)
            
            pbar.update(1)

    categorized_data = {k: v for k, v in categorized_data.items() if v}
    final_ordered_categories = [cat for cat in category_config['ordered_categories'] if cat in categorized_data]
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

    # 从 CONFIG 中提取 name_filter_words 和 channel_name_replacements
    name_filter_words = CONFIG.get('name_filter_words', [])
    name_replacements = CONFIG.get('channel_name_replacements', {})

    # 将配置参数传递给 categorize_channels 函数
    categorized_channels, uncategorized_channels, ordered_categories = categorize_channels(
        valid_channels, CATEGORY_CONFIG, name_filter_words, name_replacements
    )
    save_channels_to_files(categorized_channels, uncategorized_channels, ordered_categories, FINAL_IPTV_LIST_PATH, UNCATEGORIZED_CHANNELS_PATH)

    total_elapsed_time = time.time() - total_start_time
    logging.info(f"IPTV 频道分类和保存脚本完成，总耗时 {total_elapsed_time:.2f} 秒")

if __name__ == "__main__":
    main()
