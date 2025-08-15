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
CONFIG_PATH = "config/config.yaml"
CATEGORY_CONFIG_PATH = "config/demo.txt"
INPUT_CHANNELS_PATH = "output/valid_channels_temp.txt"
FINAL_IPTV_LIST_PATH = "output/iptv_list.txt"
UNCATEGORIZED_CHANNELS_PATH = "output/uncategorized.txt"

SIMILARITY_THRESHOLD = 90  # 使用更高的阈值，精确匹配

# --- 辅助函数：配置加载和日志 ---
def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler()
        ]
    )

def load_config(config_path):
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
    category_config = {
        'ordered_categories': [],
        'category_keywords': defaultdict(list),
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
                    category_config['category_keywords'][current_category].extend(keywords)
        logging.info("分类配置文件 config/demo.txt 加载成功")
        return category_config
    except FileNotFoundError:
        logging.error(f"错误：未找到分类配置文件 '{config_path}'")
        return None
    except Exception as e:
        logging.error(f"错误：加载分类配置文件 '{config_path}' 失败: {e}")
        return None

# --- 核心业务逻辑：频道处理 ---
def normalize_name_and_resolve_variant(name, category_keywords):
    """
    更智能的归一化和变体解析函数。
    它不仅清理名称，还尝试将其解析为 category_keywords 中的一个标准变体。
    """
    cleaned = name.lower().strip()
    
    # 移除括号和方括号内的内容及其本身
    cleaned = re.sub(r'[\(（][^)）\]]*?[\)）\]]', '', cleaned)
    cleaned = re.sub(r'\[.*?\]', '', cleaned)
    
    # 移除常见的修饰词和符号，防止它们干扰匹配
    cleaned = re.sub(r'[\s\-+_·*/]+', '', cleaned)
    
    # 尝试将清洗后的名称与所有分类关键词进行模糊匹配
    all_keywords = [kw for sublist in category_keywords.values() for kw in sublist]
    if not all_keywords:
        return cleaned, False # 如果没有关键词，只返回清洗后的名称

    best_match, score = process.extractOne(cleaned, all_keywords, scorer=fuzz.token_set_ratio)
    
    if score >= SIMILARITY_THRESHOLD:
        # 找到最佳匹配，返回该关键词作为标准变体
        return best_match, True
    
    # 如果没有找到高分匹配，返回原始清洗后的名称
    return cleaned, False

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

def categorize_channels(channels, category_config):
    """根据关键字分类频道，使用新版归一化和模糊匹配"""
    categorized_data = defaultdict(lambda: defaultdict(list))
    uncategorized_data = []

    logging.info(f"开始分类 {len(channels)} 个频道...")
    
    for name, url in tqdm(channels, desc="正在分类频道"):
        found_category = False
        
        # 使用新的归一化函数，它会尝试解析变体
        resolved_name, is_resolved = normalize_name_and_resolve_variant(name, category_config['category_keywords'])
        
        # 遍历所有分类，查找 resolved_name 属于哪个分类
        for category in category_config['ordered_categories']:
            if resolved_name in category_config['category_keywords'][category]:
                # 如果 resolved_name 是 demo.txt 中的一个关键词，则将其添加到该分类
                categorized_data[category][resolved_name].append((name, url))
                found_category = True
                break
        
        if not found_category:
            uncategorized_data.append((name, url))

    # 格式化最终数据
    final_categorized_data = {}
    for category, name_groups in categorized_data.items():
        # 按主名称（demo.txt 中的关键词）排序，使其有序
        sorted_names = sorted(name_groups.keys())
        final_categorized_data[category] = []
        for resolved_name in sorted_names:
            final_categorized_data[category].extend(name_groups[resolved_name])

    uncategorized_data.sort(key=lambda x: x[0])
    
    return final_categorized_data, uncategorized_data

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

    # 将配置参数传递给 categorize_channels 函数
    categorized_channels, uncategorized_channels = categorize_channels(
        valid_channels, CATEGORY_CONFIG
    )
    save_channels_to_files(categorized_channels, uncategorized_channels, CATEGORY_CONFIG['ordered_categories'], FINAL_IPTV_LIST_PATH, UNCATEGORIZED_CHANNELS_PATH)

    total_elapsed_time = time.time() - total_start_time
    logging.info(f"IPTV 频道分类和保存脚本完成，总耗时 {total_elapsed_time:.2f} 秒")

if __name__ == "__main__":
    main()
