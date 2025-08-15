# categorize_and_save_channels.py

import os
import re
import difflib
from collections import defaultdict
import logging
from datetime import datetime
import yaml
import time

# --- 配置和加载模块 ---
CONFIG_PATH = "config/config.yaml"
CATEGORY_CONFIG_PATH = "config/demo.txt"
# 假设这个文件现在只包含有效的频道，由 check_channels_validity.py 生成
INPUT_CHANNELS_PATH = "output/valid_channels_temp.txt"  
FINAL_IPTV_LIST_PATH = "output/iptv_list.txt"
UNCATEGORIZED_CHANNELS_PATH = "output/uncategorized.txt"

def load_config(config_path):
    """加载并解析 YAML 配置文件"""
    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file) or {}
            print("配置文件 config.yaml 加载成功")
            return config
    except FileNotFoundError:
        print(f"错误：未找到配置文件 '{config_path}'。")
        exit(1)
    except yaml.YAMLError as e:
        print(f"错误：配置文件 '{config_path}' 格式错误: {e}")
        exit(1)
    except Exception as e:
        print(f"错误：加载配置文件 '{config_path}' 失败: {e}")
        exit(1)

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
        print("分类配置文件 config/demo.txt 加载成功")
        return category_config
    except FileNotFoundError:
        print(f"错误：未找到分类配置文件 '{config_path}'")
        exit(1)
    except Exception as e:
        print(f"错误：加载分类配置文件 '{config_path}' 失败: {e}")
        exit(1)

# 全局配置
CONFIG = load_config(CONFIG_PATH)
CATEGORY_CONFIG = load_category_config(CATEGORY_CONFIG_PATH)

def performance_monitor(func):
    """记录函数执行时间"""
    if not CONFIG.get('performance_monitor', {}).get('enabled', False):
        return func
    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        elapsed_time = time.time() - start_time
        print(f"性能监控：函数 '{func.__name__}' 耗时 {elapsed_time:.2f} 秒")
        return result
    return wrapper

# --- 频道分类和管理模块 ---
def normalize_name(name):
    """优化后的规范化频道名称，保留关键数字、字母和特殊字符，移除修饰词"""
    cleaned = name.lower()
    noise_words = ['\(.*?\)', '\[.*?\]', '高清', '超清', '流畅', '备用', '测试', '网络', '直播', '在线', 'live', 'ipv6', 'ipv4', '东联', '港澳版']
    for word in noise_words:
        cleaned = re.sub(word, '', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'[\s\-]+', '', cleaned).strip()
    return cleaned or name.strip()

@performance_monitor
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
        print(f"从 {file_name} 读取 {len(channels)} 个频道")
    except FileNotFoundError:
        print(f"错误：未找到输入频道文件 '{file_name}'")
        return None
    except Exception as e:
        print(f"读取文件 '{file_name}' 失败: {e}")
        return None
    return channels

@performance_monitor
def group_variants(channels, threshold=0.85):
    """使用相似度聚类频道变体"""
    groups = defaultdict(list)
    processed_channels = set()

    for name, url in channels:
        if (name, url) in processed_channels:
            continue

        cleaned_name = normalize_name(name)
        matched_group = None

        for key in groups.keys():
            if difflib.SequenceMatcher(None, cleaned_name, key).ratio() > threshold:
                matched_group = key
                break

        if matched_group:
            groups[matched_group].append((name, url))
        else:
            groups[cleaned_name].append((name, url))

        processed_channels.add((name, url))

    return groups

@performance_monitor
def categorize_channels(channels):
    """根据关键字分类频道，使用相似度匹配"""
    categorized_data = defaultdict(list)
    uncategorized_data = []

    grouped_variants = group_variants(channels)

    for main_cleaned, group in grouped_variants.items():
        found_category = False
        for category in CATEGORY_CONFIG['ordered_categories']:
            category_keywords = CATEGORY_CONFIG['category_keywords'].get(category, [])
            for kw in category_keywords:
                normalized_kw = normalize_name(kw)
                if difflib.SequenceMatcher(None, main_cleaned, normalized_kw).ratio() > 0.85:
                    categorized_data[category].extend(group)
                    found_category = True
                    break
            if found_category:
                break

        if not found_category:
            uncategorized_data.extend(group)

    categorized_data = {k: v for k, v in categorized_data.items() if v}
    final_ordered_categories = [cat for cat in CATEGORY_CONFIG['ordered_categories'] if cat in categorized_data]
    return categorized_data, uncategorized_data, final_ordered_categories

# --- 保存模块 ---
@performance_monitor
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
                    for name, url in sorted(categorized_data[category], key=lambda x: x[0]):
                        iptv_list_file.write(f"{name},{url}\n")
        print(f"所有有效频道已分类并保存到: {output_file}")
    except Exception as e:
        print(f"写入文件 '{output_file}' 失败: {e}")

    try:
        with open(uncat_file, "w", encoding='utf-8') as uncat_file:
            uncat_file.writelines(header)
            if uncategorized_data:
                uncat_file.write(f"\n未分类频道,#genre#\n")
                for name, url in sorted(uncategorized_data, key=lambda x: x[0]):
                    uncat_file.write(f"{name},{url}\n")
        print(f"未分类频道已保存到: {uncat_file}")
    except Exception as e:
        print(f"写入未分类文件 '{uncat_file}' 失败: {e}")

# --- 主函数 ---
def main():
    """主函数，执行 IPTV 频道分类和保存流程"""
    print("开始执行 IPTV 频道分类和保存脚本...")
    total_start_time = time.time()

    # 假设输入文件 output/valid_channels_temp.txt 已经包含了经过检查的有效频道
    valid_channels = read_channels_from_file(INPUT_CHANNELS_PATH)
    if not valid_channels:
        print("没有可用于分类的频道，退出。")
        return

    categorized_channels, uncategorized_channels, ordered_categories = categorize_channels(valid_channels)
    save_channels_to_files(categorized_channels, uncategorized_channels, ordered_categories, FINAL_IPTV_LIST_PATH, UNCATEGORIZED_CHANNELS_PATH)

    total_elapsed_time = time.time() - total_start_time
    print(f"IPTV 频道分类和保存脚本完成，总耗时 {total_elapsed_time:.2f} 秒")

if __name__ == "__main__":
    main()
