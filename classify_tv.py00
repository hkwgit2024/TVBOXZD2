import os
import logging
from zhconv import convert
from collections import defaultdict # 导入 defaultdict，它在处理列表时非常方便

# 配置日志记录器
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# --- 常量定义 ---
INPUT_FILE = 'iptv_list.txt' # 输入文件名
OUTPUT_FILE = 'tv_list.txt' # 输出文件名
GENRE_DELIMITER = '#genre#' # 分类标题的分隔符
OTHER_CATEGORY_NAME = '其他' # 未分类频道的默认分类名称

# 定义分类关键词
CATEGORIES = {
    '卫视': ['卫视'],
    '新闻': ['新闻'],
    '娱乐': ['娱乐', '炫动'],
    '广东频道': ['广东'],
    '重庆频道': ['重庆'],
    '河北频道': ['河北'],
    '央视频道': ['CCTV', '中央'],
    '国外频道': ['CNN', 'CNA', 'CNBC'],
    # 根据需要添加更多类别
}

# 预处理关键词，将所有关键词转换为小写，方便后续进行大小写不敏感的匹配
LOWERCASE_CATEGORIES = {
    cat: [kw.lower() for kw in keywords]
    for cat, keywords in CATEGORIES.items()
}

# --- 函数定义 ---

def parse_iptv_list(filepath: str) -> dict[str, list[str]]:
    """
    读取 IPTV 列表文件，解析频道名称和URL。
    对于同一个频道名称，会将所有对应的 URL 收集到一个列表中。
    将名称转换为简体中文。

    Args:
        filepath: 输入 IPTV 列表文件的路径。

    Returns:
        一个字典，键是唯一的频道名称（没有 _N 后缀），
        值是一个包含所有对应 URL 的列表。
    """
    # 使用 defaultdict(list) 可以让我们在第一次访问一个键时，自动创建一个空列表
    channels = defaultdict(list) 

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or GENRE_DELIMITER in line:
                    continue

                try:
                    name_raw, url = line.split(',', 1)
                    name_clean = convert(name_raw, 'zh-cn').strip()

                    if not name_clean:
                        logging.warning(f"Line {line_num}: Skipped - Empty channel name for URL '{url}'")
                        continue

                    # *** 核心修改在这里 ***
                    # 直接将 URL 添加到对应频道名称的列表中
                    # 如果该频道名称第一次出现，defaultdict 会自动创建一个空列表
                    channels[name_clean].append(url)

                except ValueError:
                    logging.warning(f"Line {line_num}: Skipped - Malformed line (expected 'name,url'): '{line}'")
                except Exception as e:
                    logging.error(f"Line {line_num}: Error processing line '{line}': {e}")

    except FileNotFoundError:
        logging.error(f"Error: Input file '{filepath}' not found.")
        return defaultdict(list)
    except Exception as e:
        logging.error(f"An unexpected error occurred while reading '{filepath}': {e}")
        return defaultdict(list)

    return dict(channels) # 返回前转换为普通字典

def classify_channels(channels_dict: dict[str, list[str]]) -> dict[str, list[str]]:
    """
    根据预定义的类别对频道进行分类。
    每个分类下的列表包含 "频道名,URL" 格式的字符串。

    Args:
        channels_dict: 包含频道名称和对应 URL 列表的字典。

    Returns:
        一个字典，键是类别名称，值是属于该类别的 "名称,URL" 字符串列表。
        包含一个 '其他' (Other) 类别用于未分类的频道。
    """
    classified_channels = {cat: [] for cat in CATEGORIES}
    other_channels = []

    for name, urls in channels_dict.items(): # 注意这里 now 是一个 URL 列表
        categorized = False
        name_lower = name.lower()

        for cat, keywords_lower in LOWERCASE_CATEGORIES.items():
            if any(keyword in name_lower for keyword in keywords_lower):
                # 如果频道名匹配了某个类别，则将该频道的所有 URL 都添加到该类别下
                for url in urls:
                    classified_channels[cat].append(f"{name},{url}")
                categorized = True
                break

        if not categorized:
            # 如果频道未被分类，则将其所有 URL 都添加到 '其他' 列表
            for url in urls:
                other_channels.append(f"{name},{url}")
    
    if other_channels:
        classified_channels[OTHER_CATEGORY_NAME] = other_channels
    
    return classified_channels

def write_classified_list(output_filepath: str, classified_data: dict[str, list[str]]):
    """
    将分类后的频道写入输出文件，并带上类别标题。

    Args:
        output_filepath: 输出文件的路径。
        classified_data: 已分类的频道数据字典。
    """
    try:
        with open(output_filepath, 'w', encoding='utf-8') as f:
            for cat_name in CATEGORIES.keys():
                if cat_name in classified_data and classified_data[cat_name]:
                    f.write(f"{cat_name},{GENRE_DELIMITER}\n")
                    for channel_str in classified_data[cat_name]:
                        f.write(f"{channel_str}\n")
            
            if OTHER_CATEGORY_NAME in classified_data and classified_data[OTHER_CATEGORY_NAME]:
                f.write(f"{OTHER_CATEGORY_NAME},{GENRE_DELIMITER}\n")
                for channel_str in classified_data[OTHER_CATEGORY_NAME]:
                    f.write(f"{channel_str}\n")

        logging.info(f"分类完成，结果已保存到 '{output_filepath}'")
    except Exception as e:
        logging.error(f"写入输出文件 '{output_filepath}' 时发生错误: {e}")

# --- 主程序执行入口 ---
if __name__ == "__main__":
    logging.info(f"开始从 '{INPUT_FILE}' 分类 IPTV 列表...")

    # 1. 解析输入文件
    parsed_channels = parse_iptv_list(INPUT_FILE)
    if not parsed_channels:
        logging.warning("未找到频道或解析过程中发生错误。程序退出。")
    else:
        # 2. 分类频道
        classified_results = classify_channels(parsed_channels)
        
        # 3. 将分类结果写入输出文件
        write_classified_list(OUTPUT_FILE, classified_results)
