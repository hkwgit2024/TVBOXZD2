import os # 导入 os 模块，用于文件路径操作，但在此版本中主要用于检查文件是否存在
import logging # 导入 logging 模块，用于记录程序运行信息和错误
from zhconv import convert # 导入 zhconv 库，用于中文繁简体转换

# 配置日志记录器
# level=logging.INFO 表示只记录信息级别及以上（警告、错误等）的消息
# format 定义了日志消息的格式
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# --- 常量定义 ---
INPUT_FILE = 'iptv_list.txt' # 输入文件名
OUTPUT_FILE = 'tv_list.txt' # 输出文件名
GENRE_DELIMITER = '#genre#' # 分类标题的分隔符
OTHER_CATEGORY_NAME = '其他' # 未分类频道的默认分类名称

# 定义分类关键词
# 关键词应为小写，以便进行大小写不敏感的匹配（后面会统一处理为小写）
CATEGORIES = {
    '卫视': ['卫视'],
    '新闻': ['新闻'],
    '娱乐': ['娱乐', '炫动'],
    '广东频道': ['广东'],
    '重庆频道': ['重庆'],
    '河北频道': ['河北'],
    '央视频道': ['CCTV', '中央'], # 添加 '中央' 作为央视频道的常见关键词
    '国外频道': ['CNN', 'CNA', 'CNBC'],
    # 根据需要添加更多类别
}

# 预处理关键词，将所有关键词转换为小写，方便后续进行大小写不敏感的匹配
LOWERCASE_CATEGORIES = {
    cat: [kw.lower() for kw in keywords]
    for cat, keywords in CATEGORIES.items()
}

# --- 函数定义 ---

def parse_iptv_list(filepath: str) -> dict[str, str]:
    """
    读取 IPTV 列表文件，解析频道名称和URL，
    处理重复名称，并将名称转换为简体中文。

    Args:
        filepath: 输入 IPTV 列表文件的路径。

    Returns:
        一个字典，键是唯一的频道名称（重复的会带有 _N 后缀），
        值是对应的 URL。
    """
    channels = {} # 用于存储解析后的频道信息
    name_count = {} # 用于记录频道名称出现的次数，处理重复项

    try:
        # 使用 'with' 语句确保文件正确关闭
        with open(filepath, 'r', encoding='utf-8') as f:
            # enumerate 用于获取行号，方便错误报告
            for line_num, line in enumerate(f, 1):
                line = line.strip() # 移除行首尾的空白字符
                # 跳过空行和分类标题行
                if not line or GENRE_DELIMITER in line:
                    continue

                try:
                    # 将行按第一个逗号分割成名称和URL
                    name_raw, url = line.split(',', 1)
                    # 转换为简体中文并移除首尾空白
                    name_clean = convert(name_raw, 'zh-cn').strip()

                    # 如果转换后名称为空，则跳过并发出警告
                    if not name_clean:
                        logging.warning(f"Line {line_num}: Skipped - Empty channel name for URL '{url}'")
                        continue

                    # 处理重复名称：如果名称已存在，则添加 _N 后缀
                    original_name = name_clean
                    if name_clean in name_count:
                        name_count[name_clean] += 1
                        unique_name = f"{name_clean}_{name_count[name_clean]}"
                    else:
                        name_count[name_clean] = 1
                        unique_name = name_clean
                    
                    channels[unique_name] = url

                except ValueError:
                    # 捕获分割错误，表示行格式不正确
                    logging.warning(f"Line {line_num}: Skipped - Malformed line (expected 'name,url'): '{line}'")
                except Exception as e:
                    # 捕获其他未知错误
                    logging.error(f"Line {line_num}: Error processing line '{line}': {e}")

    except FileNotFoundError:
        # 捕获文件未找到错误
        logging.error(f"Error: Input file '{filepath}' not found.")
        return {} # 发生错误时返回空字典
    except Exception as e:
        # 捕获读取文件时发生的其他意外错误
        logging.error(f"An unexpected error occurred while reading '{filepath}': {e}")
        return {}

    return channels

def classify_channels(channels_dict: dict[str, str]) -> dict[str, list[str]]:
    """
    根据预定义的类别对频道进行分类。

    Args:
        channels_dict: 包含唯一频道名称和 URL 的字典。

    Returns:
        一个字典，键是类别名称，值是属于该类别的 "名称,URL" 字符串列表。
        包含一个 '其他' (Other) 类别用于未分类的频道。
    """
    # 初始化分类字典，包含所有预定义的类别
    classified_channels = {cat: [] for cat in CATEGORIES} 
    other_channels = [] # 用于存储未分类的频道

    for name, url in channels_dict.items():
        categorized = False # 标志，表示频道是否已被分类
        name_lower = name.lower() # 将频道名称转换为小写，用于大小写不敏感匹配

        # 遍历所有类别及其小写关键词
        for cat, keywords_lower in LOWERCASE_CATEGORIES.items():
            # 检查频道名称（小写）是否包含任何一个关键词（小写）
            if any(keyword in name_lower for keyword in keywords_lower):
                classified_channels[cat].append(f"{name},{url}") # 添加到对应类别
                categorized = True # 设置标志为 True
                break  # 频道已被分类，跳出当前类别循环，处理下一个频道

        # 如果频道未被分类，则添加到 '其他' 列表
        if not categorized:
            other_channels.append(f"{name},{url}")
    
    # 如果 '其他' 列表不为空，则将其添加到分类结果中
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
            # 按照 CATEGORIES 中定义的顺序写入类别，最后写入 '其他' 类别
            for cat_name in CATEGORIES.keys():
                # 只有当该类别存在且其中有频道时才写入
                if cat_name in classified_data and classified_data[cat_name]:
                    f.write(f"{cat_name},{GENRE_DELIMITER}\n") # 写入类别标题
                    for channel_str in classified_data[cat_name]:
                        f.write(f"{channel_str}\n") # 写入频道信息
            
            # 最后写入 '其他' 类别，如果其中有频道
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
