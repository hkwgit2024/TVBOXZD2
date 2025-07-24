import re
from collections import defaultdict
from datetime import datetime

def classify_iptv_sources(input_filepath, output_filepath):
    """
    读取 IPTV 节目源文件，进行分类，并输出到指定文件。
    """
    classified_sources = defaultdict(list)
    update_time = ""

    try:
        with open(input_filepath, 'r', encoding='utf-8') as f:
            for i, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue

                # 第一行是更新时间
                if i == 0:
                    update_time = line.split(',')[0]
                    continue

                # 第二行是 #genre#，跳过
                if i == 1 and line == '#genre#':
                    continue

                # 节目源行
                parts = line.split(',', 1) # 只按第一个逗号分割，防止URL中包含逗号
                if len(parts) == 2:
                    name = parts[0].strip()
                    url = parts[1].strip()

                    # 尝试从名称中提取分类。
                    # 如果名称包含“_”，则取第一个下划线前的内容作为分类。
                    # 否则，使用完整的名称作为分类。
                    match = re.match(r'^(.*?)[_.,(（].*$', name) # 匹配第一个下划线、点、逗号、左右括号
                    if match:
                        category = match.group(1).strip()
                    elif '新闻' in name:
                        category = '新闻'
                    elif '电影' in name:
                        category = '电影'
                    elif '香港' in name or '无线' in name or '有线' in name or '凤凰' in name or '明珠' in name:
                        category = '港澳台'
                    elif '剧' in name or '传' in name or '记' in name or '王' in name or '宫' in name or '部' in name or '士' in name or '侦' in name or '探' in name:
                        category = '电视剧'
                    else:
                        category = '其他' # 默认分类

                    classified_sources[category].append(f"{name},{url}")
                else:
                    print(f"Warning: Skipping malformed line: {line}")

    except FileNotFoundError:
        print(f"Error: Input file '{input_filepath}' not found.")
        return
    except Exception as e:
        print(f"An error occurred while reading the input file: {e}")
        return

    # 获取当前日期作为更新时间，如果文件第一行没有提供
    if not update_time:
        update_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 写入输出文件
    try:
        with open(output_filepath, 'w', encoding='utf-8') as f:
            f.write(f"{update_time},#genre#\n")
            for category in sorted(classified_sources.keys()):
                f.write(f"\n{category},#genre#\n") # 写入分类标题
                for entry in classified_sources[category]:
                    f.write(f"{entry}\n")
        print(f"Successfully classified IPTV sources to '{output_filepath}'.")
    except Exception as e:
        print(f"An error occurred while writing the output file: {e}")

if __name__ == '__main__':
    input_file = 'output/valid_iptv_sources.txt'
    output_file = 'input/list.txt'
    classify_iptv_sources(input_file, output_file)
