import re
from zhconv import convert

# 定义分类关键词（根据你的文件调整）
categories = {
    '卫视': ['卫视'],
    '新闻': ['新闻'],
    '娱乐': ['娱乐', '炫动'],
    '广东频道': ['广东'],
    '重庆频道': ['重庆'],
    '河北频道': ['河北'],
    '央视频道': ['CCTV'],
    '国外频道': ['CNN', 'CNA', 'CNBC'],
    # 根据需要添加更多类别
}

# 读取 iptv_list.txt 文件
with open('iptv_list.txt', 'r', encoding='utf-8') as f:
    lines = f.readlines()

# 存储频道信息
channels = {}
name_count = {}

# 解析文件内容
for line in lines:
    line = line.strip()
    if line and ',#genre#' not in line:  # 跳过分类标题行
        try:
            name, url = line.split(',', 1)
            # 统一为简体中文
            name = convert(name, 'zh-cn')
            # 处理重名
            if name in name_count:
                name_count[name] += 1
                name = f"{name}_{name_count[name]}"
            else:
                name_count[name] = 1
            channels[name] = url
        except ValueError:
            continue  # 跳过格式错误的行

# 分类频道
classified_channels = {cat: [] for cat in categories}
other_channels = []

for name, url in channels.items():
    categorized = False
    for cat, keywords in categories.items():
        if any(keyword in name for keyword in keywords):
            classified_channels[cat].append(f"{name},{url}")
            categorized = True
            break
    if not categorized:
        other_channels.append(f"{name},{url}")

# 写入分类后的文件
with open('tv_list.txt', 'w', encoding='utf-8') as f:
    for cat, channel_list in classified_channels.items():
        if channel_list:
            f.write(f"{cat},#genre#\n")
            for channel in channel_list:
                f.write(f"{channel}\n")
    if other_channels:
        f.write("其他,#genre#\n")
        for channel in other_channels:
            f.write(f"{channel}\n")

print("分类完成，结果已保存到 tv_list.txt")
