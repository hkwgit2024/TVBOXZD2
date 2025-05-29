import json
import os

# 读取本地JSON文件
try:
    with open("data/input.json", "r", encoding="utf-8") as f:
        data = json.load(f)
except FileNotFoundError:
    print("未找到 data/input.json 文件")
    exit(1)
except json.JSONDecodeError as e:
    print(f"无法解析JSON文件: {e}")
    exit(1)

# 提取包含 /api/v1/client/subscribe?token= 的链接
subscribe_links = []
for item in data.get("app", {}).get("extract", {}).get("url", []):
    if "/api/v1/client/subscribe?token=" in item:
        subscribe_links.append(item)

# 确保data目录存在
os.makedirs("data", exist_ok=True)

# 将链接保存到data/s.txt
try:
    with open("data/s.txt", "w", encoding="utf-8") as f:
        if subscribe_links:
            for link in subscribe_links:
                f.write(link + "\n")
            print(f"已将 {len(subscribe_links)} 个链接保存到 data/s.txt")
        else:
            f.write("")
            print("未找到包含 /api/v1/client/subscribe?token= 的链接，已创建空文件 data/s.txt")
except IOError as e:
    print(f"无法写入文件: {e}")
    exit(1)
