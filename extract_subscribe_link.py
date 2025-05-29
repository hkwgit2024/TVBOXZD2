import requests
import json
import os

# 目标URL
url = "https://search.onyphe.io/search?q=%22%2Fapi%2Fv1%2Fclient%2Fsubscribe%3Ftoken%3D%22"

# 发送HTTP请求获取网页内容
try:
    response = requests.get(url)
    response.raise_for_status()  # 确保请求成功
except requests.RequestException as e:
    print(f"Failed to fetch webpage: {e}")
    exit(1)

# 解析JSON数据
try:
    # 假设网页返回的JSON直接是所需数据
    data = response.json()
except json.JSONDecodeError as e:
    print(f"Failed to parse JSON: {e}")
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
        for link in subscribe_links:
            f.write(link + "\n")
    print(f"Links saved to data/s.txt: {len(subscribe_links)} links found")
except IOError as e:
    print(f"Failed to write to file: {e}")
    exit(1)
