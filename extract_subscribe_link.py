import requests
import json
import os

# 目标URL
url = "https://search.onyphe.io/search?q=%22%2Fapi%2Fv1%2Fclient%2Fsubscribe%3Ftoken%3D%22"

# 设置请求头，模拟浏览器
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*"
}

# 发送HTTP请求获取网页内容
try:
    response = requests.get(url, headers=headers, timeout=10)
    response.raise_for_status()  # 确保请求成功
except requests.RequestException as e:
    print(f"无法获取网页内容: {e}")
    exit(1)

# 检查响应内容
content_type = response.headers.get("Content-Type", "")
print(f"响应内容类型: {content_type}")
print(f"响应内容预览: {response.text[:500]}")  # 打印前500字符用于调试

# 尝试解析JSON
try:
    data = response.json()
except json.JSONDecodeError as e:
    print(f"无法解析JSON: {e}")
    # 保存响应内容到文件以便检查
    with open("data/response.txt", "w", encoding="utf-8") as f:
        f.write(response.text)
    print("响应内容已保存到 data/response.txt 用于调试")
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
