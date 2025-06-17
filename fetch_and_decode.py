import base64
import requests
import os

# 定义目标 URL 和输出文件路径
url = "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/trial.cache"
output_file = "config/cache.txt"

# 确保输出目录存在
os.makedirs(os.path.dirname(output_file), exist_ok=True)

# 获取文件内容
response = requests.get(url)
response.raise_for_status()  # 检查请求是否成功

# 解码 base64 内容
base64_content = response.text.strip()
decoded_content = base64.b64decode(base64_content).decode('utf-8')

# 保存到文件
with open(output_file, 'w', encoding='utf-8') as f:
    f.write(decoded_content)

print(f"Content successfully decoded and saved to {output_file}")
