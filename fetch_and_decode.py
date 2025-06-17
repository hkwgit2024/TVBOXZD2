import base64
import requests
import os
import re

# 定义目标 URL 和输出文件路径
url = "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/trial.cache"
output_file = "config/cache.txt"

# 确保输出目录存在
os.makedirs(os.path.dirname(output_file), exist_ok=True)

# 获取文件内容
try:
    response = requests.get(url)
    response.raise_for_status()  # 检查请求是否成功
except requests.RequestException as e:
    print(f"Failed to fetch URL: {e}")
    exit(1)

# 清理内容，只保留有效的 base64 字符 (A-Z, a-z, 0-9, +, /, =)
base64_content = response.text.strip()
base64_content = re.sub(r'[^A-Za-z0-9+/=]', '', base64_content)

# 解码 base64 内容
try:
    decoded_bytes = base64.b64decode(base64_content, validate=True)
    decoded_content = decoded_bytes.decode('utf-8')
except (base64.binascii.Error, ValueError) as e:
    print(f"Base64 decoding failed: {e}")
    exit(1)
except UnicodeDecodeError as e:
    print(f"UTF-8 decoding failed: {e}")
    exit(1)

# 保存到文件
try:
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(decoded_content)
    print(f"Content successfully decoded and saved to {output_file}")
except IOError as e:
    print(f"Failed to write to file: {e}")
    exit(1)
