import requests
import re
import base64
import os

# 设置目标URL
CACHE_URL = "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/trial.cache"

# 正则表达式匹配包含 /s/ 或 /api/v1/client/ 的URL
URL_PATTERN = r'https?://[^\s<>"]+(?:/s/|/api/v1/client/)[^\s<>"]+'

# 结果文件
RESULT_FILE = "config/cache.txt"

# 确保结果文件目录存在
if not os.path.exists(os.path.dirname(RESULT_FILE)):
    os.makedirs(os.path.dirname(RESULT_FILE))

def fix_base64_padding(encoded_str):
    """修复Base64字符串的填充问题"""
    encoded_str = encoded_str.strip()
    return encoded_str + "=" * ((4 - len(encoded_str) % 4) % 4)

def decode_base64(content):
    """尝试解码Base64内容，始终返回 (decoded_content, error)"""
    try:
        cleaned_content = content.strip()
        padded_content = fix_base64_padding(cleaned_content)
        decoded = base64.b64decode(padded_content, validate=True)
        # 尝试将解码结果转换为字符串（假设内容是文本）
        decoded_str = decoded.decode('utf-8', errors='replace')
        return decoded_str, None
    except Exception as e:
        return None, f"Base64解码失败: {e}"

def main():
    # 初始化结果文件
    with open(RESULT_FILE, "w", encoding="utf-8") as f:
        f.write("运行结果\n======\n\n")

    try:
        # 获取 trial.cache 内容
        response = requests.get(CACHE_URL, timeout=10)
        response.raise_for_status()
        cache_content = response.text

        # 提取所有匹配的URL
        urls = re.findall(URL_PATTERN, cache_content)
        
        # 将URL列表写入结果文件
        with open(RESULT_FILE, "a", encoding="utf-8") as f:
            f.write(f"找到 {len(urls)} 个匹配的URL:\n")
            for url in urls:
                f.write(f"- {url}\n")
            f.write("\n解码结果:\n")

        for url in urls:
            try:
                # 访问URL
                url_response = requests.get(url, timeout=10)
                url_response.raise_for_status()
                content = url_response.text

                # 尝试Base64解码
                decoded_content, error = decode_base64(content)
                
                # 写入结果到 config/cache.txt
                with open(RESULT_FILE, "a", encoding="utf-8") as f:
                    f.write(f"\nURL: {url}\n")
                    if decoded_content:
                        f.write(f"解码成功，内容:\n{decoded_content}\n")
                    else:
                        f.write(f"解码失败: {error}\n")

            except requests.RequestException as e:
                with open(RESULT_FILE, "a", encoding="utf-8") as f:
                    f.write(f"\nURL: {url}\n访问失败: {e}\n")
                print(f"访问URL失败: {url}, 错误: {e}")
                continue  # 继续处理下一个URL

    except requests.RequestException as e:
        with open(RESULT_FILE, "a", encoding="utf-8") as f:
            f.write(f"获取 trial.cache 失败: {e}\n")
        print(f"获取 trial.cache 失败: {e}")

if __name__ == "__main__":
    main()
