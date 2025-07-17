from source import raw2fastly, session
import os

AUTOURLS = []
AUTOFETCH = []

def example_dynamic_url():
    """示例动态 URL 生成函数"""
    if os.path.exists("local_proxy.conf"):
        url = raw2fastly("https://example.com/subscription")
        return session.get(url).text.strip().splitlines()
    return []

AUTOURLS.append(example_dynamic_url)
