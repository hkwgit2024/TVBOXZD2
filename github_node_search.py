import aiohttp
import asyncio
import base64
import json
import logging
import os
import re
import requests
import time
from datetime import datetime
import pytz
import yaml
from urllib.parse import urlparse

# 设置日志
logging.basicConfig(level=logging.INFO, format='调试: %(message)s')
logger = logging.getLogger(__name__)

# 环境变量
BOT_TOKEN = os.getenv('BOT')
if not BOT_TOKEN:
    raise ValueError("BOT 环境变量未设置")

# 上海时区
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

# 数据目录
DATA_DIR = 'data'
os.makedirs(DATA_DIR, exist_ok=True)

# 存储结果
unique_urls = set()
unique_nodes = set()

# GitHub API 请求头
headers = {
    'Authorization': f'token {BOT_TOKEN}',
    'Accept': 'application/vnd.github.v3+json'
}

# 搜索查询
SEARCH_QUERIES = [
    'clash proxies extension:yaml in:file -manifest -skaffold -locale',
    'v2ray outbounds extension:json in:file',
    'trojan nodes extension:txt in:file',
    'sing-box outbounds extension:json in:file',
    'subscription extension:txt in:file',
    'from:freefq extension:txt in:file',
    'from:mahdibland extension:txt in:file'
]

async def test_url_connection(session, url, timeout=10):
    """测试 URL 是否可连接"""
    for attempt in range(3):
        try:
            async with session.head(url, timeout=timeout, allow_redirects=True) as response:
                if response.status == 200:
                    return True
                logger.info(f"URL {url} 返回状态码: {response.status}")
        except Exception as e:
            logger.info(f"测试 URL {url} 失败 (尝试 {attempt + 1}/3): {str(e)}")
        await asyncio.sleep(1)
    return False

async def test_node_connection(session, node, timeout=10):
    """测试节点连通性（仅对 HTTP/HTTPS 订阅链接）"""
    if node.startswith(('trojan://', 'vmess://', 'ss://', 'hy2://', 'vless://')):
        return True  # 非 HTTP 协议直接通过
    return await test_url_connection(session, node, timeout)

def recursive_decode_base64(text):
    """递归解码 Base64 编码的内容"""
    try:
        decoded = base64.b64decode(text).decode('utf-8')
        # 尝试再次解码，直到无法解码
        try:
            return recursive_decode_base64(decoded)
        except:
            return decoded
    except:
        return text

def parse_file_content(content):
    """解析文件内容，提取节点"""
    nodes = []
    
    # 尝试直接提取节点链接
    node_patterns = [
        r'(trojan://[^\s]+)',
        r'(vmess://[^\s]+)',
        r'(ss://[^\s]+)',
        r'(hy2://[^\s]+)',
        r'(vless://[^\s]+)',
        r'(https?://[^\s]+)'  # 订阅链接
    ]
    
    for pattern in node_patterns:
        matches = re.findall(pattern, content)
        nodes.extend(matches)
    
    # 尝试 Base64 解码
    for line in content.splitlines():
        decoded = recursive_decode_base64(line.strip())
        if decoded != line:
            nodes.extend(parse_file_content(decoded))  # 递归解析解码内容
    
    # 尝试解析 YAML/JSON
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            for key in ['proxies', 'servers', 'nodes', 'outbounds', 'proxy-groups']:
                if key in data and isinstance(data[key], list):
                    for item in data[key]:
                        if isinstance(item, dict) and 'server' in item:
                            # 构造节点（简化示例）
                            node = f"{item.get('protocol', 'trojan')}://{item.get('password')}@{item['server']}:{item.get('port')}"
                            nodes.append(node)
    except:
        try:
            data = json.loads(content)
            if isinstance(data, dict):
                for key in ['proxies', 'servers', 'nodes', 'outbounds']:
                    if key in data and isinstance(data[key], list):
                        for item in data[key]:
                            if isinstance(item, dict) and 'server' in item:
                                node = f"{item.get('type', 'trojan')}://{item.get('password')}@{item['server']}:{item.get('port')}"
                                nodes.append(node)
        except:
            pass
    
    if not nodes:
        logger.info(f"文件无节点，内容前几行: {content[:100]}")
    
    return nodes

async def fetch_file(session, url):
    """获取文件内容"""
    try:
        async with session.get(url, timeout=10) as response:
            if response.status == 200:
                content = await response.text()
                logger.info(f"成功获取文件 {url}")
                return content
            logger.info(f"获取文件 {url} 失败，状态码: {response.status}")
    except Exception as e:
        logger.info(f"获取文件 {url} 失败: {str(e)}")
    return None

async def search_and_process(query, session):
    """执行搜索并处理结果"""
    page = 1
    while page <= 2:  # 限制 2 页
        try:
            search_url = f"https://api.github.com/search/code?q={query}&per_page=50&page={page}"
            response = requests.get(search_url, headers=headers)
            if response.status_code == 200:
                data = response.json()
                items = data.get('items', [])
                logger.info(f"查询 {query} 页 {page} 获取 {len(items)} 条结果")
                
                for item in items:
                    raw_url = item['html_url'].replace('blob/', 'raw/')
                    if await test_url_connection(session, raw_url):
                        content = await fetch_file(session, raw_url)
                        if content:
                            nodes = parse_file_content(content)
                            for node in nodes:
                                if await test_node_connection(session, node):
                                    unique_nodes.add(node)
                                    logger.info(f"添加节点: {node}")
                            unique_urls.add(raw_url)
                            timestamp = datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S %Z')
                            logger.info(f"URL {raw_url} 可连通，时间戳: {timestamp}")
            else:
                logger.info(f"GitHub API 请求失败 (查询: {query}, 页: {page}): {response.status_code}, {response.text}")
                break
        except Exception as e:
            logger.info(f"搜索查询 {query} 页 {page} 失败: {str(e)}")
        page += 1

def save_results():
    """保存结果到文件"""
    if unique_urls:
        with open(os.path.join(DATA_DIR, 'url.txt'), 'w', encoding='utf-8') as f:
            for url in unique_urls:
                timestamp = datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S %Z')
                f.write(f"{timestamp} | {url}\n")
    
    if unique_nodes:
        with open(os.path.join(DATA_DIR, 'hy2.txt'), 'w', encoding='utf-8') as f:
            for node in unique_nodes:
                f.write(f"{node}\n")
    else:
        logger.info("无节点保存，跳过 hy2.txt 写入")

async def main():
    """主函数"""
    async with aiohttp.ClientSession() as session:
        tasks = [search_and_process(query, session) for query in SEARCH_QUERIES]
        await asyncio.gather(*tasks)
    
    save_results()

if __name__ == "__main__":
    asyncio.run(main())
