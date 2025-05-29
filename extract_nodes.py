import aiohttp
import asyncio
import base64
import json
import logging
import os
import re
import yaml
from datetime import datetime
import pytz
from urllib.parse import urlparse

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')
logger = logging.getLogger(__name__)
handler = logging.FileHandler('data/extract.log')
handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
logger.addHandler(handler)

# 上海时区
SHANGHAI_TZ = pytz.timezone('Asia/Shanghai')

# 数据目录
DATA_DIR = 'data'
os.makedirs(DATA_DIR, exist_ok=True)

# 存储结果
unique_nodes = set()
url_node_counts = {}
invalid_urls = {}

async def test_node_connection(session, node, timeout=10):
    """测试节点连通性（仅对 HTTP/HTTPS 订阅链接）"""
    if node.startswith(('trojan://', 'vmess://', 'ss://', 'hy2://', 'vless://')):
        return True  # 非HTTP协议直接通过
    for attempt in range(3):
        try:
            async with session.head(node, timeout=timeout, allow_redirects=True) as response:
                if response.status == 200:
                    return True
                logger.info(f"节点 {node} 返回状态码: {response.status}")
        except Exception as e:
            logger.info(f"测试节点 {node} 失败 (尝试 {attempt + 1}/3): {str(e)}")
        await asyncio.sleep(1)
    return False

def recursive_decode_base64(text):
    """递归解码 Base64 编码的内容"""
    try:
        decoded = base64.b64decode(text).decode('utf-8')
        try:
            return recursive_decode_base64(decoded)
        except:
            return decoded
    except:
        return text

def parse_file_content(content):
    """解析文件内容，提取节点"""
    nodes = []
    
    # 直接提取节点链接
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
    
    # Base64 解码
    for line in content.splitlines():
        decoded = recursive_decode_base64(line.strip())
        if decoded != line:
            nodes.extend(parse_file_content(decoded))
    
    # 解析 YAML/JSON
    try:
        data = yaml.safe_load(content)
        if isinstance(data, dict):
            for key in ['proxies', 'servers', 'nodes', 'outbounds', 'proxy-groups']:
                if key in data and isinstance(data[key], list):
                    for item in data[key]:
                        if isinstance(item, dict) and 'server' in item:
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
            invalid_urls[url] = {'timestamp': datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S %Z'), 'reason': f'状态码 {response.status}'}
    except Exception as e:
        logger.info(f"获取文件 {url} 失败: {str(e)}")
        invalid_urls[url] = {'timestamp': datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S %Z'), 'reason': str(e)}
    return None

async def process_url(url, session):
    """处理单个 URL，提取节点"""
    content = await fetch_file(session, url)
    if content:
        nodes = parse_file_content(content)
        valid_nodes = []
        for node in nodes:
            if await test_node_connection(session, node):
                unique_nodes.add(node)
                valid_nodes.append(node)
                logger.info(f"添加节点: {node}")
        url_node_counts[url] = len(valid_nodes)
        if not valid_nodes:
            invalid_urls[url] = {'timestamp': datetime.now(SHANGHAI_TZ).strftime('%Y-%m-%d %H:%M:%S %Z'), 'reason': '无有效节点'}
            logger.info(f"URL {url} 无有效节点，标记为无效")
        return len(nodes)
    return 0

async def main():
    """主函数"""
    try:
        with open(os.path.join(DATA_DIR, 'url.txt'), 'r', encoding='utf-8') as f:
            urls = [line.strip().split(' | ')[1] for line in f if ' | ' in line]
    except FileNotFoundError:
        logger.error("url.txt 不存在")
        return
    
    total_nodes = 0
    processed_urls = 0
    async with aiohttp.ClientSession() as session:
        for url in urls:
            total_nodes += await process_url(url, session)
            processed_urls += 1
            if processed_urls % 10 == 0:
                logger.info(f"已处理 {processed_urls} 个 URL，共提取 {total_nodes} 个节点")
            await asyncio.sleep(0.5)  # 控制请求速率
    
    # 保存节点
    if unique_nodes:
        with open(os.path.join(DATA_DIR, 'hy2.txt'), 'w', encoding='utf-8') as f:
            for node in unique_nodes:
                f.write(f"{node}\n")
    
    # 保存无效 URL（追加模式，避免覆盖search_urls.py的结果）
    if invalid_urls:
        with open(os.path.join(DATA_DIR, 'invalid_urls.txt'), 'a', encoding='utf-8') as f:
            for url, info in invalid_urls.items():
                f.write(f"{info['timestamp']} | {url} | {info['reason']}\n")
    
    # 统计
    logger.info(f"统计: 共处理 {processed_urls} 个 URL，提取 {len(unique_nodes)} 个有效节点")
    for url, count in url_node_counts.items():
        if count > 0:
            logger.info(f"URL {url} 提供 {count} 个节点")
        else:
            logger.info(f"URL {url} 无节点")
    logger.info(f"无效 URL 数量: {len(invalid_urls)}")

if __name__ == "__main__":
    asyncio.run(main())
