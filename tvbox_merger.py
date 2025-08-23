import json
import os
import sys
import logging
from typing import List, Dict, Any, Tuple
import asyncio
import aiohttp
from urllib.parse import urlparse

# 配置日志系统，将日志输出到控制台
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

# URL有效性检查缓存，避免重复请求
URL_CACHE = {}
# 限制缓存大小，防止占用过多内存
MAX_CACHE_SIZE = 10000

# 定义需要排除的域名列表，这些域名通常无法访问
EXCLUDED_DOMAINS = ["agit.ai", "gitcode.net", "cccimg.com"]

def strip_proxy(url: str) -> str:
    """
    剥离URL中现有的加速代理前缀，只保留原始链接。
    例如：将 'https://ghproxy.com/https://raw.githubusercontent.com/...' 
    转换为 'https://raw.githubusercontent.com/...'
    """
    proxies = [
        'https://ghproxy.com/',
        'https://ghp.ci/',
        'https://raw.gitmirror.com/',
        'https://github.3x25.com/',
        'https://ghfast.top/',
        'https://github.moeyy.xyz/',
        'https://ghproxy.net/'
    ]
    for proxy in proxies:
        if url.startswith(proxy):
            original_url = url[len(proxy):]
            if not original_url.startswith(('http://', 'https://')):
                original_url = 'https://' + original_url
            logger.debug(f"已剥离代理前缀: {url} -> {original_url}")
            return original_url
    return url

def add_gh_proxy_if_needed(url: str) -> str:
    """
    如果URL包含GitHub链接（raw.githubusercontent.com 或 github.com），则在其前统一添加加速代理。
    """
    gh_domains = ['raw.githubusercontent.com', 'github.com']
    for domain in gh_domains:
        if domain in url:
            new_url = f"https://ghfast.top/{url}"
            logger.debug(f"已为GitHub链接添加代理: {url} -> {new_url}")
            return new_url
    return url

async def is_valid_url(url: str, session: aiohttp.ClientSession) -> bool:
    """
    异步检查URL是否有效且可访问。
    """
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    # 优先检查域名是否在排除列表中
    if domain in EXCLUDED_DOMAINS:
        logger.debug(f"URL域名位于排除列表中: {domain}")
        return False
    
    # 检查URL格式和本地相对路径
    if not all([parsed_url.scheme, parsed_url.netloc]) or url.startswith('.'):
        logger.debug(f"无效的URL格式或本地相对路径: {url}")
        return False

    # 优先检查缓存
    if url in URL_CACHE:
        logger.debug(f"正在使用缓存结果: {url}: {URL_CACHE[url]}")
        return URL_CACHE[url]
    
    # 如果缓存过大，则清空
    if len(URL_CACHE) > MAX_CACHE_SIZE:
        URL_CACHE.clear()
        logger.info("URL缓存因达到大小限制已清空。")

    try:
        async with session.head(url, timeout=5) as response:
            is_valid = response.status == 200
            URL_CACHE[url] = is_valid
            if not is_valid:
                logger.debug(f"URL无效 (状态码 {response.status}): {url}")
            return is_valid
    except aiohttp.ClientError as e:
        logger.debug(f"连接失败 {url}: {e}")
        URL_CACHE[url] = False
        return False
    except asyncio.TimeoutError:
        logger.debug(f"检查URL超时: {url}")
        URL_CACHE[url] = False
        return False
    except Exception as e:
        logger.debug(f"URL {url} 发生意外错误: {e}")
        URL_CACHE[url] = False
        return False

async def process_file(filepath: str, session: aiohttp.ClientSession) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """
    读取并解析单个JSON文件，对其中的点播源和直播源进行处理和有效性过滤。
    """
    sites: List[Dict[str, Any]] = []
    lives: List[Dict[str, Any]] = []
    spider: List[str] = []

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
            if not content.strip():
                logger.warning(f"文件 '{filepath}' 为空，跳过。")
                return sites, lives, spider
            
            data = json.loads(content)
            
            # 情况1: 文件是完整的配置，包含 'sites', 'lives' 等键
            if isinstance(data, dict) and ('sites' in data or 'lives' in data or 'spider' in data):
                all_sites = data.get('sites', [])
                all_lives = data.get('lives', [])
                all_spider = [data.get('spider', "")]
                
                # 验证和处理点播源
                tasks = []
                for site in all_sites:
                    api_url = site.get('api', '')
                    # 检查并删除本地路径的jar和ext
                    if site.get('jar', '').startswith('.'):
                        logger.debug(f"从 '{filepath}' 中删除本地jar路径: {site.get('jar', '')}")
                        del site['jar']
                    if site.get('ext', '').startswith('.'):
                        logger.debug(f"从 '{filepath}' 中删除本地ext路径: {site.get('ext', '')}")
                        del site['ext']

                    if api_url:
                        stripped_url = strip_proxy(api_url)
                        processed_url = add_gh_proxy_if_needed(stripped_url)
                        site['api'] = processed_url
                        tasks.append(is_valid_url(processed_url, session))
                    else:
                        tasks.append(asyncio.sleep(0, result=False))

                valid_results = await asyncio.gather(*tasks)

                for site, is_valid in zip(all_sites, valid_results):
                    if is_valid:
                        sites.append(site)
                    else:
                        logger.debug(f"从 '{filepath}' 中排除无效的点播源: {site.get('name', '未命名')}")
                
                # 验证和处理直播源
                live_tasks = []
                valid_lives = []
                for live_channel in all_lives:
                    if isinstance(live_channel, dict) and 'url' in live_channel:
                        # 确保链接不是proxy://或本地相对路径
                        if not live_channel['url'].startswith('proxy://') and not live_channel['url'].startswith('.'):
                            stripped_url = strip_proxy(live_channel['url'])
                            processed_url = add_gh_proxy_if_needed(stripped_url)
                            live_channel['url'] = processed_url
                            live_tasks.append(is_valid_url(processed_url, session))
                            valid_lives.append(live_channel)
                        else:
                            logger.warning(f"从 '{filepath}' 中排除非标准的直播源（代理或本地路径）: {live_channel.get('name', '未命名')}")
                    elif 'channels' in live_channel or 'group' in live_channel:
                        logger.warning(f"从 '{filepath}' 中排除非标准分组的直播源: {live_channel.get('name', '未命名')}")

                valid_live_results = await asyncio.gather(*live_tasks)
                for live_channel, is_valid in zip(valid_lives, valid_live_results):
                    if is_valid:
                        lives.append(live_channel)
                    else:
                        logger.warning(f"从 '{filepath}' 中排除无效的直播源: {live_channel.get('name', '未命名')}")
                
                if all_spider and all_spider[0]:
                    spider.extend(all_spider)

            # 情况2: 文件是单个站点对象
            elif isinstance(data, dict) and 'api' in data and 'name' in data:
                site_url = data.get('api', '')
                # 检查并删除本地路径的jar和ext
                if data.get('jar', '').startswith('.'):
                    logger.debug(f"从 '{filepath}' 中删除本地jar路径: {data.get('jar', '')}")
                    del data['jar']
                if data.get('ext', '').startswith('.'):
                    logger.debug(f"从 '{filepath}' 中删除本地ext路径: {data.get('ext', '')}")
                    del data['ext']
                
                if site_url:
                    stripped_url = strip_proxy(site_url)
                    processed_url = add_gh_proxy_if_needed(stripped_url)
                    data['api'] = processed_url
                    is_valid = await is_valid_url(processed_url, session)
                    if is_valid:
                        sites.append(data)
                    else:
                        logger.debug(f"从 '{filepath}' 中排除无效的单个站点源: {data.get('name', '未命名')}")
            else:
                logger.warning(f"文件 '{filepath}' 不包含有效的站点配置，跳过。")

    except json.JSONDecodeError as e:
        logger.error(f"解析文件 '{filepath}' 中的JSON失败: {e}")
    except Exception as e:
        logger.error(f"处理文件 '{filepath}' 时发生错误: {e}")
    
    return sites, lives, spider

def deduplicate_sources(sources: List[Dict[str, Any]], key_field: str) -> List[Dict[str, Any]]:
    """
    根据给定的字段（例如'api'或'url'）对源列表进行去重。
    """
    seen_urls = set()
    deduplicated_list = []
    for source in sources:
        # 使用get方法来避免键不存在时出错
        url = source.get(key_field)
        if url and url not in seen_urls:
            deduplicated_list.append(source)
            seen_urls.add(url)
        elif url:
            logger.debug(f"已移除重复的源: {source.get('name', '未命名')} - {url}")
    return deduplicated_list

async def merge_files(source_files: List[str], output_file: str):
    """
    将多个JSON配置文件合并成一个。
    """
    logger.info("开始合并配置文件...")
    sites: List[Dict[str, Any]] = []
    lives: List[Dict[str, Any]] = []
    spider: List[str] = []

    async with aiohttp.ClientSession() as session:
        tasks = [process_file(f, session) for f in source_files]
        results = await asyncio.gather(*tasks)
        
        for result in results:
            if isinstance(result, tuple):
                file_sites, file_lives, file_spider = result
                sites.extend(file_sites)
                lives.extend(file_lives)
                if file_spider and not spider:
                    spider.extend(file_spider)
    
    # 对点播源和直播源进行去重
    deduplicated_sites = deduplicate_sources(sites, 'api')
    deduplicated_lives = deduplicate_sources(lives, 'url')

    merged_data = {
        "sites": deduplicated_sites,
        "lives": deduplicated_lives,
        "spider": spider[0] if spider else ""
    }

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(merged_data, f, ensure_ascii=False, indent=2)
        logger.info(f"所有配置已成功合并并保存到 '{output_file}'。")
        logger.info(f"有效去重后的点播源总数: {len(deduplicated_sites)}, 有效去重后的直播源总数: {len(deduplicated_lives)}")
    except Exception as e:
        logger.error(f"保存合并文件时发生错误: {e}")

if __name__ == "__main__":
    SOURCE_DIRECTORY = "box"
    OUTPUT_FILE = "merged_tvbox_config.json"

    if os.path.exists(SOURCE_DIRECTORY) and os.path.isdir(SOURCE_DIRECTORY):
        source_files = [
            os.path.join(SOURCE_DIRECTORY, f)
            for f in os.listdir(SOURCE_DIRECTORY)
            if f.endswith(('.json', '.txt'))
        ]
        if source_files:
            asyncio.run(merge_files(source_files, OUTPUT_FILE))
        else:
            logger.error(f"在 '{SOURCE_DIRECTORY}' 目录下未找到 .json 或 .txt 文件。")
    else:
        logger.error(f"源目录 '{SOURCE_DIRECTORY}' 不存在或不是一个目录。请创建它并将您的JSON/TXT文件放入其中。")
