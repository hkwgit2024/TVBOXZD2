import os
import re
import subprocess
import requests
import time
import logging
import logging.handlers
import yaml
from urllib.parse import urlparse
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from tqdm import tqdm

# 配置日志系统，支持文件和控制台输出
def setup_logging(config):
    """配置日志系统，支持文件和控制台输出，日志文件自动轮转以避免过大
    参数:
        config: 配置文件字典，包含日志级别和日志文件路径
    返回:
        配置好的日志记录器
    """
    log_level = getattr(logging, config['logging']['log_level'], logging.INFO)
    log_file = config['logging']['log_file']
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logger = logging.getLogger()
    logger.setLevel(log_level)

    # 文件处理器，支持日志文件轮转，最大10MB，保留1个备份
    file_handler = logging.handlers.RotatingFileHandler(
        log_file, maxBytes=10*1024*1024, backupCount=1
    )
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))

    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    ))

    logger.handlers = [file_handler, console_handler]
    return logger

# 加载配置文件
def load_config(config_path="config/config.yaml"):
    """加载并解析 YAML 配置文件
    参数:
        config_path: 配置文件路径，默认为 'config/config.yaml'
    返回:
        解析后的配置字典
    """
    try:
        with open(config_path, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file)
            logging.info("配置文件 config.yaml 加载成功")
            return config
    except FileNotFoundError:
        logging.error(f"错误：未找到配置文件 '{config_path}'")
        exit(1)
    except yaml.YAMLError as e:
        logging.error(f"错误：配置文件 '{config_path}' 格式错误: {e}")
        exit(1)
    except Exception as e:
        logging.error(f"错误：加载配置文件 '{config_path}' 失败: {e}")
        exit(1)

# 读取本地 TXT 文件
def read_txt_to_array_local(file_name):
    """从本地 TXT 文件读取内容到数组
    参数:
        file_name: 文件路径
    返回:
        包含文件每行内容的列表
    """
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            lines = [line.strip() for line in file if line.strip()]
        return lines
    except FileNotFoundError:
        logging.warning(f"文件 '{file_name}' 未找到")
        return []
    except Exception as e:
        logging.error(f"读取文件 '{file_name}' 失败: {e}")
        return []

# 写入本地 TXT 文件
def write_array_to_txt_local(file_path, data_array):
    """将数组内容写入本地 TXT 文件
    参数:
        file_path: 输出文件路径
        data_array: 要写入的数据数组
    """
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as file:
            file.write('\n'.join(data_array))
        logging.info(f"写入 {len(data_array)} 行到 '{file_path}'")
    except Exception as e:
        logging.error(f"写入文件 '{file_path}' 失败: {e}")

# 加载配置和设置日志
CONFIG_PATH = "config/config.yaml"
CONFIG = load_config(CONFIG_PATH)
setup_logging(CONFIG)

# 检查环境变量 GITHUB_TOKEN
GITHUB_TOKEN = os.getenv('BOT')
if not GITHUB_TOKEN:
    logging.error("错误：未设置环境变量 'BOT'")
    exit(1)

# 从配置中获取文件路径
URLS_PATH = CONFIG['output']['paths']['channel_cache_file'].replace('channel_cache.json', 'urls.txt')

# GitHub API 基础 URL
GITHUB_API_BASE_URL = "https://api.github.com"
SEARCH_CODE_ENDPOINT = "/search/code"

# 配置 requests 会话
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
})
pool_size = CONFIG['network']['requests_pool_size']
retry_strategy = Retry(
    total=3,
    backoff_factor=CONFIG['network']['requests_retry_backoff_factor'],
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"]
)
adapter = HTTPAdapter(
    pool_connections=pool_size,
    pool_maxsize=pool_size,
    max_retries=retry_strategy
)
session.mount("http://", adapter)
session.mount("https://", adapter)

def auto_discover_github_urls(urls_file_path_local, github_token):
    """从 GitHub 自动发现新的 IPTV 源 URL
    参数:
        urls_file_path_local: 本地 URL 文件路径
        github_token: GitHub API 令牌
    """
    if not github_token:
        logging.warning("未提供 GitHub token，跳过 URL 自动发现")
        return

    existing_urls = set(read_txt_to_array_local(urls_file_path_local))
    for backup_url in CONFIG.get('backup_urls', []):
        try:
            response = session.get(backup_url, timeout=10)
            response.raise_for_status()
            existing_urls.update([line.strip() for line in response.text.split('\n') if line.strip()])
        except Exception as e:
            logging.warning(f"从备用 URL {backup_url} 获取失败: {e}")

    found_urls = set()
    headers = {
        "Accept": "application/vnd.github.v3.text-match+json",
        "Authorization": f"token {github_token}"
    }

    logging.warning("开始从 GitHub 自动发现新的 IPTV 源 URL")
    keyword_url_counts = {keyword: 0 for keyword in CONFIG.get('search_keywords', [])}
    
    keywords_list = CONFIG.get('search_keywords', [])
    total_keywords = len(keywords_list)

    for i, keyword in enumerate(tqdm(keywords_list, desc="关键词搜索进度")):
        keyword_found_urls = set()
        if i > 0:
            logging.warning(f"切换到下一个关键词: '{keyword}'，等待 {CONFIG['github']['retry_wait']} 秒以避免速率限制")
            time.sleep(CONFIG['github']['retry_wait'])

        page = 1
        while page <= CONFIG['github']['max_search_pages']:
            params = {
                "q": keyword,
                "sort": "indexed",
                "order": "desc",
                "per_page": CONFIG['github']['per_page'],
                "page": page
            }
            try:
                response = session.get(
                    f"{GITHUB_API_BASE_URL}{SEARCH_CODE_ENDPOINT}",
                    headers=headers,
                    params=params,
                    timeout=CONFIG['github']['api_timeout']
                )
                response.raise_for_status()
                data = response.json()

                rate_limit_remaining = int(response.headers.get('X-RateLimit-Remaining', 0))
                rate_limit_reset = int(response.headers.get('X-RateLimit-Reset', 0))

                if rate_limit_remaining == 0:
                    wait_seconds = max(0, rate_limit_reset - time.time()) + 5
                    logging.warning(f"GitHub API 速率限制达到，剩余请求: 0，等待 {wait_seconds:.0f} 秒")
                    time.sleep(wait_seconds)
                    continue

                if not data.get('items'):
                    logging.info(f"关键词 '{keyword}' 在第 {page} 页无结果")
                    break

                for item in data['items']:
                    html_url = item.get('html_url', '')
                    raw_url = None
                    match = re.search(r'https?://github\.com/([^/]+)/([^/]+)/blob/([^/]+)/(.*)', html_url)
                    if match:
                        user, repo, branch, file_path = match.groups()
                        raw_url = f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{file_path}"
                    else:
                        logging.info(f"无法解析 raw URL: {html_url}")
                        continue

                    if raw_url and raw_url not in existing_urls and raw_url not in found_urls:
                        try:
                            content_response = session.get(raw_url, timeout=5)
                            content_response.raise_for_status()
                            content = content_response.text
                            if re.search(r'#EXTM3U', content, re.IGNORECASE) or re.search(r'\.(m3u8|m3u|txt|csv|ts|flv|mp4|hls|dash)$', raw_url, re.IGNORECASE):
                                found_urls.add(raw_url)
                                keyword_found_urls.add(raw_url)
                                logging.info(f"发现新的 IPTV 源 URL: {raw_url}")
                            else:
                                logging.info(f"URL {raw_url} 不包含 M3U 内容或不支持的文件扩展名，跳过")
                        except requests.exceptions.RequestException as req_e:
                            logging.info(f"获取 {raw_url} 内容失败: {req_e}")
                        except Exception as exc:
                            logging.info(f"检查 {raw_url} 内容时发生意外错误: {exc}")

                logging.info(f"完成关键词 '{keyword}' 第 {page} 页，发现 {len(keyword_found_urls)} 个新 URL")
                page += 1

            except requests.exceptions.RequestException as e:
                if isinstance(e, requests.exceptions.HTTPError) and e.response.status_code == 403:
                    logging.error(f"GitHub API 速率限制或访问被拒绝，关键词 '{keyword}': {e}")
                    if rate_limit_remaining == 0:
                        wait_seconds = max(0, rate_limit_reset - time.time()) + 5
                        logging.warning(f"关键词 '{keyword}' 速率限制，等待 {wait_seconds:.0f} 秒")
                        time.sleep(wait_seconds)
                        continue
                else:
                    logging.error(f"搜索 GitHub 关键词 '{keyword}' 失败: {e}")
                break
            except Exception as e:
                logging.error(f"搜索 GitHub 关键词 '{keyword}' 时发生意外错误: {e}")
                break
        keyword_url_counts[keyword] = len(keyword_found_urls)

    if found_urls:
        updated_urls = sorted(list(existing_urls | found_urls))
        logging.warning(f"发现 {len(found_urls)} 个新唯一 URL，总计保存 {len(updated_urls)} 个 URL")
        write_array_to_txt_local(urls_file_path_local, updated_urls)
    else:
        logging.warning("未发现新的 IPTV 源 URL")

    for keyword, count in keyword_url_counts.items():
        logging.warning(f"关键词 '{keyword}' 发现 {count} 个新 URL")

if __name__ == "__main__":
    auto_discover_github_urls(URLS_PATH, GITHUB_TOKEN)
