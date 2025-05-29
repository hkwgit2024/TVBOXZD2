import os
import re
import base64
import yaml
import json
import time
import datetime
import logging
import argparse
from concurrent.futures import ThreadPoolExecutor
from github import Github
from github.GithubException import RateLimitExceededException, UnknownObjectException
from tqdm import tqdm

# 配置日志系统
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.FileHandler("node_extractor.log"), logging.StreamHandler()]
)

# 命令行参数解析
parser = argparse.ArgumentParser(description="GitHub Node Extractor")
parser.add_argument("--output", default="data/clash_config.yaml", help="Output Clash config file path")
parser.add_argument("--history", default="data/nodes_history.json", help="History file path")
parser.add_argument("--config", default="config.yaml", help="Configuration file path")
args = parser.parse_args()

# 加载配置文件
def load_config(config_file):
    default_config = {
        "search": {
            "extensions": ["txt", "md", "json", "yaml", "yml", "conf", "cfg"],
            "keywords": ["ss://", "ssr://", "vmess://", "trojan://", "vless://", "hysteria://"],
            "excluded_extensions": [
                "zip", "tar", "gz", "rar", "7z", "jpg", "jpeg", "png", "gif", "bmp", "svg", "ico",
                "mp3", "wav", "ogg", "mp4", "avi", "mov", "mkv", "pdf", "doc", "docx", "xls",
                "xlsx", "ppt", "pptx", "exe", "dll", "so", "bin", "class", "jar", "pyc"
            ]
        },
        "query_delay_seconds": 38,
        "max_file_size": 1_000_000,  # 1MB
        "history_expiry_days": 30,
        "max_parallel_workers": 5,
        "max_backoff_seconds": 300  # 最大退避时间
    }
    if os.path.exists(config_file):
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                user_config = yaml.safe_load(f)
            default_config.update(user_config)
            logging.info(f"已加载配置文件：{config_file}")
        except Exception as e:
            logging.warning(f"无法加载配置文件 {config_file}：{e}，使用默认配置")
    return default_config

CONFIG = load_config(args.config)
HISTORY_FILE = args.history
OUTPUT_FILE = args.output

# 初始化 GitHub 客户端
GITHUB_TOKEN = os.getenv("BOT")
if not GITHUB_TOKEN:
    logging.error("未找到 GitHub 令牌（BOT），请设置 'BOT' 环境变量")
    exit(1)
g = Github(GITHUB_TOKEN)

# 加载历史记录
nodes_history = {}
if os.path.exists(HISTORY_FILE):
    try:
        with open(HISTORY_FILE, "r", encoding="utf-8") as f:
            nodes_history = json.load(f)
        logging.info(f"从历史记录文件 {HISTORY_FILE} 加载了 {len(nodes_history)} 个节点")
    except json.JSONDecodeError:
        logging.warning(f"无法解析 JSON 文件 {HISTORY_FILE}，使用空历史记录")
        nodes_history = {}
    except Exception as e:
        logging.error(f"加载历史记录文件 {HISTORY_FILE} 失败：{e}，使用空历史记录")
        nodes_history = {}

current_run_nodes = set()

# 协议和搜索关键词
protocol_keywords = CONFIG["search"]["keywords"]
search_keywords = protocol_keywords + [kw.split("://")[0] for kw in protocol_keywords if "://" in kw]
search_extensions = CONFIG["search"]["extensions"]
excluded_extensions = CONFIG["search"]["excluded_extensions"]

# 生成搜索查询
search_queries = []
override_query = os.getenv("OVERRIDE_SEARCH_QUERY")
if override_query:
    search_queries.append(override_query)
    logging.info(f"使用覆盖查询：{override_query}")
else:
    for ext in search_extensions:
        for kw in search_keywords:
            search_queries.append(f'"{kw}" in:file extension:{ext}')
    search_queries.append(f'("ss://" OR "ssr://" OR "vmess://") in:file filename:config')
    search_queries.append(f'("ss://" OR "ssr://" OR "vmess://") in:file filename:nodes')
    search_queries.append(f'("ss://" OR "ssr://" OR "vmess://") in:file filename:sub')
    excluded_query_part = " ".join([f"-extension:{e}" for e in excluded_extensions])
    general_nodes_query = f'({" OR ".join([f'"{kw}"' for kw in protocol_keywords])}) in:file {excluded_query_part}'
    search_queries.append(general_nodes_query)
logging.info(f"生成了 {len(search_queries)} 个搜索查询")

# 正则表达式
NODE_PATTERN = re.compile(r"(ss://[^\s]+|ssr://[^\s]+|vmess://[^\s]+|trojan://[^\s]+|vless://[^\s]+|hysteria://[^\s]+)")

# 节点提取器接口
class NodeExtractor:
    def extract(self, content):
        raise NotImplementedError

class Base64Extractor(NodeExtractor):
    def extract(self, content):
        links = []
        try:
            cleaned_text = content.replace(" ", "").replace("\n", "").replace("\r", "")
            padding_needed = 4 - (len(cleaned_text) % 4)
            if padding_needed != 4:
                cleaned_text += '=' * padding_needed
            decoded_bytes = base64.b64decode(cleaned_text, validate=True)
            decoded_string = decoded_bytes.decode('utf-8', errors='ignore')
            links.extend(NODE_PATTERN.findall(decoded_string))
        except Exception:
            pass
        return links

class YAMLExtractor(NodeExtractor):
    def extract(self, content):
        links = []
        try:
            data = yaml.safe_load(content)
            if isinstance(data, (dict, list)):
                def find_urls_in_yaml(item):
                    if isinstance(item, dict):
                        for key, value in item.items():
                            if isinstance(value, str):
                                links.extend(NODE_PATTERN.findall(value))
                            else:
                                find_urls_in_yaml(value)
                    elif isinstance(item, list):
                        for value in item:
                            if isinstance(value, str):
                                links.extend(NODE_PATTERN.findall(value))
                            else:
                                find_urls_in_yaml(value)
                    elif isinstance(item, str):
                        links.extend(NODE_PATTERN.findall(item))
                find_urls_in_yaml(data)
        except yaml.YAMLError:
            pass
        return links

extractors = [Base64Extractor(), YAMLExtractor()]

# 处理单个搜索结果
def process_search_result(result):
    global current_run_nodes
    try:
        if result.size > CONFIG["max_file_size"]:
            logging.warning(f"跳过 {result.path}（位于 {result.repository.full_name}）：文件大小 {result.size} 超过 {CONFIG['max_file_size']} 字节")
            return

        file_content = result.decoded_content.decode('utf-8', errors='ignore')
        found_nodes = NODE_PATTERN.findall(file_content)
        current_run_nodes.update(found_nodes)

        # 应用提取器
        for extractor in extractors:
            current_run_nodes.update(extractor.extract(file_content))

        # 处理 Base64 编码内容
        base64_pattern = re.compile(r"[A-Za-z0-9+/]{16,}(?:={0,2})")
        for b64_str in base64_pattern.findall(file_content):
            for extractor in extractors:
                if isinstance(extractor, Base64Extractor):
                    current_run_nodes.update(extractor.extract(b64_str))

        logging.debug(f"处理了 {result.path}（位于 {result.repository.full_name}）：找到 {len(found_nodes)} 个节点")

    except UnknownObjectException as e:
        logging.warning(f"无法访问或对象不存在：{result.path}（位于 {result.repository.full_name}）：{e}")
    except Exception as e:
        logging.error(f"处理 {result.path}（位于 {result.repository.full_name}）时出错：{e}")

# 并行处理搜索结果
def process_search_results_parallel(results, max_workers):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(tqdm(executor.map(process_search_result, results), desc="处理搜索结果", unit="文件"))

# 清理过期历史记录
def clean_old_nodes(history):
    now = datetime.datetime.now(datetime.timezone.utc)
    cutoff = now - datetime.timedelta(days=CONFIG["history_expiry_days"])
    return {k: v for k, v in history.items() if datetime.datetime.fromisoformat(v) > cutoff}

# 生成 Clash 配置文件
def save_as_clash_config(nodes, output_file):
    clash_config = {
        "proxies": [],
        "proxy-groups": [
            {
                "name": "auto",
                "type": "url-test",
                "proxies": [],
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300
            }
        ],
        "rules": [
            "MATCH,auto"
        ]
    }
    for idx, node in enumerate(sorted(nodes)):
        proxy = {
            "name": f"node-{idx}",
            "type": node.split("://")[0],
            "server": "unknown",
            "port": 0,
            "node-url": node
        }
        clash_config["proxies"].append(proxy)
        clash_config["proxy-groups"][0]["proxies"].append(f"node-{idx}")

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    logging.info(f"已保存 Clash 配置文件，包含 {len(nodes)} 个代理到 '{output_file}'")

# 主逻辑
def main():
    global current_run_nodes
    for current_query in search_queries:
        logging.info(f"正在 GitHub 上搜索：'{current_query}'...")
        try:
            rate_limit_before = g.get_rate_limit().core
            reset_timestamp = rate_limit_before.reset.timestamp()
            logging.info(f"查询前 - 剩余 API 调用次数：{rate_limit_before.remaining}/{rate_limit_before.limit}，重置时间：{time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(reset_timestamp))}")

            if rate_limit_before.remaining <= 10:  # 留一些余量
                wait_seconds = reset_timestamp - time.time() + 5
                logging.warning(f"API 调用次数不足（剩余 {rate_limit_before.remaining}），等待 {wait_seconds} 秒直到 {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(reset_timestamp))}...")
                time.sleep(max(wait_seconds, 0))
                continue

            search_results = g.search_code(query=current_query)
            process_search_results_parallel(search_results, CONFIG["max_parallel_workers"])
            logging.info(f"完成查询 '{current_query}' 的结果处理")
            time.sleep(CONFIG["query_delay_seconds"])

        except RateLimitExceededException:
            logging.warning("GitHub API 速率限制已达上限")
            rate_limit = g.get_rate_limit().core
            reset_timestamp = rate_limit.reset.timestamp()
            wait_seconds = reset_timestamp - time.time() + 5
            reset_time_utc = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(reset_timestamp))
            logging.info(f"当前剩余 API 调用次数：{rate_limit.remaining}，等待 {wait_seconds} 秒直到 {reset_time_utc}...")
            time.sleep(max(wait_seconds, 0))
            continue
        except Exception as e:
            if "403" in str(e):
                logging.warning(f"遇到 403 Forbidden 错误，可能触发次级速率限制：{e}")
                wait_seconds = min(CONFIG["max_backoff_seconds"], 300)  # 默认等待 5 分钟
                logging.info(f"等待 {wait_seconds} 秒后重试...")
                time.sleep(wait_seconds)
                continue
            logging.error(f"搜索查询 '{current_query}' 期间发生意外错误：{e}")
            continue

    # 更新历史记录
    current_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    newly_added_count = 0
    for node_link in current_run_nodes:
        if node_link not in nodes_history:
            newly_added_count += 1
        nodes_history[node_link] = current_timestamp

    # 清理过期记录
    nodes_history.update(clean_old_nodes(nodes_history))

    logging.info(f"\n--- 节点历史记录更新 ---")
    logging.info(f"本次运行找到 {len(current_run_nodes)} 个唯一节点")
    logging.info(f"新增到历史记录的节点：{newly_added_count}")
    logging.info(f"历史记录中总节点数：{len(nodes_history)}")

    # 保存历史记录
    os.makedirs(os.path.dirname(HISTORY_FILE), exist_ok=True)
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(nodes_history, f, ensure_ascii=False, indent=2)
        logging.info(f"已更新历史记录并保存到 '{HISTORY_FILE}'")
    except Exception as e:
        logging.error(f"无法保存历史记录文件 {HISTORY_FILE}：{e}")

    # 保存为 Clash 配置文件
    save_as_clash_config(current_run_nodes, OUTPUT_FILE)

if __name__ == "__main__":
    main()
