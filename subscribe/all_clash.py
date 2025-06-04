# -*- coding: utf-8 -*-
import os
import requests
from urllib.parse import urlparse
import base64
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from tqdm import tqdm
import argparse
import re
import yaml
import json
import csv # 导入csv库

# 配置日志
logging.basicConfig(filename='error.log', level=logging.ERROR,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# 请求头
headers = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/91.0.4472.124 Safari/537.36'
    ),
    'Accept-Encoding': 'gzip, deflate'
}

# 命令行参数
parser = argparse.ArgumentParser(description="URL内容获取脚本，支持多个URL来源和节点解析")
parser.add_argument('--max_success', type=int, default=99999, help="目标成功数量")
parser.add_argument('--timeout', type=int, default=60, help="请求超时时间（秒）")
parser.add_argument('--output', type=str, default='data/all_clash.txt', help="输出文件路径")
args = parser.parse_args()

MAX_SUCCESS = args.max_success
TIMEOUT = args.timeout
OUTPUT_FILE = args.output
TEMP_MERGED_FILE = 'temp_merged_nodes.txt' # 中间文件路径
STATISTICS_FILE = 'data/url_statistics.csv' # 统计文件路径
SUCCESS_URLS_FILE = 'data/successful_urls.txt' # 成功获取的URL列表文件
FAILED_URLS_FILE = 'data/failed_urls.txt' # 获取失败的URL列表文件

def is_valid_url(url):
    """验证URL格式是否合法，仅接受 http 或 https 方案"""
    try:
        result = urlparse(url)
        return all([result.scheme in ['http', 'https'], result.netloc])
    except Exception:
        return False

def get_url_list_from_remote(url_source):
    """从给定的公开网址获取 URL 列表"""
    try:
        response = requests.get(url_source, headers=headers, timeout=10)
        response.raise_for_status()
        text_content = response.text.strip()
        raw_urls = [line.strip() for line in text_content.splitlines() if line.strip()]
        print(f"从 {url_source} 获取到 {len(raw_urls)} 个URL")
        return raw_urls
    except Exception as e:
        logging.error(f"获取URL列表失败: {url_source} - {e}")
        return []

def parse_content_to_nodes(content):
    """
    从文本内容中解析出各种类型的节点。
    支持 Base64 解码、Clash YAML 格式的proxies，以及多种节点协议的直接链接。
    """
    if not content:
        return []

    found_nodes = set()
    processed_content = content

    # 1. 尝试 Base64 解码
    try:
        decoded_bytes = base64.b64decode(content)
        processed_content = decoded_bytes.decode('utf-8')
        logging.info("内容成功 Base64 解码。")
    except Exception:
        pass

    # 2. 尝试 YAML 解析 (主要用于 Clash 配置)
    try:
        parsed_data = yaml.safe_load(processed_content)
        if isinstance(parsed_data, dict) and 'proxies' in parsed_data and isinstance(parsed_data['proxies'], list):
            for proxy_entry in parsed_data['proxies']:
                if isinstance(proxy_entry, dict):
                    node_str_representation = json.dumps(proxy_entry, sort_keys=True, ensure_ascii=False)
                    found_nodes.add(node_str_representation)
                elif isinstance(proxy_entry, str) and (
                    proxy_entry.startswith("vmess://") or
                    proxy_entry.startswith("trojan://") or
                    proxy_entry.startswith("ss://") or
                    proxy_entry.startswith("ssr://") or
                    proxy_entry.startswith("vless://") or
                    proxy_entry.startswith("hy://") or
                    proxy_entry.startswith("hy2://") or
                    proxy_entry.startswith("hysteria://") or
                    proxy_entry.startswith("hysteria2://")
                ):
                    found_nodes.add(proxy_entry.strip())
            logging.info("内容成功解析为 Clash YAML。")
        elif isinstance(parsed_data, list):
            for item in parsed_data:
                if isinstance(item, str):
                    found_nodes.add(item.strip())
            logging.info("内容成功解析为 YAML 列表。")
    except yaml.YAMLError:
        pass
    except Exception as e:
        logging.error(f"YAML 解析失败: {e}")
        pass

    # 3. 通过正则表达式提取节点
    node_pattern = re.compile(
        r'(vmess://\S+|'
        r'trojan://\S+|'
        r'ss://\S+|'
        r'ssr://\S+|'
        r'vless://\S+|'
        r'hy://\S+|'
        r'hy2://\S+|'
        r'hysteria://\S+|'
        r'hysteria2://\S+)'
    )

    matches = node_pattern.findall(content)
    for match in matches:
        found_nodes.add(match.strip())

    if content != processed_content:
        matches_decoded = node_pattern.findall(processed_content)
        for match in matches_decoded:
            found_nodes.add(match.strip())

    return list(found_nodes) # 返回列表

def fetch_and_parse_url(url):
    """
    获取URL内容并解析出节点。
    返回一个元组：(节点列表, 是否成功, 错误信息(如果失败))
    """
    try:
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status()
        content = resp.text.strip()

        if len(content) < 10:
            logging.warning(f"获取到内容过短，可能无效: {url}")
            return [], False, "内容过短"

        nodes = parse_content_to_nodes(content)
        return nodes, True, None
    except requests.exceptions.Timeout:
        logging.error(f"请求超时: {url}")
        return [], False, "请求超时"
    except requests.exceptions.RequestException as e:
        logging.error(f"请求失败: {url} - {e}")
        return [], False, f"请求失败: {e}"
    except Exception as e:
        logging.error(f"处理URL异常: {url} - {e}")
        return [], False, f"未知异常: {e}"

def write_statistics_to_csv(statistics_data, filename):
    """将统计数据写入CSV文件"""
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        fieldnames = ['URL', '节点数量', '状态', '错误信息']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        writer.writeheader()
        for row in statistics_data:
            writer.writerow(row)
    print(f"统计数据已保存至：{filename}")

def write_urls_to_file(urls, filename):
    """将URL列表写入文件"""
    with open(filename, 'w', encoding='utf-8') as f:
        for url in urls:
            f.write(url + '\n')
    print(f"URL列表已保存至：{filename}")

# --- 主程序流程 ---

# 从环境变量中读取 URL_SOURCE 并调试
URL_SOURCE = os.environ.get("URL_SOURCE")
print(f"调试信息 - 读取到的 URL_SOURCE 值: {URL_SOURCE}")

initial_urls_to_fetch = set()

if URL_SOURCE:
    print(f"将从远程URL_SOURCE获取订阅链接: {URL_SOURCE}")
    raw_urls_from_remote = get_url_list_from_remote(URL_SOURCE)
    for url in raw_urls_from_remote:
        if is_valid_url(url):
            initial_urls_to_fetch.add(url)
        else:
            logging.warning(f"URL_SOURCE中发现非HTTP/HTTPS订阅链接（将被忽略，但会尝试解析为节点）：{url}")
            # 如果不是有效的URL，但可能是直接的节点字符串，将其作为内容进行解析
            # 这些节点不会参与requests请求，而是直接进入合并阶段
            nodes_from_direct_string = parse_content_to_nodes(url)
            if nodes_from_direct_string:
                # 暂时不在这里直接加入temp_merged_nodes_set，因为temp_merged_nodes_set在多线程处理后才统一写入
                # 这里只记录一下，这些节点会在最终去重时被捕获
                pass
else:
    print("错误：环境变量 'URL_SOURCE' 未设置。无法获取订阅链接。")
    exit(1)

# 确保输出目录存在
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

# 阶段一：解析URL内容，下载并合并多个URL的节点到临时文件
print("\n--- 阶段一：获取并合并所有来源的节点 ---")
temp_merged_nodes_set = set() # 用于阶段一的去重
url_statistics = [] # 存储每个URL的统计数据
successful_urls = [] # 存储成功获取的URL
failed_urls = [] # 存储获取失败的URL

total_urls_to_process = len(initial_urls_to_fetch)

if total_urls_to_process > 0:
    with ThreadPoolExecutor(max_workers=16) as executor:
        future_to_url = {executor.submit(fetch_and_parse_url, url): url for url in initial_urls_to_fetch}
        for future in tqdm(as_completed(future_to_url), total=total_urls_to_process, desc="处理URL并解析节点"):
            url = future_to_url[future]
            nodes, success, error_message = future.result()

            stat_entry = {'URL': url, '节点数量': len(nodes), '状态': '成功' if success else '失败', '错误信息': error_message if error_message else ''}
            url_statistics.append(stat_entry)

            if success:
                successful_urls.append(url)
                for node in nodes:
                    temp_merged_nodes_set.add(node) # 添加到集合进行去重
            else:
                failed_urls.append(url)

# 处理那些在 URL_SOURCE 中直接是节点字符串的（非 HTTP/HTTPS URL）
# 因为这些没有经过 requests.get，它们在 initial_urls_to_fetch 中被标记为非有效URL
# 这里需要重新解析它们并加入 temp_merged_nodes_set
print("\n--- 正在处理 URL_SOURCE 中直接包含的节点字符串 ---")
for url_string_from_source in raw_urls_from_remote:
    if not is_valid_url(url_string_from_source):
        direct_nodes = parse_content_to_nodes(url_string_from_source)
        if direct_nodes:
            print(f"从非URL字符串中解析到 {len(direct_nodes)} 个节点：{url_string_from_source[:50]}...")
            for node in direct_nodes:
                temp_merged_nodes_set.add(node)
            # 对于这些直接解析成功的字符串，也记录到统计中
            stat_entry = {'URL': url_string_from_source, '节点数量': len(direct_nodes), '状态': '直接解析成功', '错误信息': ''}
            url_statistics.append(stat_entry)
            successful_urls.append(url_string_from_source) # 认为其解析成功
        else:
            # 如果不是有效URL，且也无法解析出节点，则视为失败
            if url_string_from_source not in failed_urls and url_string_from_source not in successful_urls: # 避免重复记录
                stat_entry = {'URL': url_string_from_source, '节点数量': 0, '状态': '直接解析失败', '错误信息': '非URL且无法解析为节点'}
                url_statistics.append(stat_entry)
                failed_urls.append(url_string_from_source)


# 将阶段一收集到的节点写入临时文件
with open(TEMP_MERGED_FILE, 'w', encoding='utf-8') as temp_file:
    for node in temp_merged_nodes_set:
        temp_file.write(node.strip() + '\n')

# 写入统计数据和URL列表文件
write_statistics_to_csv(url_statistics, STATISTICS_FILE)
write_urls_to_file(successful_urls, SUCCESS_URLS_FILE)
write_urls_to_file(failed_urls, FAILED_URLS_FILE)

print(f"\n阶段一完成。从所有订阅链接中合并到 {len(temp_merged_nodes_set)} 个唯一节点，已保存至 {TEMP_MERGED_FILE}")

# 阶段二：从聚合的节点文件中再次进行去重后输出保存
print("\n--- 阶段二：最终去重并保存节点 ---")
final_unique_nodes = set()
try:
    with open(TEMP_MERGED_FILE, 'r', encoding='utf-8') as temp_file:
        for line in temp_file:
            stripped_line = line.strip()
            if stripped_line:
                final_unique_nodes.add(stripped_line)
except FileNotFoundError:
    print(f"警告：未找到临时文件 {TEMP_MERGED_FILE}，可能阶段一没有成功获取到任何节点。")
except Exception as e:
    logging.error(f"读取临时文件 {TEMP_MERGED_FILE} 失败: {e}")

success_count = 0
with open(OUTPUT_FILE, 'w', encoding='utf-8') as out_file:
    for node in sorted(list(final_unique_nodes)): # 排序后写入，方便查看和比较
        if success_count < MAX_SUCCESS:
            out_file.write(node + '\n')
            success_count += 1
        else:
            break

# 清理临时文件
if os.path.exists(TEMP_MERGED_FILE):
    os.remove(TEMP_MERGED_FILE)
    print(f"已删除临时文件：{TEMP_MERGED_FILE}")

# 最终结果报告
print("\n" + "=" * 50)
print("最终结果：")
print(f"待处理订阅链接总数：{len(initial_urls_to_fetch) + len([u for u in raw_urls_from_remote if not is_valid_url(u)])}") # 包含直接解析的字符串
print(f"成功处理的URL/字符串数量：{len(successful_urls)}")
print(f"失败的URL/字符串数量：{len(failed_urls)}")
print(f"初步聚合的唯一节点数：{len(temp_merged_nodes_set)}")
print(f"最终去重并成功保存的节点数：{success_count}")
if len(temp_merged_nodes_set) > 0:
    print(f"最终有效内容率（相对于初步聚合）：{success_count/len(temp_merged_nodes_set):.1%}")
if success_count < MAX_SUCCESS:
    print("警告：未能达到目标数量，原始列表可能有效URL/节点不足，或部分URL获取失败。")
print(f"结果文件已保存至：{OUTPUT_FILE}")
print(f"统计数据已保存至：{STATISTICS_FILE}")
print(f"成功URL列表已保存至：{SUCCESS_URLS_FILE}")
print(f"失败URL列表已保存至：{FAILED_URLS_FILE}")
print("=" * 50)
