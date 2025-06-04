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
import csv

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

# 命令行参数解析
parser = argparse.ArgumentParser(description="URL内容获取脚本，支持多个URL来源和节点解析")
parser.add_argument('--max_success', type=int, default=99999, help="目标成功数量")
parser.add_argument('--timeout', type=60, default=60, help="请求超时时间（秒）")
parser.add_argument('--output', type=str, default='data/all_clash.yaml', help="输出文件路径") # 更改默认输出文件类型为 .yaml
args = parser.parse_args()

# 全局变量，从命令行参数或默认值获取
MAX_SUCCESS = args.max_success
TIMEOUT = args.timeout
OUTPUT_FILE = args.output # 现在将是 .yaml 文件
TEMP_MERGED_NODES_RAW_FILE = 'temp_merged_nodes_raw.txt' # 临时存储原始（去重后）节点字符串
STATISTICS_FILE = 'data/url_statistics.csv'
SUCCESS_URLS_FILE = 'data/successful_urls.txt'
FAILED_URLS_FILE = 'data/failed_urls.txt'

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
    返回的节点格式保持原始字符串或字典形式，用于后续统一处理。
    """
    if not content:
        return []

    found_nodes = [] # 使用列表，因为这里可能包含字典，方便后续处理
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
            # 这是 Clash 配置的 proxies 部分
            for proxy_entry in parsed_data['proxies']:
                if isinstance(proxy_entry, dict):
                    found_nodes.append(proxy_entry) # 直接添加字典
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
                    found_nodes.append(proxy_entry.strip())
            logging.info("内容成功解析为 Clash YAML。")
        elif isinstance(parsed_data, list):
            # 有些订阅可能直接返回一个节点列表（YAML格式）
            for item in parsed_data:
                if isinstance(item, str):
                    found_nodes.append(item.strip())
                elif isinstance(item, dict): # 兼容直接返回字典列表
                    found_nodes.append(item)
            logging.info("内容成功解析为 YAML 列表。")
    except yaml.YAMLError:
        pass
    except Exception as e:
        logging.error(f"YAML 解析失败: {e}")
        pass

    # 3. 通过正则表达式提取节点（处理明文、非标准格式等）
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
        found_nodes.append(match.strip())
    
    if content != processed_content:
        matches_decoded = node_pattern.findall(processed_content)
        for match in matches_decoded:
            found_nodes.append(match.strip())

    return found_nodes

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

def deduplicate_and_format_nodes(raw_nodes_list):
    """
    对混合格式的节点进行去重，并转换为统一的Clash YAML代理字典或节点链接。
    返回一个列表，其中包含唯一的代理字典或节点链接字符串。
    """
    unique_nodes_processed = set() # 用于存储唯一节点的字符串表示形式（用于去重）
    final_nodes_list = [] # 存储最终的代理字典或节点链接

    for node in raw_nodes_list:
        if isinstance(node, dict):
            # 将字典转换为JSON字符串用于去重，确保键排序和非ASCII字符
            node_identifier = json.dumps(node, sort_keys=True, ensure_ascii=False)
            if node_identifier not in unique_nodes_processed:
                unique_nodes_processed.add(node_identifier)
                final_nodes_list.append(node) # 存储原始字典
        elif isinstance(node, str):
            # 对于字符串节点，直接使用字符串进行去重
            if node not in unique_nodes_processed:
                unique_nodes_processed.add(node)
                final_nodes_list.append(node) # 存储原始字符串
    return final_nodes_list


# --- 主程序流程 ---

# 从环境变量中读取 URL_SOURCE
URL_SOURCE = os.environ.get("URL_SOURCE")
print(f"调试信息 - 读取到的 URL_SOURCE 值: {URL_SOURCE}")

if not URL_SOURCE:
    print("错误：环境变量 'URL_SOURCE' 未设置。无法获取订阅链接。")
    exit(1)

# 确保输出目录存在
os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
os.makedirs(os.path.dirname(STATISTICS_FILE), exist_ok=True)

# 获取原始的URL列表（包含可能不是HTTP/HTTPS的条目）
raw_urls_from_source = get_url_list_from_remote(URL_SOURCE)

# 用于存储需要进行 HTTP 请求的订阅 URL
urls_to_fetch = set()

# 存储所有 URL 的统计信息，包括成功和失败的 HTTP 请求以及直接解析的结果
url_statistics = []
# 存储成功获取节点或直接解析成功的原始 URL/字符串
successful_urls = []
# 存储获取失败或直接解析失败的原始 URL/字符串
failed_urls = []

# 用于阶段一合并所有解析到的原始节点（可以是字符串或字典）
all_parsed_nodes_raw = []

# 预处理 raw_urls_from_source，分离出真正需要请求的URL和直接解析的节点字符串
print("\n--- 预处理原始URL/字符串列表 ---")
for entry in raw_urls_from_source:
    if is_valid_url(entry):
        urls_to_fetch.add(entry)
    else:
        # 如果不是有效的HTTP/HTTPS URL，尝试将其作为内容直接解析为节点
        print(f"发现非HTTP/HTTPS条目，尝试直接解析: {entry[:80]}...")
        parsed_nodes = parse_content_to_nodes(entry)
        if parsed_nodes:
            all_parsed_nodes_raw.extend(parsed_nodes) # 将直接解析的节点加入总列表
            stat_entry = {'URL': entry, '节点数量': len(parsed_nodes), '状态': '直接解析成功', '错误信息': ''}
            url_statistics.append(stat_entry)
            successful_urls.append(entry)
        else:
            stat_entry = {'URL': entry, '节点数量': 0, '状态': '直接解析失败', '错误信息': '非URL且无法解析为节点'}
            url_statistics.append(stat_entry)
            failed_urls.append(entry)

# 阶段一：并行获取并解析所有 HTTP/HTTPS 订阅链接
print("\n--- 阶段一：获取并合并所有订阅链接中的节点 ---")
total_urls_to_process_via_http = len(urls_to_fetch)

if total_urls_to_process_via_http > 0:
    with ThreadPoolExecutor(max_workers=16) as executor:
        future_to_url = {executor.submit(fetch_and_parse_url, url): url for url in urls_to_fetch}
        for future in tqdm(as_completed(future_to_url), total=total_urls_to_process_via_http, desc="通过HTTP/HTTPS请求并解析节点"):
            url = future_to_url[future]
            nodes, success, error_message = future.result()

            stat_entry = {'URL': url, '节点数量': len(nodes), '状态': '成功' if success else '失败', '错误信息': error_message if error_message else ''}
            url_statistics.append(stat_entry)

            if success:
                successful_urls.append(url)
                all_parsed_nodes_raw.extend(nodes) # 将 HTTP 获取的节点加入总列表
            else:
                failed_urls.append(url)

# 对所有收集到的原始节点进行去重和格式化
final_unique_clash_proxies = deduplicate_and_format_nodes(all_parsed_nodes_raw)

# 将去重后的原始节点数据写入临时文件（用于二次去重前的保存）
# 这里的目的是保存去重后的原始格式，方便后续处理或调试
with open(TEMP_MERGED_NODES_RAW_FILE, 'w', encoding='utf-8') as temp_file:
    for node in final_unique_clash_proxies:
        if isinstance(node, dict):
            # 将字典写入为YAML格式的单个代理条目
            yaml.dump([node], temp_file, allow_unicode=True, default_flow_style=False, sort_keys=False)
        else:
            temp_file.write(node.strip() + '\n')

print(f"\n阶段一完成。合并到 {len(final_unique_clash_proxies)} 个唯一原始节点，已保存至 {TEMP_MERGED_NODES_RAW_FILE}")


# 写入统计数据和URL列表文件
write_statistics_to_csv(url_statistics, STATISTICS_FILE)
write_urls_to_file(successful_urls, SUCCESS_URLS_FILE)
write_urls_to_file(failed_urls, FAILED_URLS_FILE)


# 阶段二：将去重并格式化后的节点输出为 Clash YAML 配置
print("\n--- 阶段二：输出最终 Clash YAML 配置 ---")

# 确保输出文件是 .yaml 格式
if not OUTPUT_FILE.endswith(('.yaml', '.yml')):
    OUTPUT_FILE = os.path.splitext(OUTPUT_FILE)[0] + '.yaml'

# 构建最终的 Clash 配置字典
clash_config = {
    'proxies': final_unique_clash_proxies[:MAX_SUCCESS], # 取最多 MAX_SUCCESS 个节点
    'proxy-groups': [
        {
            'name': '🚀 节点选择',
            'type': 'select',
            'proxies': ['DIRECT'] + [p['name'] if isinstance(p, dict) else p.split('#')[-1] for p in final_unique_clash_proxies[:MAX_SUCCESS]]
            # 这里的代理名称需要统一处理，如果节点是URL，需要提取其名称部分
            # 为了简化，如果节点是URL，暂用其完整URL作为名称，客户端会处理
            # 实际生产中，会更复杂地解析URL并提取名称
        }
    ],
    'rules': [
        'MATCH,🚀 节点选择'
    ]
}

# 动态生成 proxy-groups 中的代理名称
proxy_names_in_group = []
for node in final_unique_clash_proxies[:MAX_SUCCESS]:
    if isinstance(node, dict):
        if 'name' in node:
            proxy_names_in_group.append(node['name'])
    elif isinstance(node, str):
        # 尝试从URL中提取名称，如果失败则使用整个URL
        match = re.search(r'#(.*)$', node)
        if match:
            proxy_names_in_group.append(match.group(1))
        else:
            proxy_names_in_group.append(node) # 没有名称，直接使用URL


# 重新构建 proxy-groups
clash_config['proxy-groups'] = [
    {
        'name': '🚀 节点选择',
        'type': 'select',
        'proxies': ['DIRECT'] + proxy_names_in_group
    }
]


success_count = len(final_unique_clash_proxies[:MAX_SUCCESS])

# 将 Clash 配置写入 YAML 文件
try:
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as out_file:
        yaml.dump(clash_config, out_file, allow_unicode=True, default_flow_style=False, sort_keys=False)
    print(f"最终 Clash YAML 配置已保存至：{OUTPUT_FILE}")
except Exception as e:
    logging.error(f"写入最终 Clash YAML 文件失败: {e}")
    print(f"错误：写入最终 Clash YAML 文件失败: {e}")


# 清理临时文件
if os.path.exists(TEMP_MERGED_NODES_RAW_FILE):
    os.remove(TEMP_MERGED_NODES_RAW_FILE)
    print(f"已删除临时文件：{TEMP_MERGED_NODES_RAW_FILE}")

# 最终结果报告
print("\n" + "=" * 50)
print("最终结果：")
print(f"原始来源总条目数：{len(raw_urls_from_source)}")
print(f"其中需要HTTP/HTTPS请求的订阅链接数：{len(urls_to_fetch)}")
print(f"其中直接解析的非URL字符串数：{len(raw_urls_from_source) - len(urls_to_fetch)}")
print(f"成功处理的URL/字符串总数：{len(successful_urls)}")
print(f"失败的URL/字符串总数：{len(failed_urls)}")
print(f"初步聚合的唯一原始节点数（去重前）：{len(all_parsed_nodes_raw)}")
print(f"去重并格式化后的唯一节点数：{len(final_unique_clash_proxies)}")
print(f"最终输出到Clash YAML文件的节点数：{success_count}")
if len(final_unique_clash_proxies) > 0:
    print(f"最终有效内容率（相对于去重后原始节点）：{success_count/len(final_unique_clash_proxies):.1%}")
if success_count < MAX_SUCCESS:
    print("警告：未能达到目标数量，原始列表可能有效URL/节点不足，或部分URL获取失败。")
print(f"结果文件已保存至：{OUTPUT_FILE}")
print(f"统计数据已保存至：{STATISTICS_FILE}")
print(f"成功URL列表已保存至：{SUCCESS_URLS_FILE}")
print(f"失败URL列表已保存至：{FAILED_URLS_FILE}")
print("=" * 50)
