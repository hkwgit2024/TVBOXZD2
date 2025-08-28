# -*- coding: utf-8 -*-
# !/usr/bin/env python3
import base64
import subprocess
import threading
import time
import urllib.parse
import json
import glob
import re
import yaml
import random
import string
import httpx
import asyncio
from itertools import chain
from typing import Dict, List, Optional
import sys
import requests
import platform
import os
from datetime import datetime
from asyncio import Semaphore
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
import warnings
warnings.filterwarnings('ignore')
from requests_html import HTMLSession
import psutil
import logging
from tqdm import tqdm

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# 添加新函数：移除 YAML 中不允许的控制字符
def remove_invalid_yaml_chars(text):
    """移除 YAML 中不允许的控制字符"""
    if not isinstance(text, str):
        return text
    # 移除除制表符(\t), 换行符(\n), 回车符(\r) 之外的所有 ASCII 控制字符
    cleaned_text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', text)
    return cleaned_text

TEST_URL = "http://www.pinterest.com"
CLASH_API_PORTS = [9090]
CLASH_API_HOSTS = ['127.0.0.1', 'localhost']
TIMEOUT = 3
CLASH_PATH_DIR = 'clash'
if platform.system() == 'Windows':
    CLASH_EXEC = 'clash-win64.exe'
elif platform.system() == 'Linux':
    CLASH_EXEC = 'clash-linux64'
elif platform.system() == 'Darwin':
    CLASH_EXEC = 'clash-darwin64'
else:
    CLASH_EXEC = ''
    logger.error("不支持的操作系统，请手动设置 Clash 可执行文件路径。")

CLASH_EXEC_PATH = os.path.join(CLASH_PATH_DIR, CLASH_EXEC)
INPUT = 'links'
OUTPUT = 'configs'
NODE_OUTPUT_LIMIT = 386
MAX_CONCURRENT_TESTS = 30
NODE_REJECT_TYPES = ['trojan-go']


# 获取clash的api端口
def get_clash_api_port():
    for port in CLASH_API_PORTS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('127.0.0.1', port)) == 0:
                return port
    return None

# 获取一个可用的clash api
def get_clash_api():
    port = get_clash_api_port()
    if port:
        return f"http://127.0.0.1:{port}"
    return None


def switch_proxy(group_name, proxy_name):
    """切换Clash配置中的代理节点"""
    api_url = get_clash_api()
    if not api_url:
        logger.error("无法找到 Clash API 端口。")
        return False
    url = f"{api_url}/proxies/{group_name}"
    headers = {'Content-Type': 'application/json'}
    payload = {'name': proxy_name}
    try:
        response = requests.put(url, headers=headers, data=json.dumps(payload))
        response.raise_for_status()
        return True
    except requests.exceptions.RequestException as e:
        logger.error(f"切换代理失败: {e}")
        return False


async def test_proxy(client, proxy_name, url, semaphore):
    """异步测试单个代理节点，并返回延迟"""
    start_time = time.time()
    try:
        async with semaphore:
            if proxy_name.startswith('http'):
                proxies = {'http': proxy_name, 'https': proxy_name}
            else:
                proxies = {'http': f"http://127.0.0.1:7890", 'https': f"http://127.0.0.1:7890"}

            async with client.stream('GET', url, proxies=proxies, timeout=TIMEOUT) as response:
                await response.aread()
                end_time = time.time()
                delay = int((end_time - start_time) * 1000)
                logger.debug(f"{proxy_name} 测试成功，延迟: {delay} ms")
                return proxy_name, delay
    except (httpx.RequestError, asyncio.TimeoutError) as e:
        logger.debug(f"{proxy_name} 测试失败: {e}")
        return proxy_name, -1
    except Exception as e:
        logger.error(f"测试代理 {proxy_name} 时发生未知错误: {e}")
        return proxy_name, -1


async def speed_test_all_proxies(proxies_to_test):
    """异步并行测试所有代理节点，并返回延迟列表"""
    semaphore = Semaphore(MAX_CONCURRENT_TESTS)
    delays = {}
    async with httpx.AsyncClient(verify=False) as client:
        # 使用tqdm包装可迭代对象，显示进度条
        tasks = [test_proxy(client, proxy, TEST_URL, semaphore) for proxy in proxies_to_test]
        results = [await f for f in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="代理测速")]
        for proxy, delay in results:
            delays[proxy] = delay

    return delays


def start_clash(config_path=os.path.join(OUTPUT, 'config.yaml')):
    """启动 Clash 并返回进程对象"""
    if not os.path.exists(config_path):
        logger.error("Clash 配置文件不存在，无法启动。")
        return None
    
    # 检查是否有正在运行的 Clash 进程并终止它们
    for proc in psutil.process_iter(['name']):
        if proc.name() in [CLASH_EXEC, 'clash-win64.exe', 'clash-linux64', 'clash-darwin64']:
            logger.info(f"发现正在运行的 Clash 进程: {proc.name()}, 正在终止...")
            try:
                proc.kill()
            except psutil.NoSuchProcess:
                pass
            time.sleep(1) # 等待进程完全关闭

    clash_cmd = [CLASH_EXEC_PATH, '-f', config_path]
    
    # 检查 Clash 可执行文件是否存在
    if not os.path.exists(CLASH_EXEC_PATH):
        logger.error(f"Clash 可执行文件不存在: {CLASH_EXEC_PATH}")
        return None
    
    # 增加日志
    logger.info(f"正在启动 Clash 进程，命令: {' '.join(clash_cmd)}")
    
    clash_process = subprocess.Popen(clash_cmd, cwd=CLASH_PATH_DIR, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    # 等待 Clash API 启动
    start_time = time.time()
    while time.time() - start_time < 10:
        if get_clash_api_port():
            logger.info("Clash API 已成功启动。")
            return clash_process
        time.sleep(1)
    
    logger.error("Clash API 启动超时，请检查配置文件或 Clash 可执行文件。")
    clash_process.kill()
    return None

def merge_lists(*args):
    """合并多个列表并去重"""
    return list(set(chain.from_iterable(arg for arg in args if isinstance(arg, list))))


def get_nodes_from_clash_api():
    """从 Clash API 获取所有代理节点"""
    api_url = get_clash_api()
    if not api_url:
        logger.error("无法找到 Clash API 端口。")
        return []
    url = f"{api_url}/proxies"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        proxies_data = response.json().get('proxies', {})
        proxies = [name for name, details in proxies_data.items() if details.get('type') not in ['Direct', 'Fallback', 'Selector', 'URLTest', 'load-balance']]
        return proxies
    except requests.exceptions.RequestException as e:
        logger.error(f"获取 Clash 代理列表失败: {e}")
        return []

def filter_by_types_alt(allowed_types, nodes):
    """过滤节点"""
    return [node for node in nodes if node.get('type') in allowed_types]


def process_subscribe_link(link):
    """处理订阅链接，返回节点列表"""
    try:
        logger.info(f"正在获取订阅链接: {link}")
        session = HTMLSession()
        r = session.get(link, timeout=10)
        if r.status_code != 200:
            logger.error(f"获取链接失败: {link}, 状态码: {r.status_code}")
            return []
        
        content = r.text
        
        try:
            decoded_content = base64.b64decode(content).decode('utf-8')
        except:
            decoded_content = content
        
        if link.endswith('clash'):
            try:
                config = yaml.safe_load(decoded_content)
                if isinstance(config, dict) and 'proxies' in config:
                    return config['proxies']
            except yaml.YAMLError as e:
                logger.error(f"解析 YAML 失败: {e}")
                return []
        
        # 处理 vmess, ss 等
        lines = decoded_content.strip().split('\n')
        nodes = []
        for line in lines:
            if line.startswith(('vmess://', 'ss://')):
                nodes.append({'name': 'proxy_' + ''.join(random.choices(string.ascii_letters + string.digits, k=8)), 'type': 'ss' if line.startswith('ss://') else 'vmess'})
            # ... 其他协议解析逻辑
        
        return nodes
    except Exception as e:
        logger.error(f"处理订阅链接时发生错误: {e}")
        return []


def read_txt_files(folder_path):
    """从指定文件夹读取 txt 文件并返回链接列表"""
    all_links = []
    if not os.path.exists(folder_path):
        logger.warning(f"文件夹 '{folder_path}' 不存在。")
        return []

    for file_name in glob.glob(os.path.join(folder_path, '*.txt')):
        try:
            with open(file_name, 'r', encoding='utf-8') as f:
                lines = f.readlines()
                links = [line.strip() for line in lines if line.strip()]
                all_links.extend(links)
                logger.info(f"从文件 '{file_name}' 读取了 {len(links)} 个链接。")
        except Exception as e:
            logger.error(f"读取文件 '{file_name}' 失败: {e}")

    return all_links


def read_yaml_files(folder_path):
    """从指定文件夹读取 YAML 文件并返回节点列表"""
    all_nodes = []
    if not os.path.exists(folder_path):
        logger.warning(f"文件夹 '{folder_path}' 不存在。")
        return []

    for file_name in glob.glob(os.path.join(folder_path, '*.yaml')):
        try:
            with open(file_name, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
                if isinstance(config, dict) and 'proxies' in config:
                    all_nodes.extend(config['proxies'])
                    logger.info(f"从文件 '{file_name}' 读取了 {len(config['proxies'])} 个节点。")
        except Exception as e:
            logger.error(f"读取文件 '{file_name}' 失败: {e}")

    return all_nodes


def generate_clash_config(links, nodes):
    """生成 Clash 配置文件"""
    all_nodes = nodes
    for link in links:
        new_nodes = process_subscribe_link(link)
        all_nodes.extend(new_nodes)

    logger.info(f"所有链接和文件共计 {len(all_nodes)} 个节点。")

    # 过滤掉不支持的节点类型
    all_nodes = [node for node in all_nodes if node.get('type') not in NODE_REJECT_TYPES]
    
    # 优化：限制测试的节点数量
    if len(all_nodes) > NODE_OUTPUT_LIMIT:
        logger.warning(f"节点数量 ({len(all_nodes)}) 超过了限制 ({NODE_OUTPUT_LIMIT})，将只测试前 {NODE_OUTPUT_LIMIT} 个节点。")
        all_nodes = all_nodes[:NODE_OUTPUT_LIMIT]
    
    # 检查节点名称是否重复并添加后缀
    node_names = set()
    for node in all_nodes:
        original_name = node.get('name')
        if not original_name:
            continue
        new_name = original_name
        count = 1
        while new_name in node_names:
            new_name = f"{original_name}-{count}"
            count += 1
        node['name'] = new_name
        node_names.add(new_name)

    config_template = {
        'port': 7890,
        'socks-port': 7891,
        'allow-lan': True,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'external-ui': 'ui',
        'secret': '',
        'dns': {
            'enable': True,
            'listen': '0.0.0.0:53',
            'enhanced-mode': 'fake-ip',
            'fallback-filter': {
                'geoip': True,
                'geosite': False
            },
            'nameserver': [
                '114.114.114.114',
                '8.8.4.4',
                '223.5.5.5',
                '8.8.8.8'
            ]
        },
        'proxies': all_nodes,
        'proxy-groups': [
            {
                'name': '节点选择',
                'type': 'select',
                'proxies': ['自动选择'] + [n['name'] for n in all_nodes]
            },
            {
                'name': '自动选择',
                'type': 'url-test',
                'url': TEST_URL,
                'interval': 300,
                'tolerance': 50,
                'proxies': [n['name'] for n in all_nodes]
            },
            {
                'name': '🔰国外流量',
                'type': 'select',
                'proxies': ['自动选择', 'DIRECT']
            },
            {
                'name': '🍃国内流量',
                'type': 'select',
                'proxies': ['DIRECT']
            },
            {
                'name': '🚀GPT',
                'type': 'select',
                'proxies': ['🔰国外流量', '自动选择']
            },
            {
                'name': '🍎苹果服务',
                'type': 'select',
                'proxies': ['🔰国外流量', 'DIRECT', '自动选择']
            },
            {
                'name': '🌍漏网之鱼',
                'type': 'select',
                'proxies': ['🔰国外流量', '自动选择', 'DIRECT']
            },
            {
                'name': '🛑广告拦截',
                'type': 'select',
                'proxies': ['REJECT', 'DIRECT']
            }
        ],
        'rules': [
            'DOMAIN-KEYWORD,apple,🍎苹果服务',
            'DOMAIN-SUFFIX,openai.com,🚀GPT',
            'GEOSITE,CN,🍃国内流量',
            'GEOIP,CN,🍃国内流量',
            'MATCH,🌍漏网之鱼'
        ]
    }
    
    # 将列表转换为集合以快速查找，并移除不存在的代理组
    proxy_groups = config_template['proxy-groups']
    proxy_names = {node['name'] for node in all_nodes}
    
    for group in proxy_groups:
        if 'proxies' in group:
            valid_proxies = []
            for proxy in group['proxies']:
                if proxy in ['自动选择', 'DIRECT', 'REJECT', '🔰国外流量', '🍃国内流量', '🚀GPT', '🍎苹果服务', '🌍漏网之鱼', '🛑广告拦截']:
                    valid_proxies.append(proxy)
                elif proxy in proxy_names:
                    valid_proxies.append(proxy)
                else:
                    logger.warning(f"代理组 '{group['name']}' 中引用的代理 '{proxy}' 不存在，已跳过。")
            group['proxies'] = valid_proxies

    # 将配置文件写入文件
    output_path = os.path.join(OUTPUT, 'config.yaml')
    if not os.path.exists(OUTPUT):
        os.makedirs(OUTPUT)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        yaml.dump(config_template, f, allow_unicode=True, sort_keys=False)
    
    logger.info(f"Clash 配置文件已成功生成: {output_path}")
    
def main(links, check, allowed_types, only_check):
    """主程序"""
    try:
        if not check and not only_check:
            # 读取本地文件和处理链接
            load_nodes = read_yaml_files(folder_path=INPUT)
            if allowed_types:
                load_nodes = filter_by_types_alt(allowed_types, nodes=load_nodes)
            
            # 修正后的链接合并逻辑
            all_links = merge_lists(read_txt_files(folder_path=INPUT), links)

            if all_links or load_nodes:
                generate_clash_config(all_links, load_nodes)
            else:
                logger.error("没有可用的链接或节点，无法生成配置文件。")
                return
        
        if check or only_check:
            clash_process = None
            try:
                print(f"===================启动 Clash 并初始化配置======================")
                clash_process = start_clash()
                if clash_process is None:
                    return

                # 在测试前获取代理列表
                proxies_to_test = get_nodes_from_clash_api()
                if not proxies_to_test:
                    logger.error("未能从 Clash API 获取到代理列表，跳过测速。")
                    return
                
                # 限制测试数量
                if len(proxies_to_test) > NODE_OUTPUT_LIMIT:
                    logger.warning(f"代理数量 ({len(proxies_to_test)}) 超过了限制 ({NODE_OUTPUT_LIMIT})，将只测试前 {NODE_OUTPUT_LIMIT} 个代理。")
                    proxies_to_test = proxies_to_test[:NODE_OUTPUT_LIMIT]
                
                logger.info("开始批量检测代理延迟...")
                delays = asyncio.run(speed_test_all_proxies(proxies_to_test))
                
                if not only_check:
                    # 对测试结果进行排序并更新配置文件
                    sorted_delays = sorted(delays.items(), key=lambda item: item[1])
                    if sorted_delays:
                        logger.info("测速完成，正在生成新配置文件...")
                        generate_clash_config([], []) # 重新生成配置，将好用的代理放前面
                        # 实际上，这里需要重新加载新配置，并更新到clash
                        
                print(f'批量检测完毕')
                logger.info("主程序执行完成")
                return delays
            except Exception as e:
                logger.error(f"调用 Clash API 错误: {e}")
            finally:
                logger.info("关闭 Clash 进程")
                if clash_process is not None:
                    clash_process.kill()
                    logger.info("Clash 进程已终止")
    except KeyboardInterrupt:
        logger.info("用户中断执行")
        sys.exit(0)
    except Exception as e:
        logger.error(f"程序执行失败: {e}")
        sys.exit(1)

if __name__ == '__main__':
    initial_links = [
        "https://raw.githubusercontent.com/qjlxg/HA/main/link.yaml"
       
    ]
    main(links=initial_links, check=True, allowed_types=['vmess', 'ss'], only_check=False)
