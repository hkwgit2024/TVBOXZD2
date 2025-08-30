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
import zipfile
import gzip
import shutil
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

# TEST_URL = "http://www.gstatic.com/generate_204"
TEST_URL = "http://www.pinterest.com"
CLASH_API_PORTS = [9090]
CLASH_API_HOST = "127.0.0.1"
CLASH_API_SECRET = ""
TIMEOUT = 3
# 存储所有节点的速度测试结果
SPEED_TEST = False
SPEED_TEST_LIMIT = 5  # 只测试前30个节点的下行速度，每个节点测试5秒
results_speed = []
MAX_CONCURRENT_TESTS = 100
LIMIT = 386 # 最多保留LIMIT个节点
CONFIG_FILE = 'clash_config.yaml'
INPUT = "input"  # 从文件中加载代理节点，支持yaml/yml、txt(每条代理链接占一行)
BAN = ["中国", "China", "CN", "电信", "移动", "联通"]
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en;q=0.7",
    "Cache-Control": "max-age=0",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive"
}
global PROXY_NODES
global total_test_nodes_count

def convert_to_clash(proxy_url):
    try:
        if "vmess://" in proxy_url:
            return convert_vmess(proxy_url)
        elif "vless://" in proxy_url:
            return convert_vless(proxy_url)
        elif "ss://" in proxy_url:
            return convert_ss(proxy_url)
        elif "trojan://" in proxy_url:
            return convert_trojan(proxy_url)
        elif "hysteria2://" in proxy_url:
            return convert_hysteria2(proxy_url)
        else:
            return None
    except Exception as e:
        # print(f"无法转换的代理链接: {e}")
        return None

def convert_vmess(proxy_url):
    try:
        base64_part = proxy_url.split("vmess://")[1]
        decoded_json = base64.b64decode(base64_part).decode('utf-8')
        config = json.loads(decoded_json)
        
        clash_config = {
            'name': config.get('ps', ''),
            'type': 'vmess',
            'server': config.get('add', ''),
            'port': int(config.get('port', 443)),
            'uuid': config.get('id', ''),
            'alterId': int(config.get('aid', '0')),
            'cipher': 'auto',
            'tls': config.get('tls', '') == 'tls',
            'network': config.get('net', ''),
            'udp': True
        }
        
        if clash_config['network'] == 'ws':
            ws_path = config.get('path', '/')
            ws_headers = {'Host': config.get('host', '')}
            if config.get('host'):
                clash_config['ws-opts'] = {'path': ws_path, 'headers': ws_headers}
            else:
                clash_config['ws-opts'] = {'path': ws_path}
        
        if config.get('sni'):
            clash_config['sni'] = config['sni']
        
        if config.get('fp'):
            clash_config['client-fingerprint'] = config['fp']
            
        if config.get('tls', '') == 'tls':
            clash_config['tls'] = True
            
        if 'host' in config and config['host']:
            clash_config['servername'] = config['host']
            
        return clash_config

    except Exception as e:
        # print(f"无法转换VMESS代理: {e}")
        return None

def convert_vless(proxy_url):
    try:
        parsed_url = urllib.parse.urlparse(proxy_url)
        
        # 解析用户信息部分，通常是 UUID
        user_info = parsed_url.username
        if user_info:
            uuid = user_info
        else:
            return None # UUID是必须的
        
        # 解析服务器地址和端口
        server = parsed_url.hostname
        port = parsed_url.port
        
        # 解析查询参数
        params = urllib.parse.parse_qs(parsed_url.query)
        
        # 提取插件（Flow、Tls、Encryption）信息
        flow = params.get('flow', [None])[0]
        encryption = params.get('encryption', [None])[0]
        security = params.get('security', [None])[0]
        
        # Clash配置
        clash_config = {
            'name': urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else f'{server}',
            'type': 'vless',
            'server': server,
            'port': port,
            'uuid': uuid,
            'network': params.get('type', ['tcp'])[0],
            'tls': security == 'tls',
            'udp': True
        }
        
        if flow:
            clash_config['flow'] = flow

        if clash_config['network'] == 'ws':
            ws_opts = {}
            if 'path' in params:
                ws_opts['path'] = params['path'][0]
            if 'host' in params:
                ws_opts['headers'] = {'Host': params['host'][0]}
            clash_config['ws-opts'] = ws_opts
            
        if 'fp' in params:
            clash_config['client-fingerprint'] = params['fp'][0]
            
        if 'sni' in params:
            clash_config['servername'] = params['sni'][0]
        elif 'host' in params:
            clash_config['servername'] = params['host'][0]

        return clash_config

    except Exception as e:
        # print(f"无法转换VLESS代理: {e}")
        return None

def convert_ss(proxy_url):
    try:
        # ss://method:password@server:port#tag
        parsed_url = urllib.parse.urlparse(proxy_url)
        
        # Base64编码的用户名和密码
        if parsed_url.username and parsed_url.password:
            decoded_info = base64.b64decode(f"{parsed_url.username}:{parsed_url.password}").decode('utf-8')
            method, password = decoded_info.split(':', 1)
        else: # 未编码，直接解析
            method = parsed_url.username
            password = parsed_url.password
        
        clash_config = {
            'name': urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else parsed_url.hostname,
            'type': 'ss',
            'server': parsed_url.hostname,
            'port': parsed_url.port,
            'cipher': method,
            'password': password,
            'udp': True
        }
        
        return clash_config

    except Exception as e:
        # print(f"无法转换SS代理: {e}")
        return None

def convert_trojan(proxy_url):
    try:
        parsed_url = urllib.parse.urlparse(proxy_url)
        
        clash_config = {
            'name': urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else parsed_url.hostname,
            'type': 'trojan',
            'server': parsed_url.hostname,
            'port': parsed_url.port,
            'password': parsed_url.username,
            'udp': True
        }
        
        params = urllib.parse.parse_qs(parsed_url.query)
        if 'sni' in params:
            clash_config['sni'] = params['sni'][0]
        if 'security' in params and params['security'][0] == 'tls':
            clash_config['tls'] = True
        
        return clash_config
    
    except Exception as e:
        # print(f"无法转换Trojan代理: {e}")
        return None

def convert_hysteria2(proxy_url):
    try:
        parsed_url = urllib.parse.urlparse(proxy_url)
        
        clash_config = {
            'name': urllib.parse.unquote(parsed_url.fragment) if parsed_url.fragment else parsed_url.hostname,
            'type': 'hysteria2',
            'server': parsed_url.hostname,
            'port': parsed_url.port,
            'password': parsed_url.username,
            'udp': True,
            'tls': True,
        }
        
        params = urllib.parse.parse_qs(parsed_url.query)
        
        if 'obfs' in params:
            clash_config['obfs'] = params['obfs'][0]
        if 'obfs-password' in params:
            clash_config['obfs-password'] = params['obfs-password'][0]
        if 'sni' in params:
            clash_config['sni'] = params['sni'][0]
        
        return clash_config
    
    except Exception as e:
        # print(f"无法转换Hysteria2代理: {e}")
        return None

def read_remote_proxy_links(link):
    print(f"当前正在处理link: {link}")
    try:
        with requests.get(link, headers=headers, timeout=10) as r:
            r.raise_for_status()
            content = r.text
            if content.startswith('trojan://') or content.startswith('ss://') or content.startswith('vmess://') or content.startswith('vless://') or content.startswith('hysteria2://'):
                return [link for link in content.splitlines() if link.strip()]
            else:
                decoded_content = base64.b64decode(content).decode('utf-8')
                return [link for link in decoded_content.splitlines() if link.strip()]
    except Exception as e:
        # print(f"无法读取远程代理链接 {link}: {e}")
        return []

def filter_proxies(proxies, limit=LIMIT):
    filtered_proxies = []
    seen = set()
    for p in proxies:
        # 过滤掉缺失关键字段的节点
        if not all(key in p for key in ['server', 'port', 'name', 'type']):
            continue
        # 根据名字过滤
        if any(b.lower() in p['name'].lower() for b in BAN):
            continue
        
        # 使用一个可哈希的元组作为节点的唯一标识
        identifier = (p['server'], p['port'], p['type'])
        if identifier not in seen:
            filtered_proxies.append(p)
            seen.add(identifier)
            if len(filtered_proxies) >= limit:
                break
    return filtered_proxies

def merge_lists(*args):
    return list(chain(*args))

def read_yaml_files(folder_path):
    nodes = []
    yaml_files = glob.glob(os.path.join(folder_path, '*.yaml'))
    yaml_files.extend(glob.glob(os.path.join(folder_path, '*.yml')))
    for file in yaml_files:
        try:
            with open(file, 'r', encoding='utf-8') as f:
                content = yaml.safe_load(f)
                if content and 'proxies' in content:
                    nodes.extend(content['proxies'])
        except Exception as e:
            print(f"Error reading YAML file {file}: {e}")
    return nodes
    
def read_txt_files(folder_path):
    links = []
    txt_files = glob.glob(os.path.join(folder_path, '*.txt'))
    for file in txt_files:
        try:
            with open(file, 'r', encoding='utf-8') as f:
                links.extend(f.read().splitlines())
        except Exception as e:
            print(f"Error reading TXT file {file}: {e}")
    return links
    
def filter_by_types_alt(allowed_types, nodes=None):
    if not nodes:
        nodes = PROXY_NODES
    return [node for node in nodes if node.get('type') in allowed_types]
    
def generate_clash_config(links: List[str], load_nodes: List[Dict]):
    """
    根据给定的链接和节点列表生成Clash配置文件
    """
    
    # 转换远程订阅链接
    all_proxies = []
    for link in links:
        proxy_links = read_remote_proxy_links(link)
        all_proxies.extend([convert_to_clash(p) for p in proxy_links])
        
    # 合并本地加载的节点
    all_proxies.extend(load_nodes)
    
    # 过滤掉转换失败的节点(None)和重复、无效的节点
    proxies = filter_proxies([p for p in all_proxies if p is not None])
    
    # ==========================
    # 修复：自动移除不兼容的 alterId 键
    # ==========================
    cleaned_proxies = []
    for p in proxies:
        # 定义不需要 alterId 的代理类型
        incompatible_types = ["ss", "trojan", "hysteria2"]
        if p.get("type") in incompatible_types and "alterId" in p:
            print(f"警告：正在从代理 '{p.get('name')}' 中移除不兼容的 'alterId' 键。")
            del p["alterId"]
        cleaned_proxies.append(p)
    proxies = cleaned_proxies
    # ==========================
    
    if not proxies:
        print("警告：没有可用的代理节点。")
        return
        
    global PROXY_NODES
    PROXY_NODES = proxies
    
    proxy_names = [p['name'] for p in proxies]
    
    proxy_groups = [
        {'name': '手动选择', 'type': 'select', 'proxies': proxy_names},
        {'name': '国内直连', 'type': 'select', 'proxies': ['DIRECT', '手动选择']},
        {'name': '国外直连', 'type': 'select', 'proxies': ['DIRECT', '手动选择']},
        {'name': '广告拦截', 'type': 'select', 'proxies': ['REJECT', '手动选择']},
        {'name': '节点选择', 'type': 'select', 'proxies': proxy_names},
    ]

    config_data = {
        'port': 7890,
        'allow-lan': True,
        'mode': 'rule',
        'log-level': 'info',
        'external-controller': '127.0.0.1:9090',
        'proxies': proxies,
        'proxy-groups': proxy_groups,
        'rules': [
            'GEOIP,CN,国内直连',
            'MATCH,节点选择'
        ],
        'dns': {
            'enable': True,
            'enhanced-mode': 'fake-ip',
            'listen': '0.0.0.0:53',
            'fake-ip-range': '198.18.0.1/16',
            'default-nameserver': [
                '223.5.5.5',
                '119.29.29.29'
            ],
            'nameserver': [
                'https://doh.pub/dns-query',
                'https://dns.alidns.com/dns-query',
                'https://doh.dns.sb/dns-query'
            ],
            'fallback': [
                'https://doh.dns.sb/dns-query',
                'https://dns.cloudflare.com/dns-query',
                'tls://8.8.4.4:853'
            ],
            'fallback-filter': {
                'geoip': True,
                'ipcidr': ['240.0.0.0/4', '0.0.0.0/32']
            }
        },
        'geodata-mode': True,
        'geox-url': {
            'geoip': 'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/geoip.dat',
            'mmdb': 'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/GeoLite2-Country.mmdb'
        }
    }
    
    try:
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            yaml.safe_dump(config_data, f, allow_unicode=True)
        print(f"已经生成Clash配置文件{CONFIG_FILE}")
        
        # 额外生成一个json格式的文件，以防万一
        with open(f'{CONFIG_FILE}.json', 'w', encoding='utf-8') as f:
            json.dump(config_data, f, ensure_ascii=False, indent=2)
        print(f"已经生成Clash配置文件{CONFIG_FILE}.json")
        
    except Exception as e:
        print(f"生成配置文件失败: {e}")

def get_clash_bin_name():
    system = platform.system()
    if system == "Linux":
        return "./clash-linux"
    elif system == "Darwin":
        return "./clash-darwin"
    elif system == "Windows":
        return "clash-windows.exe"
    else:
        raise OSError("Unsupported operating system")

def download_clash_core():
    clash_bin = get_clash_bin_name()
    if os.path.exists(clash_bin):
        print("Clash核心文件已存在，跳过下载。")
        return

    print("Clash核心文件不存在，正在下载...")
    
    base_url = "https://raw.githubusercontent.com/Clash-Verge-Rev/Clash-Verge-Rev/main/release/premium/"
    
    system = platform.system()
    if system == "Linux":
        url = base_url + "clash-linux"
    elif system == "Darwin":
        url = base_url + "clash-darwin"
    elif system == "Windows":
        url = base_url + "clash-windows.exe"
    else:
        print("不支持的操作系统")
        return
        
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()
        with open(clash_bin, 'wb') as f:
            for chunk in response.iter_content(chunk_size=8192):
                f.write(chunk)
        os.chmod(clash_bin, 0o755)
        print("Clash核心下载成功。")
    except Exception as e:
        print(f"下载Clash核心失败: {e}")
        
def start_clash():
    clash_bin = get_clash_bin_name()
    clash_process = None
    try:
        # 先下载核心文件
        download_clash_core()
        
        clash_process = subprocess.Popen([clash_bin, '-f', f'{CONFIG_FILE}.json'],
                                        stdout=subprocess.PIPE,
                                        stderr=subprocess.STDOUT,
                                        text=True,
                                        encoding='utf-8',
                                        bufsize=1)
        
        # 检查Clash是否成功启动
        start_time = time.time()
        while time.time() - start_time < 15:
            line = clash_process.stdout.readline()
            if not line:
                break
            print(f"Clash stdout: {line.strip()}")
            if "Start initial configuration in progress" in line:
                print("Clash API已成功启动。")
                return clash_process
        
        print("Clash API 未能在 15 秒内启动，可能存在问题。")
        
        # 打印剩余的输出以帮助调试
        while True:
            line = clash_process.stdout.readline()
            if not line:
                break
            print(f"Clash stdout: {line.strip()}")
            
        return clash_process

    except FileNotFoundError:
        print(f"错误: 找不到Clash可执行文件 '{clash_bin}'。请确保文件存在且具有执行权限。")
        if clash_process:
            clash_process.kill()
        sys.exit(1)
    except Exception as e:
        print(f"启动Clash失败: {e}")
        if clash_process:
            clash_process.kill()
        sys.exit(1)

def stop_clash(process):
    if process:
        print("正在关闭Clash进程...")
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            print("Clash进程被强制终止。")
        print("Clash进程已关闭。")

async def get_clash_proxies():
    """从Clash API获取代理列表"""
    url = f"http://{CLASH_API_HOST}:{CLASH_API_PORTS[0]}/proxies"
    async with httpx.AsyncClient(headers={'Authorization': f'Bearer {CLASH_API_SECRET}'}) as client:
        response = await client.get(url, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()['proxies']

async def switch_proxy(proxy_name):
    """切换Clash API中的代理"""
    url = f"http://{CLASH_API_HOST}:{CLASH_API_PORTS[0]}/group/节点选择"
    data = {'name': proxy_name}
    async with httpx.AsyncClient(headers={'Authorization': f'Bearer {CLASH_API_SECRET}'}) as client:
        response = await client.put(url, json=data, timeout=TIMEOUT)
        response.raise_for_status()

async def get_proxy_delay(proxy_name):
    """测试单个代理的延迟"""
    url = f"http://{CLASH_API_HOST}:{CLASH_API_PORTS[0]}/proxies/{urllib.parse.quote(proxy_name)}/delay?url={TEST_URL}&timeout={TIMEOUT*1000}"
    async with httpx.AsyncClient(headers={'Authorization': f'Bearer {CLASH_API_SECRET}'}) as client:
        response = await client.get(url, timeout=TIMEOUT)
        response.raise_for_status()
        return response.json()['delay']

async def test_proxy(proxy_name, semaphore):
    """测试单个代理的延迟，使用信号量控制并发"""
    async with semaphore:
        try:
            delay = await get_proxy_delay(proxy_name)
            return proxy_name, delay
        except httpx.HTTPError:
            return proxy_name, -1

async def test_all_proxies():
    """并行测试所有代理的延迟并排序"""
    semaphore = asyncio.Semaphore(MAX_CONCURRENT_TESTS)
    
    clash_proxies = await get_clash_proxies()
    proxy_names = clash_proxies['节点选择']['all']
    
    tasks = [test_proxy(name, semaphore) for name in proxy_names]
    results = await asyncio.gather(*tasks)
    
    # 过滤掉测试失败的节点并按延迟排序
    sorted_proxies = sorted([
        (name, delay) for name, delay in results if delay != -1
    ], key=lambda x: x[1])
    
    return sorted_proxies

async def proxy_clean():
    """批量测试并清理代理节点"""
    global PROXY_NODES
    
    print("开始批量测试代理节点...")
    try:
        sorted_proxies = await test_all_proxies()
        
        # 提取前 LIMIT 个有效的代理名
        valid_proxy_names = [name for name, _ in sorted_proxies[:LIMIT]]
        
        # 将原始的 PROXY_NODES 列表按有效代理名的顺序重新排序
        sorted_nodes = sorted(PROXY_NODES, key=lambda node: valid_proxy_names.index(node['name']) if node['name'] in valid_proxy_names else float('inf'))
        
        # 更新 PROXY_NODES 列表，只保留有效的且在 LIMIT 内的节点
        new_proxies = [node for node in sorted_nodes if node['name'] in valid_proxy_names]

        # 如果节点数量超过 LIMIT，则截断
        if len(new_proxies) > LIMIT:
            new_proxies = new_proxies[:LIMIT]

        # 检查是否需要更新配置文件
        if len(new_proxies) < len(PROXY_NODES):
            PROXY_NODES = new_proxies
            print(f"已过滤掉 {len(PROXY_NODES) - len(new_proxies)} 个无效节点。")
            
            # 重新生成配置文件
            # generate_clash_config([], new_proxies)
        
    except httpx.ConnectError:
        print(f"无法连接到Clash API: http://{CLASH_API_HOST}:{CLASH_API_PORTS[0]}")
    except Exception as e:
        print(f"批量测试失败: {e}")

def work(links, check=False, allowed_types=[], only_check=False):
    try:
        if not only_check:
            load_nodes = read_yaml_files(folder_path=INPUT)
            if allowed_types:
                load_nodes = filter_by_types_alt(allowed_types, nodes=load_nodes)
            links = merge_lists(read_txt_files(folder_path=INPUT), links)
            if links or load_nodes:
                generate_clash_config(links, load_nodes)

        if check or only_check:
            clash_process = None
            try:
                # 启动clash
                print(f"===================启动clash并初始化配置======================")
                clash_process = start_clash()
                # 切换节点到'节点选择-DIRECT'
                switch_proxy('DIRECT')
                asyncio.run(proxy_clean())
                print(f'批量检测完毕')
            except Exception as e:
                print("Error calling Clash API:", e)
            finally:
                print(f'关闭Clash API')
                if clash_process is not None:
                    clash_process.kill()

    except KeyboardInterrupt:
        print("\n用户中断执行")
        sys.exit(0)
    except Exception as e:
        print(f"程序执行失败: {e}")
        sys.exit(1)

if __name__ == '__main__':
    links = [
        "https://raw.githubusercontent.com/qjlxg/VT/refs/heads/main/link.yaml",
        "https://raw.githubusercontent.com/Fidela/v2ray/main/Sub/vless",
        "https://raw.githubusercontent.com/v2ray/v2ray-subscribe/master/link.txt",
        "https://raw.githubusercontent.com/v2ray/v2ray-subscribe/master/vless.txt",
        "https://raw.githubusercontent.com/v2ray/v2ray-subscribe/master/vmess.txt",
        "https://raw.githubusercontent.com/v2ray/v2ray-subscribe/master/ss.txt",
        "https://raw.githubusercontent.com/v2ray/v2ray-subscribe/master/trojan.txt",
        "https://raw.githubusercontent.com/Pawl001/v2ray/main/vless.txt",
        "https://raw.githubusercontent.com/pawl001/v2ray/main/vless.txt",
        "https://raw.githubusercontent.com/Pawl001/v2ray/main/vmess.txt",
        "https://raw.githubusercontent.com/Pawl001/v2ray/main/ss.txt",
        "https://raw.githubusercontent.com/Pawl001/v2ray/main/trojan.txt",
        "https://raw.githubusercontent.com/sveatlo/v2ray-configs/main/vless.txt",
        "https://raw.githubusercontent.com/sveatlo/v2ray-configs/main/vmess.txt",
        "https://raw.githubusercontent.com/sveatlo/v2ray-configs/main/ss.txt",
        "https://raw.githubusercontent.com/sveatlo/v2ray-configs/main/trojan.txt",
        "https://raw.githubusercontent.com/sveatlo/v2ray-configs/main/ssr.txt",
        "https://raw.githubusercontent.com/tbbatbb/Proxy/main/vless",
        "https://raw.githubusercontent.com/tbbatbb/Proxy/main/vmess",
        "https://raw.githubusercontent.com/tbbatbb/Proxy/main/ss",
        "https://raw.githubusercontent.com/tbbatbb/Proxy/main/trojan",
        "https://raw.githubusercontent.com/tbbatbb/Proxy/main/hysteria2",
        "https://raw.githubusercontent.com/yebekhe/V2ray-Configs/main/sub/vless",
        "https://raw.githubusercontent.com/yebekhe/V2ray-Configs/main/sub/vmess",
        "https://raw.githubusercontent.com/yebekhe/V2ray-Configs/main/sub/trojan",
        "https://raw.githubusercontent.com/yebekhe/V2ray-Configs/main/sub/ss",
        "https://raw.githubusercontent.com/yebekhe/V2ray-Configs/main/sub/hysteria2",
        "https://raw.githubusercontent.com/v2fly/v2ray-core/master/release/v2ray-configs/vless.txt",
        "https://raw.githubusercontent.com/v2fly/v2ray-core/master/release/v2ray-configs/vmess.txt",
        "https://raw.githubusercontent.com/v2fly/v2ray-core/master/release/v2ray-configs/ss.txt",
        "https://raw.githubusercontent.com/v2fly/v2ray-core/master/release/v2ray-configs/trojan.txt",
        "https://raw.githubusercontent.com/v2fly/v2ray-core/master/release/v2ray-configs/hysteria2.txt",
        "https://raw.githubusercontent.com/Elias-Black/v2ray-configs/main/vless.txt",
        "https://raw.githubusercontent.com/Elias-Black/v2ray-configs/main/vmess.txt",
        "https://raw.githubusercontent.com/Elias-Black/v2ray-configs/main/trojan.txt",
        "https://raw.githubusercontent.com/Elias-Black/v2ray-configs/main/ss.txt",
        "https://raw.githubusercontent.com/Elias-Black/v2ray-configs/main/hysteria2.txt",
        "https://raw.githubusercontent.com/xray-project/xray-core/main/release/xray-configs/vless.txt",
        "https://raw.githubusercontent.com/xray-project/xray-core/main/release/xray-configs/vmess.txt",
        "https://raw.githubusercontent.com/xray-project/xray-core/main/release/xray-configs/trojan.txt",
        "https://raw.githubusercontent.com/xray-project/xray-core/main/release/xray-configs/ss.txt",
        "https://raw.githubusercontent.com/xray-project/xray-core/main/release/xray-configs/hysteria2.txt",
        "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Ech.json",
    ]
    
    # 每次启动时删除旧文件
    if os.path.exists(f'{CONFIG_FILE}.json'):
        os.remove(f'{CONFIG_FILE}.json')
    if os.path.exists(f'{CONFIG_FILE}'):
        os.remove(f'{CONFIG_FILE}')
        
    print(f"当前时间: {datetime.now()}")
    print("---")
    work(links)
