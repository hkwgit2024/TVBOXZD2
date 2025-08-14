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
ssl._create_default_https_context = ssl._unverified_context
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
SPEED_TEST_LIMIT = 5 # 只测试前30个节点的下行速度，每个节点测试5秒
results_speed = []
MAX_CONCURRENT_TESTS = 100
LIMIT = 1086 # 最多保留LIMIT个节点
CONFIG_FILE = 'clash_config.yaml'
INPUT = os.getenv("INPUT", "input") # 从文件中加载代理节点，支持yaml/yml、txt(每条代理链接占一行)
BAN = ["中国", "China", "CN", "电信", "移动", "联通"]
headers = {
    'Accept-Charset': 'utf-8',
    'Accept': 'text/html,application/x-yaml,*/*',
    'User-Agent': 'Clash Verge/1.7.7'
}

# Clash 配置文件的基础结构
clash_config_template = {
    "port": 7890,
    "socks-port": 7891,
    "redir-port": 7892,
    "allow-lan": True,
    "mode": "rule",
    "log-level": "info",
    "external-controller": "127.0.0.1:9090",
    "geodata-mode": True,
    'geox-url': {'geoip': 'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/geoip.dat', 'mmdb': 'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/GeoLite2-Country.mmdb'},
    "dns": {
        "enable": True,
        "ipv6": False,
        "default-nameserver": [
            "223.5.5.5",
            "119.29.29.29"
        ],
        "enhanced-mode": "fake-ip",
        "fake-ip-range": "198.18.0.1/16",
        "use-hosts": True,
        "nameserver": [
            "https://doh.pub/dns-query",
            "https://dns.alidns.com/dns-query"
        ],
        "fallback": [
            "https://doh.dns.sb/dns-query",
            "https://dns.cloudflare.com/dns-query",
            "https://dns.twnic.tw/dns-query",
            "tls://8.8.4.4:853"
        ],
        "fallback-filter": {
            "geoip": True,
            "ipcidr": [
                "240.0.0.0/4",
                "0.0.0.0/32"
            ]
        }
    },
    "proxies": [],
    "proxy-groups": [
        {
            "name": "节点选择",
            "type": "select",
            "proxies": [
                "自动选择",
                "故障转移",
                "DIRECT",
                "手动选择"
            ]
        },
        {
            "name": "自动选择",
            "type": "url-test",
            "exclude-filter": "(?i)中国|China|CN|电信|移动|联通",
            "proxies": [],
            # "url": "http://www.gstatic.com/generate_204",
            "url": "http://www.pinterest.com",
            "interval": 300,
            "tolerance": 50
        },
        {
            "name": "故障转移",
            "type": "fallback",
            "exclude-filter": "(?i)中国|China|CN|电信|移动|联通",
            "proxies": [],
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300
        },
        {
            "name": "手动选择",
            "type": "select",
            "proxies": []
        },
    ],
    "rules": [
        # 以下规则已根据您的要求精简，仅保留部分示例
        "DOMAIN,app.adjust.com,DIRECT",
        "DOMAIN,bdtj.tagtic.cn,DIRECT",
        "DOMAIN,log.mmstat.com,DIRECT",
        "DOMAIN,sycm.mmstat.com,DIRECT",
        "DOMAIN-SUFFIX,blog.google,DIRECT",
        "DOMAIN-SUFFIX,googletraveladservices.com,DIRECT",
        "DOMAIN,dl.google.com,DIRECT",
        "DOMAIN,dl.l.google.com,DIRECT",
        "DOMAIN,fonts.googleapis.com,DIRECT",
        "DOMAIN-SUFFIX,youtube.com,节点选择",
        "DOMAIN-SUFFIX,googlevideo.com,节点选择",
        "PROCESS-NAME,com.google.android.youtube,节点选择",
        "PROCESS-NAME,com.netflix.mediaclient,节点选择",
        "DOMAIN-SUFFIX,netflix.com,节点选择",
        "DOMAIN-SUFFIX,wikipedia.org,节点选择",
        "DOMAIN-SUFFIX,google.com,节点选择",
        "DOMAIN-SUFFIX,twitter.com,节点选择",
        "DOMAIN-SUFFIX,facebook.com,节点选择",
        "DOMAIN-SUFFIX,github.com,节点选择",
        "GEOSITE,tld-cn,DIRECT",
        "GEOSITE,CN,DIRECT",
        "GEOIP,LAN,DIRECT",
        "GEOIP,CN,DIRECT",
        "MATCH,节点选择"
    ]
}

# --- 修改后的代理加载函数 ---
def load_proxy_nodes(input_source):
    """
    根据输入源（本地文件路径或URL）加载代理节点。
    """
    proxies_content = ""
    # 检查输入源是否为 URL
    if input_source.startswith("http://") or input_source.startswith("https://"):
        print(f"从 URL 下载代理节点文件: {input_source}")
        try:
            # 禁用SSL验证
            response = requests.get(input_source, verify=False, headers=headers, timeout=TIMEOUT)
            response.raise_for_status() # 如果请求失败，会抛出异常
            proxies_content = response.text
        except requests.exceptions.RequestException as e:
            print(f"下载文件失败: {e}")
            return None
    else:
        print(f"从本地文件加载代理节点: {input_source}")
        try:
            with open(input_source, 'r', encoding='utf-8') as f:
                proxies_content = f.read()
        except FileNotFoundError:
            print(f"本地文件 '{input_source}' 未找到.")
            return None

    if not proxies_content:
        return None

    # 解析文件内容
    try:
        data = yaml.safe_load(proxies_content)
        if isinstance(data, dict) and "proxies" in data:
            return data.get("proxies", [])
        # 如果是简单的文本文件，每行一个链接
        elif isinstance(proxies_content, str):
            return [line.strip() for line in proxies_content.splitlines() if line.strip()]
        else:
            print("文件内容格式不支持。")
            return None
    except yaml.YAMLError as e:
        print(f"解析YAML文件失败: {e}")
        return None
        
def parse_proxy_line(proxy_line: str) -> Optional[Dict]:
    """
    解析代理链接，支持vmess、ss、trojan、hysteria2等协议。
    返回一个字典，包含Clash代理配置的详细信息。
    """
    if proxy_line.startswith('vmess://'):
        return parse_vmess(proxy_line)
    elif proxy_line.startswith('ss://'):
        return parse_shadowsocks(proxy_line)
    elif proxy_line.startswith('trojan://'):
        return parse_trojan(proxy_line)
    elif proxy_line.startswith('hysteria2://'):
        return parse_hysteria2(proxy_line)
    # elif proxy_line.startswith('tuic://'):
    #     return parse_tuic(proxy_line)
    # elif proxy_line.startswith('hy2://'):
    #     return parse_hy2(proxy_line)
    # elif proxy_line.startswith('vless://'):
    #     return parse_vless(proxy_line)
    else:
        # print(f"未知的代理协议或格式: {proxy_line[:30]}...")
        return None

def parse_vmess(vmess_link: str) -> Optional[Dict]:
    """
    解析VMess链接。
    """
    try:
        base64_data = vmess_link.replace('vmess://', '')
        # 如果长度不是4的倍数，进行填充
        if len(base64_data) % 4 != 0:
            base64_data += '=' * (4 - len(base64_data) % 4)
        json_data = base64.b64decode(base64_data).decode('utf-8')
        config = json.loads(json_data)
        
        # 兼容性处理
        ws_path = config.get('path', '/')
        ws_headers = config.get('host', '')
        if not ws_headers and 'headers' in config and 'Host' in config['headers']:
            ws_headers = config['headers']['Host']
        
        # 提取端口
        port = int(config.get('port', 443))
        # 根据 tls 设置确定网络类型
        if config.get('tls') == 'tls':
            network = 'ws'  # Clash中VMess TLS通常伴随WebSocket
            servername = config.get('sni', ws_headers) if 'sni' in config and config['sni'] else ws_headers
        else:
            # 非TLS情况，通常是TCP
            network = 'tcp'
            servername = ''

        return {
            "name": f"vmess-{config['ps']}-{datetime.now().strftime('%H%M%S')}-{random.randint(100,999)}",
            "type": "vmess",
            "server": config['add'],
            "port": port,
            "uuid": config['id'],
            "alterId": config.get('aid', 0),
            "cipher": "auto",
            "network": network,
            "tls": config.get('tls') == 'tls',
            "servername": servername if servername else None,
            "ws-opts": {
                "path": ws_path,
                "headers": {
                    "Host": ws_headers
                }
            } if network == 'ws' else None
        }
    except (json.JSONDecodeError, KeyError, IndexError, UnicodeDecodeError) as e:
        # print(f"解析VMess链接失败: {e} - {vmess_link[:30]}...")
        return None

def parse_shadowsocks(ss_link: str) -> Optional[Dict]:
    """
    解析Shadowsocks链接。
    """
    try:
        # ss://method:password@server:port#name
        parsed = urllib.parse.urlparse(ss_link)
        if parsed.fragment:
            # SS链接可能包含Base64编码的info
            name = urllib.parse.unquote(parsed.fragment)
        else:
            name = f"ss-{parsed.hostname}-{datetime.now().strftime('%H%M%S')}-{random.randint(100,999)}"

        if parsed.netloc:
            # Base64编码
            decoded_netloc = base64.b64decode(parsed.netloc.encode('utf-8')).decode('utf-8')
            parts = decoded_netloc.split('@')
            credentials, server_info = parts[0], parts[1]
            method, password = credentials.split(':', 1)
            server, port = server_info.split(':')
        else:
            # 未编码
            credentials = parsed.username
            password = parsed.password
            server = parsed.hostname
            port = parsed.port
            method = credentials
            
        return {
            "name": name,
            "type": "ss",
            "server": server,
            "port": int(port),
            "cipher": method,
            "password": password
        }
    except Exception as e:
        # print(f"解析Shadowsocks链接失败: {e} - {ss_link[:30]}...")
        return None

def parse_trojan(trojan_link: str) -> Optional[Dict]:
    """
    解析Trojan链接。
    """
    try:
        # trojan://password@server:port?param1=value1#name
        parsed = urllib.parse.urlparse(trojan_link)
        name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"trojan-{parsed.hostname}-{datetime.now().strftime('%H%M%S')}-{random.randint(100,999)}"
        params = urllib.parse.parse_qs(parsed.query)

        return {
            "name": name,
            "type": "trojan",
            "server": parsed.hostname,
            "port": parsed.port,
            "password": parsed.username,
            "network": params.get('type', ['tcp'])[0],
            "tls": True,
            "servername": params.get('sni', [parsed.hostname])[0]
        }
    except Exception as e:
        # print(f"解析Trojan链接失败: {e} - {trojan_link[:30]}...")
        return None

def parse_hysteria2(hy2_link: str) -> Optional[Dict]:
    """
    解析Hysteria2链接。
    """
    try:
        # hysteria2://password@server:port?obfs=obfs_type&obfs-password=obfs_password#name
        parsed = urllib.parse.urlparse(hy2_link)
        name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"hy2-{parsed.hostname}-{datetime.now().strftime('%H%M%S')}-{random.randint(100,999)}"
        params = urllib.parse.parse_qs(parsed.query)

        # 检查是否为 base64 编码
        password = parsed.username
        if re.match(r'^[A-Za-z0-9+/=]+$', password):
            try:
                password = base64.b64decode(password).decode('utf-8')
            except:
                pass # 如果解码失败，保持原样

        return {
            "name": name,
            "type": "hysteria2",
            "server": parsed.hostname,
            "port": parsed.port,
            "password": password,
            "obfs": params.get('obfs', [None])[0],
            "obfs-password": params.get('obfs-password', [None])[0],
            "tls": True,
            "sni": params.get('sni', [None])[0] or parsed.hostname,
            "alpn": [ "h3" ],
            "skip-cert-verify": "true" == params.get('insecure', ['false'])[0]
        }
    except Exception as e:
        # print(f"解析Hysteria2链接失败: {e} - {hy2_link[:30]}...")
        return None

def filter_banned_proxies(proxies: List[Dict]) -> List[Dict]:
    """
    过滤掉包含BAN关键词的代理。
    """
    filtered_proxies = []
    for proxy in proxies:
        if proxy and 'name' in proxy:
            if not any(ban_word in proxy['name'] for ban_word in BAN):
                filtered_proxies.append(proxy)
            # else:
            #     print(f"过滤掉不符合要求的节点: {proxy['name']}")
    return filtered_proxies

def find_clash_api_port():
    """
    查找可用的Clash API端口。
    """
    for port in CLASH_API_PORTS:
        try:
            r = requests.get(f"http://{CLASH_API_HOST}:{port}/traffic", headers=headers, timeout=TIMEOUT)
            if r.status_code == 200:
                print(f"找到Clash API端口: {port}")
                return port
        except requests.exceptions.RequestException:
            continue
    print("未找到可用的Clash API端口，可能Clash没有运行或者API未启用。")
    return None

def test_proxy_latency(proxy_name: str, api_port: int):
    """
    测试单个代理的延迟。
    """
    url = f"http://{CLASH_API_HOST}:{api_port}/proxies/{urllib.parse.quote(proxy_name)}/delay"
    data = {
        "url": "http://www.gstatic.com/generate_204",
        "timeout": 5000
    }
    try:
        r = requests.get(url, params=data, headers=headers, timeout=TIMEOUT)
        r.raise_for_status()
        result = r.json()
        delay = result.get('delay')
        # print(f"节点 {proxy_name} 延迟: {delay}ms")
        return delay
    except requests.exceptions.RequestException as e:
        # print(f"测试节点 {proxy_name} 延迟失败: {e}")
        return 999999 # 返回一个大值表示失败

async def test_proxy_speed(proxy_name: str, api_port: int, semaphore: Semaphore):
    """
    异步测试单个代理的下行速度。
    """
    async with semaphore:
        url = f"http://{CLASH_API_HOST}:{api_port}/proxies/{urllib.parse.quote(proxy_name)}/delay"
        data = {
            "url": "http://www.speedtest.net/images/speedtest-mobile-icon-256.png",
            "timeout": 5000
        }
        try:
            # print(f"开始测试节点 {proxy_name} 的速度...")
            async with httpx.AsyncClient(timeout=TIMEOUT, verify=False) as client:
                start_time = time.time()
                r = await client.get(url, params=data, headers=headers)
                r.raise_for_status()
                # 假设r.json()包含速度信息或可以计算
                # 这里我们简单地以响应时间作为参考，实际速度测试需要更复杂的逻辑
                end_time = time.time()
                elapsed = (end_time - start_time) * 1000 # 毫秒
                # print(f"节点 {proxy_name} 速度测试完成，耗时: {elapsed:.2f}ms")
                results_speed.append({'name': proxy_name, 'delay': elapsed})
        except Exception as e:
            # print(f"测试节点 {proxy_name} 速度失败: {e}")
            results_speed.append({'name': proxy_name, 'delay': 999999})

async def run_speed_tests(proxy_names: List[str], api_port: int):
    """
    并发运行速度测试。
    """
    semaphore = Semaphore(MAX_CONCURRENT_TESTS)
    tasks = [test_proxy_speed(name, api_port, semaphore) for name in proxy_names[:SPEED_TEST_LIMIT]]
    await asyncio.gather(*tasks)

def save_clash_config(config: Dict, filename: str):
    """
    将Clash配置保存到YAML文件。
    """
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            yaml.dump(config, f, allow_unicode=True, sort_keys=False)
        print(f"Clash配置已保存到文件: {filename}")
    except Exception as e:
        print(f"保存Clash配置失败: {e}")

def main():
    """
    主函数，用于加载、测试和生成Clash配置。
    """
    # 1. 从环境变量或文件中加载代理节点
    print(f"正在加载代理节点，输入源: {INPUT}")
    proxy_nodes = load_proxy_nodes(INPUT)
    if not proxy_nodes:
        print("未加载到任何代理节点，脚本结束。")
        return

    # 2. 解析代理链接
    clash_proxies = []
    if isinstance(proxy_nodes[0], str): # 如果是链接列表
        print("正在解析代理链接...")
        for line in proxy_nodes:
            proxy_config = parse_proxy_line(line)
            if proxy_config:
                clash_proxies.append(proxy_config)
    elif isinstance(proxy_nodes[0], dict): # 如果是Clash配置列表
        print("已检测到YAML格式，直接使用...")
        clash_proxies = proxy_nodes
    else:
        print("不支持的代理节点格式，脚本结束。")
        return
        
    print(f"成功解析 {len(clash_proxies)} 个节点。")
    
    # 3. 过滤被BAN的节点
    clash_proxies = filter_banned_proxies(clash_proxies)
    print(f"过滤后剩余 {len(clash_proxies)} 个节点。")

    if not clash_proxies:
        print("没有可用的代理节点，脚本结束。")
        return
    
    # 4. 排序和限制节点数量
    clash_proxies = sorted(clash_proxies, key=lambda p: p['name'])
    clash_proxies = clash_proxies[:LIMIT]
    print(f"排序并限制后剩余 {len(clash_proxies)} 个节点。")

    # 5. 生成Clash配置
    config = clash_config_template.copy()
    config['proxies'] = clash_proxies
    
    proxy_names = [p['name'] for p in clash_proxies]
    config['proxy-groups'][0]['proxies'] = ["自动选择", "故障转移", "DIRECT"] + proxy_names
    config['proxy-groups'][1]['proxies'] = proxy_names
    config['proxy-groups'][2]['proxies'] = proxy_names
    config['proxy-groups'][3]['proxies'] = proxy_names
    
    # 6. 保存配置
    save_clash_config(config, CONFIG_FILE)

if __name__ == "__main__":
    main()
