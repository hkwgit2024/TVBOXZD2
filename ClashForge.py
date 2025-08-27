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
LIMIT = 10000  # 最多保留LIMIT个节点
CONFIG_FILE = 'clash_config.yaml'
INPUT = "input"  # 从文件中加载代理节点，支持yaml/yml、txt(每条代理链接占一行)
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
    'geox-url': {'geoip': 'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/geoip.dat',
                 'mmdb': 'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/GeoLite2-Country.mmdb'},
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

        "MATCH,节点选择"
    ]
}


def validate_proxy(proxy: Dict) -> Optional[Dict]:
    """验证代理配置是否符合 Clash 规范，并返回清洗后的节点。"""
    required_fields = {
        'hysteria2': ['name', 'server', 'port', 'type', 'password'],
        'ss': ['name', 'server', 'port', 'type', 'cipher', 'password'],
        'trojan': ['name', 'server', 'port', 'type', 'password'],
        'vless': ['name', 'server', 'port', 'type', 'uuid'],
        'vmess': ['name', 'server', 'port', 'type', 'uuid']
    }

    proxy_type = proxy.get('type')
    if not proxy_type or proxy_type not in required_fields:
        print(f"[-] 排除节点: {proxy.get('name', '未知') if proxy else '未知'}，原因: 类型不正确或缺失")
        return None

    for field in required_fields[proxy_type]:
        if field not in proxy or not proxy[field]:
            print(f"[-] 排除节点: {proxy.get('name', '未知')}，原因: 缺少或值为空的必要字段 '{field}'")
            return None

    # 移除额外不必要的字段，确保格式严格
    cleaned_proxy = {k: v for k, v in proxy.items() if k in required_fields[proxy_type] or k in ['network', 'ws-opts', 'tls', 'sni', 'skip-cert-verify', 'alterId', 'udp']}
    
    return cleaned_proxy


# 解析 Hysteria2 链接
def parse_hysteria2_link(link):
    link = link[14:]
    parts = link.split('@')
    if len(parts) < 2: return None
    uuid = parts[0]
    server_info = parts[1].split('?')
    server_port_part = server_info[0].split('/')
    if not server_port_part or ':' not in server_port_part[0]: return None
    server_part = server_port_part[0].split(':')
    server = server_part[0]
    port = int(server_part[1].strip())
    
    query_params = urllib.parse.parse_qs(server_info[1] if len(server_info) > 1 else '')
    insecure = '1' in query_params.get('insecure', ['0'])
    sni = query_params.get('sni', [''])[0]
    name_part = link.split('#')
    name = urllib.parse.unquote(name_part[-1].strip()) if len(name_part) > 1 else 'hysteria2_node'

    return validate_proxy({
        "name": f"{name}",
        "server": server,
        "port": port,
        "type": "hysteria2",
        "password": uuid,
        "auth": uuid,
        "sni": sni,
        "skip-cert-verify": insecure,
        "client-fingerprint": "chrome"
    })


# 解析 Shadowsocks 链接
def parse_ss_link(link):
    link = link[5:]
    if "#" in link:
        config_part, name = link.split('#')
    else:
        config_part, name = link, "ss_node"
    
    try:
        decoded = base64.urlsafe_b64decode(config_part.split('@')[0] + '=' * (-len(config_part.split('@')[0]) % 4)).decode('utf-8')
        method_passwd = decoded.split(':')
        cipher, password = method_passwd if len(method_passwd) == 2 else (method_passwd[0], "")
        server_info = config_part.split('@')[1]
        server, port = server_info.split(':') if ":" in server_info else (server_info, "")
    except Exception as e:
        print(f"[-] 排除无效的SS链接: {link}, 错误: {e}")
        return None

    return validate_proxy({
        "name": urllib.parse.unquote(name),
        "type": "ss",
        "server": server,
        "port": int(port),
        "cipher": cipher,
        "password": password,
        "udp": True
    })


# 解析 Trojan 链接
def parse_trojan_link(link):
    link = link[9:]
    if '#' not in link: return None
    config_part, name = link.split('#')
    if '@' not in config_part: return None
    user_info, host_info = config_part.split('@')
    username, password = user_info.split(':') if ":" in user_info else ("", user_info)
    host, port_and_query = host_info.split(':') if ":" in host_info else (host_info, "")
    port, query = port_and_query.split('?', 1) if '?' in port_and_query else (port_and_query, "")

    return validate_proxy({
        "name": urllib.parse.unquote(name),
        "type": "trojan",
        "server": host,
        "port": int(port),
        "password": password,
        "sni": urllib.parse.parse_qs(query).get("sni", [""])[0],
        "skip-cert-verify": urllib.parse.parse_qs(query).get("skip-cert-verify", ["false"])[0] == "true"
    })


# 解析 VLESS 链接
def parse_vless_link(link):
    link = link[8:]
    if '#' not in link or '@' not in link: return None
    config_part, name = link.split('#')
    user_info, host_info = config_part.split('@')
    uuid = user_info
    host_part = host_info.split('?', 1)
    host_port = host_part[0]
    query_str = host_part[1] if len(host_part) > 1 else ""

    host_parts = host_port.split(':')
    host = host_parts[0]
    port = host_parts[1] if len(host_parts) > 1 else ""
    
    query_params = urllib.parse.parse_qs(query_str)
    security = query_params.get("security", ["none"])[0]
    
    return validate_proxy({
        "name": urllib.parse.unquote(name),
        "type": "vless",
        "server": host,
        "port": int(port),
        "uuid": uuid,
        "security": security,
        "tls": security == "tls",
        "sni": query_params.get("sni", [""])[0],
        "skip-cert-verify": query_params.get("skip-cert-verify", ["false"])[0] == "true",
        "network": query_params.get("type", ["tcp"])[0],
        "ws-opts": {
            "path": query_params.get("path", [""])[0],
            "headers": {
                "Host": query_params.get("host", [""])[0]
            }
        } if query_params.get("type", ["tcp"])[0] == "ws" else {}
    })


# 解析 VMESS 链接
def parse_vmess_link(link):
    link = link[8:]
    try:
        decoded_link = base64.urlsafe_b64decode(link + '=' * (-len(link) % 4)).decode("utf-8")
        vmess_info = json.loads(decoded_link)
    except Exception as e:
        print(f"[-] 排除无效的VMESS链接: {link}, 错误: {e}")
        return None
    
    return validate_proxy({
        "name": urllib.parse.unquote(vmess_info.get("ps", "vmess")),
        "type": "vmess",
        "server": vmess_info["add"],
        "port": int(vmess_info["port"]),
        "uuid": vmess_info["id"],
        "alterId": int(vmess_info.get("aid", 0)),
        "cipher": "auto",
        "network": vmess_info.get("net", "tcp"),
        "tls": vmess_info.get("tls", "") == "tls",
        "sni": vmess_info.get("sni", ""),
        "ws-opts": {
            "path": vmess_info.get("path", ""),
            "headers": {
                "Host": vmess_info.get("host", "")
            }
        } if vmess_info.get("net", "tcp") == "ws" else {}
    })


# 解析ss订阅源
def parse_ss_sub(link):
    new_links = []
    try:
        response = requests.get(link, headers=headers, verify=False, allow_redirects=True, timeout=10)
        if response.status_code == 200:
            data = response.json()
            new_links = [validate_proxy({"name": x.get('remarks'), "type": "ss", "server": x.get('server'), "port": x.get('server_port'),
                          "cipher": x.get('method'), "password": x.get('password'), "udp": True}) for x in data]
            return [n for n in new_links if n is not None]
    except requests.RequestException as e:
        print(f"[-] 请求SS订阅源错误: {e}")
        return new_links


def parse_md_link(link):
    try:
        response = requests.get(link, timeout=10)
        response.raise_for_status()
        content = response.text
        content = urllib.parse.unquote(content)
        pattern = r'(?:vless|vmess|trojan|hysteria2|ss):\/\/[^#\s]*(?:#[^\s]*)?'
        matches = re.findall(pattern, content)
        return matches
    except requests.RequestException as e:
        print(f"[-] 请求Markdown文件错误: {e}")
        return []


def js_render(url):
    timeout = 15
    browser_args = ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--disable-software-rasterizer',
                    '--disable-setuid-sandbox']
    session = HTMLSession(browser_args=browser_args)
    r = session.get(f'{url}', headers=headers, timeout=timeout, verify=False)
    r.html.render(timeout=timeout)
    return r


def match_nodes(text):
    proxy_pattern = r"\{[^}]*name\s*:\s*['\"][^'\"]+['\"][^}]*server\s*:\s*[^,]+[^}]*\}"
    nodes = re.findall(proxy_pattern, text, re.DOTALL)
    proxies_list = []
    for node in nodes:
        try:
            node_dict = yaml.safe_load(node)
            proxies_list.append(node_dict)
        except Exception as e:
            print(f"[-] 无法解析节点字符串: {node}, 错误: {e}")
    yaml_data = {"proxies": proxies_list}
    return yaml_data


def process_url(url):
    isyaml = False
    try:
        response = requests.get(url, headers=headers, verify=False, allow_redirects=True, timeout=10)
        if response.status_code == 200:
            content = response.content.decode('utf-8')
            if 'proxies:' in content:
                if '</pre>' in content:
                    content = content.replace('<pre style="word-wrap: break-word; white-space: pre-wrap;">',
                                              '').replace('</pre>', '')
                yaml_data = yaml.safe_load(content)
                if 'proxies' in yaml_data:
                    isyaml = True
                    proxies = yaml_data['proxies'] if yaml_data['proxies'] else []
                    return proxies, isyaml
            else:
                try:
                    decoded_bytes = base64.b64decode(content)
                    decoded_content = decoded_bytes.decode('utf-8')
                    decoded_content = urllib.parse.unquote(decoded_content)
                    return decoded_content.splitlines(), isyaml
                except Exception as e:
                    print(f"[-] Base64解码失败，尝试JS渲染: {e}")
                    try:
                        res = js_render(url)
                        if 'external-controller' in res.html.text:
                            try:
                                yaml_data = yaml.safe_load(res.html.text)
                            except Exception:
                                yaml_data = match_nodes(res.html.text)
                            finally:
                                if 'proxies' in yaml_data:
                                    isyaml = True
                                    return yaml_data['proxies'], isyaml
                        else:
                            pattern = r'([A-Za-z0-9_+/\-]+={0,2})'
                            matches = re.findall(pattern, res.html.text)
                            stdout = matches[-1] if matches else []
                            decoded_bytes = base64.b64decode(stdout)
                            decoded_content = decoded_bytes.decode('utf-8')
                            return decoded_content.splitlines(), isyaml
                    except Exception as e:
                        print(f"[-] JS渲染失败，跳过URL: {e}")
                        return [], isyaml
        else:
            print(f"[-] 无法从 {url} 获取数据，状态码: {response.status_code}")
            return [], isyaml
    except requests.RequestException as e:
        print(f"[-] 请求 {url} 时发生错误: {e}")
        return [], isyaml


def parse_proxy_link(link):
    try:
        if link.startswith("hysteria2://") or link.startswith("hy2://"):
            return parse_hysteria2_link(link)
        elif link.startswith("trojan://"):
            return parse_trojan_link(link)
        elif link.startswith("ss://"):
            return parse_ss_link(link)
        elif link.startswith("vless://"):
            return parse_vless_link(link)
        elif link.startswith("vmess://"):
            return parse_vmess_link(link)
    except Exception as e:
        print(f"[-] 解析链接 {link} 时出错: {e}")
        return None
    return None


def deduplicate_proxies(proxies_list):
    unique_proxies = []
    seen = set()
    for proxy in proxies_list:
        key = (proxy['server'], proxy['port'], proxy['type'])
        if key not in seen:
            seen.add(key)
            unique_proxies.append(proxy)
    return unique_proxies


def add_random_suffix(name, existing_names):
    suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
    new_name = f"{name}-{suffix}"
    while new_name in existing_names:
        suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
        new_name = f"{name}-{suffix}"
    return new_name


def read_txt_files(folder_path):
    all_lines = []
    txt_files = glob.glob(os.path.join(folder_path, '*.txt'))
    for file_path in txt_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                lines = file.readlines()
                all_lines.extend(line.strip() for line in lines)
        except Exception as e:
            print(f"[-] 读取文件 {file_path} 错误: {str(e)}")
    if all_lines:
        print(f'[*] 从【{folder_path}】目录下加载 {len(all_lines)} 条代理链接')
    return all_lines


def read_yaml_files(folder_path):
    load_nodes = []
    yaml_files = glob.glob(os.path.join(folder_path, '*.yaml'))
    yaml_files.extend(glob.glob(os.path.join(folder_path, '*.yml')))
    for file_path in yaml_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                config = yaml.safe_load(file)
                if config and 'proxies' in config:
                    load_nodes.extend(config['proxies'])
        except Exception as e:
            print(f"[-] 读取文件 {file_path} 错误: {str(e)}")
    if load_nodes:
        print(f'[*] 从【{folder_path}】目录下加载 {len(load_nodes)} 个节点')
    return load_nodes


def filter_by_types_alt(allowed_types, nodes):
    return [x for x in nodes if x.get('type') in allowed_types]


def merge_lists(*lists):
    return [item for item in chain.from_iterable(lists) if item != '']


def generate_clash_config(links, load_nodes):
    print("===================开始处理代理链接和文件======================")
    now = datetime.now()
    print(f"[*] 当前时间: {now}")
    final_nodes = []
    existing_names = set()
    config = clash_config_template.copy()

    def resolve_name_conflicts(node):
        server = node.get("server")
        if not server:
            return
        name = str(node["name"])
        if not_contains(name):
            if name in existing_names:
                name = add_random_suffix(name, existing_names)
            existing_names.add(name)
            node["name"] = name
            final_nodes.append(node)

    print("[*] 正在解析本地文件节点...")
    for node in load_nodes:
        cleaned_node = validate_proxy(node)
        if cleaned_node:
            resolve_name_conflicts(cleaned_node)

    print("[*] 正在解析在线链接...")
    for link in links:
        if link.startswith(("hysteria2://", "hy2://", "trojan://", "ss://", "vless://", "vmess://")):
            node = parse_proxy_link(link)
            if node:
                resolve_name_conflicts(node)
        else:
            print(f"[*] 正在处理订阅源: {link}")
            if '|links' in link or '.md' in link:
                link = link.replace('|links', '')
                new_links = parse_md_link(link)
                for new_link in new_links:
                    node = parse_proxy_link(new_link)
                    if node:
                        resolve_name_conflicts(node)
            elif '|ss' in link:
                link = link.replace('|ss', '')
                new_links = parse_ss_sub(link)
                for node in new_links:
                    resolve_name_conflicts(node)
            elif '{' in link:
                link = resolve_template_url(link)
            
            new_links, isyaml = process_url(link)
            if isyaml:
                for node in new_links:
                    cleaned_node = validate_proxy(node)
                    if cleaned_node:
                        resolve_name_conflicts(cleaned_node)
            else:
                for new_link in new_links:
                    node = parse_proxy_link(new_link)
                    if node:
                        resolve_name_conflicts(node)

    final_nodes = deduplicate_proxies(final_nodes)
    print(f"[*] 解析完成，共获取 {len(final_nodes)} 个唯一节点")

    config["proxies"] = final_nodes
    for node in final_nodes:
        name = str(node["name"])
        if not_contains(name):
            config["proxy-groups"][1]["proxies"].append(name)
    
    # 对代理组进行去重并更新
    proxies = list(set(config["proxy-groups"][1]["proxies"]))
    config["proxy-groups"][1]["proxies"] = proxies
    config["proxy-groups"][2]["proxies"] = proxies
    config["proxy-groups"][3]["proxies"] = proxies

    if config["proxies"]:
        global CONFIG_FILE
        CONFIG_FILE = CONFIG_FILE[:-5] if CONFIG_FILE.endswith('.json') else CONFIG_FILE
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            yaml.dump(config, f, allow_unicode=True, default_flow_style=False)
        with open(f'{CONFIG_FILE}.json', "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False)
        print(f"[*] 已生成Clash配置文件 {CONFIG_FILE} 和 {CONFIG_FILE}.json")
    else:
        print('[-] 没有节点数据可供更新')


def not_contains(s):
    return not any(k in s for k in BAN)


class ClashAPIException(Exception):
    pass


class ProxyTestResult:
    def __init__(self, name: str, delay: Optional[float] = None):
        self.name = name
        self.delay = delay if delay is not None else float('inf')
        self.status = "ok" if delay is not None else "fail"
        self.tested_time = datetime.now()

    @property
    def is_valid(self) -> bool:
        return self.status == "ok"


def ensure_executable(file_path):
    if platform.system().lower() in ['linux', 'darwin']:
        os.chmod(file_path, 0o755)


def handle_clash_error(error_message, config_file_path):
    start_time = time.time()
    config_file_path = f'{config_file_path}.json' if os.path.exists(f'{config_file_path}.json') else config_file_path
    
    proxy_index_match = re.search(r'proxy (\d+):', error_message)
    if not proxy_index_match:
        return False
    problem_index = int(proxy_index_match.group(1))

    try:
        with open(config_file_path, 'r', encoding='utf-8') as file:
            config = json.load(file)
        problem_proxy_name = config['proxies'][problem_index]['name']
        del config['proxies'][problem_index]
        
        proxies = config['proxy-groups'][1]["proxies"]
        if problem_proxy_name in proxies:
            proxies.remove(problem_proxy_name)
        for group in config["proxy-groups"][1:]:
            group["proxies"] = proxies
        
        with open(config_file_path, 'w', encoding='utf-8') as file:
            file.write(json.dumps(config, ensure_ascii=False))
        
        print(f"[*] 配置异常，已移除无效节点: {problem_proxy_name}")
        return True

    except Exception as e:
        print(f"[-] 处理配置文件时出错: {str(e)}")
        return False


def download_and_extract_latest_release():
    url = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
    response = requests.get(url, timeout=10)
    if response.status_code != 200:
        print("[-] 无法获取最新版本信息")
        return
    
    data = response.json()
    assets = data.get("assets", [])
    os_type = platform.system().lower()
    targets = {
        "darwin": "mihomo-darwin-amd64-compatible",
        "linux": "mihomo-linux-amd64-compatible",
        "windows": "mihomo-windows-amd64-compatible"
    }

    download_url = None
    new_name = f"clash-{os_type}" if os_type != "windows" else "clash.exe"
    if os.path.exists(new_name):
        print(f"[*] Clash可执行文件已存在: {new_name}")
        return
    
    print(f"[*] 正在下载Clash可执行文件...")
    for asset in assets:
        name = asset.get("name", "")
        if os_type == "darwin" and targets["darwin"] in name and name.endswith('.gz'):
            download_url = asset["browser_download_url"]
            break
        elif os_type == "linux" and targets["linux"] in name and name.endswith('.gz'):
            download_url = asset["browser_download_url"]
            break
        elif os_type == "windows" and targets["windows"] in name and name.endswith('.zip'):
            download_url = asset["browser_download_url"]
            break

    if download_url:
        filename = download_url.split('/')[-1]
        response = requests.get(download_url, timeout=30)
        with open(filename, 'wb') as f:
            f.write(response.content)
        
        extracted_files = []
        if filename.endswith('.zip'):
            with zipfile.ZipFile(filename, 'r') as zip_ref:
                zip_ref.extractall()
                extracted_files = zip_ref.namelist()
        elif filename.endswith('.gz'):
            with gzip.open(filename, 'rb') as f_in:
                output_filename = filename[:-3]
                with open(output_filename, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
                    extracted_files.append(output_filename)

        for file_name in extracted_files:
            if os.path.exists(file_name):
                os.rename(file_name, new_name)
                break
        os.remove(filename)
        print(f"[*] Clash可执行文件下载完成: {new_name}")
    else:
        print("[-] 未找到适用于当前操作系统的版本")


def read_output(pipe, output_lines):
    while True:
        line = pipe.readline()
        if line:
            output_lines.append(line)
        else:
            break


def kill_clash():
    system = platform.system()
    clash_process_names = {
        "Windows": "clash.exe",
        "Linux": "clash-linux",
        "Darwin": "clash-darwin"
    }
    config_files = ["clash_config.yaml", "clash_config.yaml.json"]

    if system not in clash_process_names:
        print("[-] 不支持的操作系统")
        return

    process_name = clash_process_names[system]
    print(f"[*] 正在尝试结束 Clash 进程 ({process_name})")
    
    found = False
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['name'] != process_name:
                continue
            cmdline = proc.info['cmdline']
            if cmdline and len(cmdline) >= 3 and cmdline[1] == '-f' and cmdline[2] in config_files:
                proc.kill()
                found = True
                print(f"[*] Clash 进程 (PID: {proc.pid}) 已终止")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    if not found:
        print(f"[*] 未找到 Clash 进程")


def start_clash():
    download_and_extract_latest_release()
    system_platform = platform.system().lower()

    if system_platform == 'windows':
        clash_binary = '.\\clash.exe'
    elif system_platform in ["linux", "darwin"]:
        clash_binary = f'./clash-{system_platform}'
        ensure_executable(clash_binary)
    else:
        raise OSError("不支持的操作系统")

    if not os.path.exists(clash_binary):
        raise FileNotFoundError(f"Clash 可执行文件不存在: {clash_binary}")

    global CONFIG_FILE
    CONFIG_FILE = f'{CONFIG_FILE}.json' if os.path.exists(f'{CONFIG_FILE}.json') else CONFIG_FILE

    while True:
        print(f'[*] 正在启动 Clash，加载配置: {CONFIG_FILE}')
        clash_process = subprocess.Popen(
            [clash_binary, '-f', CONFIG_FILE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8'
        )

        output_lines = []
        stdout_thread = threading.Thread(target=read_output, args=(clash_process.stdout, output_lines))
        stdout_thread.daemon = True
        stdout_thread.start()

        timeout = 20
        start_time = time.time()
        while time.time() - start_time < timeout:
            stdout_thread.join(timeout=0.5)
            if output_lines:
                last_line = output_lines[-1].strip()
                if "Parse config error" in last_line:
                    print("[-] 检测到配置解析错误，正在尝试修复...")
                    clash_process.kill()
                    if handle_clash_error(last_line, CONFIG_FILE):
                        output_lines = []
                        continue
                    else:
                        raise ValueError("无法修复配置错误，请手动检查配置文件。")
            
            if is_clash_api_running():
                print("[*] Clash API 成功启动。")
                return clash_process
            
            if clash_process.poll() is not None:
                print("[-] Clash 进程意外终止，请检查日志或配置。")
                raise RuntimeError("Clash 进程无法启动。")

        clash_process.kill()
        raise TimeoutError("[-] Clash 在预设时间内未能启动。")


def is_clash_api_running():
    try:
        url = f"http://{CLASH_API_HOST}:{CLASH_API_PORTS[0]}/configs"
        response = requests.get(url, timeout=3)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False


def switch_proxy(proxy_name='DIRECT'):
    url = f"http://{CLASH_API_HOST}:{CLASH_API_PORTS[0]}/proxies/节点选择"
    data = {"name": proxy_name}
    try:
        response = requests.put(url, json=data, timeout=5)
        if response.status_code == 204:
            print(f"[*] 已切换到代理: '{proxy_name}'")
        else:
            print(f"[-] 切换代理失败，状态码: {response.status_code}")
    except Exception as e:
        print(f"[-] 切换代理时发生错误: {e}")


class ClashAPI:
    def __init__(self, host: str, ports: List[int], secret: str = ""):
        self.host = host
        self.ports = ports
        self.base_url = None
        self.headers = {
            "Authorization": f"Bearer {secret}" if secret else "",
            "Content-Type": "application/json",
            'Accept-Charset': 'utf-8',
            'Accept': 'text/html,application/x-yaml,*/*',
            'User-Agent': 'Clash Verge/1.7.7'
        }
        self.client = httpx.AsyncClient(timeout=TIMEOUT)
        self.semaphore = Semaphore(MAX_CONCURRENT_TESTS)
        self._test_results_cache: Dict[str, ProxyTestResult] = {}
        self.progress_count = 0
        self.total_proxies = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()

    async def check_connection(self) -> bool:
        for port in self.ports:
            try:
                test_url = f"http://{self.host}:{port}"
                response = await self.client.get(f"{test_url}/version", timeout=5)
                if response.status_code == 200:
                    version = response.json().get('version', 'unknown')
                    print(f"[*] 成功连接到 Clash API (端口 {port})，版本: {version}")
                    self.base_url = test_url
                    return True
            except httpx.RequestError:
                continue
        print("[-] 所有端口均连接失败，请检查 Clash 是否正在运行")
        return False

    async def test_proxy_delay(self, proxy_name: str) -> ProxyTestResult:
        self.progress_count += 1
        print(f"\r测试进度: {self.progress_count}/{self.total_proxies} ({self.progress_count/self.total_proxies*100:.1f}%)", end="", flush=True)

        async with self.semaphore:
            if proxy_name in self._test_results_cache:
                cached_result = self._test_results_cache[proxy_name]
                if (datetime.now() - cached_result.tested_time).total_seconds() < 60:
                    return cached_result
            
            try:
                response = await self.client.get(
                    f"{self.base_url}/proxies/{urllib.parse.quote(proxy_name, safe='')}/delay",
                    headers=self.headers,
                    params={"url": TEST_URL, "timeout": int(TIMEOUT * 1000)}
                )
                response.raise_for_status()
                delay = response.json().get("delay")
                result = ProxyTestResult(proxy_name, delay)
            except httpx.HTTPError:
                result = ProxyTestResult(proxy_name)
            except Exception:
                result = ProxyTestResult(proxy_name)
            finally:
                self._test_results_cache[proxy_name] = result
                return result


class ClashConfig:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = self._load_config()
        self.proxy_groups = self._get_proxy_groups()

    def _load_config(self) -> dict:
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"[-] 找不到配置文件: {self.config_path}")
            sys.exit(1)
        except yaml.YAMLError as e:
            print(f"[-] 配置文件格式错误: {e}")
            sys.exit(1)

    def _get_proxy_groups(self) -> List[Dict]:
        return self.config.get("proxy-groups", [])

    def get_group_names(self) -> List[str]:
        return [group["name"] for group in self.proxy_groups]

    def get_group_proxies(self, group_name: str) -> List[str]:
        for group in self.proxy_groups:
            if group["name"] == group_name:
                return group.get("proxies", [])
        return []

    def remove_invalid_proxies(self, results: List[ProxyTestResult]):
        invalid_proxies = {r.name for r in results if not r.is_valid}
        if not invalid_proxies:
            return
        
        valid_proxies = []
        if "proxies" in self.config:
            valid_proxies = [p for p in self.config["proxies"] if p.get("name") not in invalid_proxies]
            self.config["proxies"] = valid_proxies

        for group in self.proxy_groups:
            if "proxies" in group:
                group["proxies"] = [p for p in group["proxies"] if p not in invalid_proxies]
        
        global LIMIT
        left = LIMIT if len(self.config['proxies']) > LIMIT else len(self.config['proxies'])
        print(f"[*] 已从配置中移除 {len(invalid_proxies)} 个失效节点，最终保留 {left} 个有效节点")

    def keep_proxies_by_limit(self, proxy_names):
        if "proxies" in self.config:
            self.config["proxies"] = [p for p in self.config["proxies"] if p["name"] in proxy_names]

    def update_group_proxies(self, group_name: str, results: List[ProxyTestResult]):
        self.remove_invalid_proxies(results)
        
        valid_results = [r for r in results if r.is_valid]
        valid_results.sort(key=lambda x: x.delay)

        proxy_names = [r.name for r in valid_results]
        for group in self.proxy_groups:
            if group["name"] == group_name:
                group["proxies"] = proxy_names
                break
        return proxy_names

    def save(self):
        try:
            yaml_cfg = self.config_path.strip('.json') if self.config_path.endswith('.json') else self.config_path
            with open(yaml_cfg, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, allow_unicode=True, sort_keys=False)
            with open(f'{yaml_cfg}.json', "w", encoding="utf-8") as f:
                json.dump(self.config, f, ensure_ascii=False)
            print(f"[*] 新配置已保存到: {yaml_cfg} 和 {yaml_cfg}.json")
        except Exception as e:
            print(f"[-] 保存配置文件失败: {e}")
            sys.exit(1)


def print_test_summary(group_name: str, results: List[ProxyTestResult]):
    valid_results = [r for r in results if r.is_valid]
    invalid_results = [r for r in results if not r.is_valid]
    total = len(results)
    valid = len(valid_results)
    invalid = len(invalid_results)
    
    print("\n---")
    print(f"策略组 '{group_name}' 测试结果:")
    print(f"总节点数: {total}")
    print(f"可用节点数: {valid}")
    print(f"失效节点数: {invalid}")
    
    delays = []
    if valid > 0:
        avg_delay = sum(r.delay for r in valid_results) / valid
        print(f"平均延迟: {avg_delay:.2f}ms")
        print("可用节点排序（按延迟从小到大）:")
        sorted_results = sorted(valid_results, key=lambda x: x.delay)
        for i, result in enumerate(sorted_results[:LIMIT], 1):
            delays.append({"name": result.name, "Delay_ms": round(result.delay, 2)})
            print(f"{i}. {result.name}: {result.delay:.2f}ms")
    print("---")
    return delays


async def test_group_proxies(clash_api: ClashAPI, proxies: List[str]) -> List[ProxyTestResult]:
    clash_api.total_proxies = len(proxies)
    clash_api.progress_count = 0
    print(f"[*] 开始测试 {len(proxies)} 个节点 (最大并发: {MAX_CONCURRENT_TESTS})")
    
    tasks = [clash_api.test_proxy_delay(proxy_name) for proxy_name in proxies]
    results = await asyncio.gather(*tasks)
    
    print("\n测试完成。")
    return results


async def proxy_clean():
    delays = []
    global MAX_CONCURRENT_TESTS, TIMEOUT, CLASH_API_SECRET, LIMIT, CONFIG_FILE
    CONFIG_FILE = f'{CONFIG_FILE}.json' if os.path.exists(f'{CONFIG_FILE}.json') else CONFIG_FILE
    
    print("===================节点批量检测基本信息======================")
    print(f"配置文件: {CONFIG_FILE}")
    print(f"API 端口: {CLASH_API_PORTS[0]}")
    print(f"并发数量: {MAX_CONCURRENT_TESTS}")
    print(f"超时时间: {TIMEOUT}秒")
    print(f"保留节点：最多保留{LIMIT}个延迟最小的有效节点")

    config = ClashConfig(CONFIG_FILE)
    available_groups = config.get_group_names()[1:]
    groups_to_test = available_groups
    if not groups_to_test:
        print("[-] 没有找到要测试的有效策略组")
        return

    start_time = datetime.now()
    async with ClashAPI(CLASH_API_HOST, CLASH_API_PORTS, CLASH_API_SECRET) as clash_api:
        if not await clash_api.check_connection():
            return
        
        try:
            group_name = groups_to_test[0]
            proxies = config.get_group_proxies(group_name)
            if not proxies:
                print(f"[-] 策略组 '{group_name}' 中没有代理节点")
                return

            results = await test_group_proxies(clash_api, proxies)
            delays = print_test_summary(group_name, results)
            
            config.remove_invalid_proxies(results)
            
            valid_results = [r for r in results if r.is_valid]
            valid_results.sort(key=lambda x: x.delay)
            
            if LIMIT:
                valid_results = valid_results[:LIMIT]
            
            proxy_names_to_keep = [r.name for r in valid_results]
            
            for group_name in groups_to_test:
                for group in config.proxy_groups:
                    if group["name"] == group_name:
                        group["proxies"] = proxy_names_to_keep
                        break
                print(f"[*] 策略组 '{group_name}' 已按延迟重新排序")
            
            config.keep_proxies_by_limit(proxy_names_to_keep)
            config.save()

            total_time = (datetime.now() - start_time).total_seconds()
            print(f"\n[*] 节点检测和排序总耗时: {total_time:.2f} 秒")
            return delays
        except ClashAPIException as e:
            print(f"[-] Clash API 错误: {e}")
        except Exception as e:
            print(f"[-] 发生错误: {e}")
            raise


def parse_datetime_variables():
    now = datetime.now()
    return {
        'Y': str(now.year),
        'm': str(now.month).zfill(2),
        'd': str(now.day).zfill(2),
        'H': str(now.hour).zfill(2),
        'M': str(now.minute).zfill(2),
        'S': str(now.second).zfill(2)
    }


def strip_proxy_prefix(url):
    proxy_pattern = r'^https?://[^/]+/https://'
    match = re.match(proxy_pattern, url)
    if match:
        real_url = re.sub(proxy_pattern, 'https://', url)
        proxy_prefix = url[:match.end() - 8]
        return real_url, proxy_prefix
    return url, None


def is_github_raw_url(url):
    return 'raw.githubusercontent.com' in url


def extract_file_pattern(url):
    match = re.search(r'\{x\}(\.[a-zA-Z0-9]+)(?:/|$)', url)
    if match:
        return match.group(1)
    return None


def get_github_filename(github_url, file_suffix):
    match = re.match(r'https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)', github_url)
    if not match:
        raise ValueError("无法从URL中提取owner和repo信息")
    owner, repo, branch, path_part = match.groups()
    path_part = re.sub(r'\{x\}' + re.escape(file_suffix) + '(?:/|$)', '', path_part)
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path_part}"
    
    response = requests.get(api_url, timeout=10)
    if response.status_code != 200:
        raise Exception(f"GitHub API请求失败: {response.status_code} {response.text}")

    files = response.json()
    if not isinstance(files, list):
        raise ValueError(f"GitHub API返回的不是文件列表，请检查路径: {api_url}")
    matching_files = [f['name'] for f in files if f['name'].endswith(file_suffix)]

    if not matching_files:
        raise Exception(f"未找到匹配的{file_suffix}文件")

    return matching_files[0]


def parse_template(template_url, datetime_vars):
    def replace_template(match):
        template_content = match.group(1)
        if template_content == 'x':
            return '{x}'
        
        result = ''
        current_char = ''
        for char in template_content:
            if char in datetime_vars:
                if current_char:
                    result += current_char
                    current_char = ''
                result += datetime_vars[char]
            else:
                current_char += char
        if current_char:
            result += current_char
        return result

    return re.sub(r'\{([^}]+)\}', replace_template, template_url)


def resolve_template_url(template_url):
    url, proxy_prefix = strip_proxy_prefix(template_url)
    datetime_vars = parse_datetime_variables()
    resolved_url = parse_template(url, datetime_vars)

    if is_github_raw_url(resolved_url) and '{x}' in resolved_url:
        file_suffix = extract_file_pattern(resolved_url)
        if file_suffix:
            filename = get_github_filename(resolved_url, file_suffix)
            resolved_url = re.sub(r'\{x\}' + re.escape(file_suffix), filename, resolved_url)

    if proxy_prefix:
        resolved_url = f"{proxy_prefix}{resolved_url}"

    return resolved_url


def start_download_test(proxy_names, speed_limit=0.1):
    test_all_proxies(proxy_names[:SPEED_TEST_LIMIT])
    filtered_list = [item for item in results_speed if float(item[1]) >= float(f'{speed_limit}')]
    sorted_proxy_names = []
    sorted_list = sorted(filtered_list, key=lambda x: float(x[1]), reverse=True)
    
    print('---')
    print('节点速度统计:')
    for i, result in enumerate(sorted_list[:LIMIT], 1):
        sorted_proxy_names.append(result[0])
        print(f"{i}. {result[0]}: {result[1]}Mb/s")
    print('---')

    return sorted_proxy_names


def test_all_proxies(proxy_names):
    try:
        i = 0
        for proxy_name in proxy_names:
            i += 1
            print(f"\r正在测速节点【{i}/{len(proxy_names)}】: {proxy_name}", flush=True, end='')
            test_proxy_speed(proxy_name)
        print("\r" + " " * 50 + "\r", end='')
    except Exception as e:
        print(f"[-] 测试节点速度时出错: {e}")


def test_proxy_speed(proxy_name):
    switch_proxy(proxy_name)
    proxies = {
        "http": 'http://127.0.0.1:7890',
        "https": 'http://127.0.0.1:7890',
    }
    start_time = time.time()
    total_length = 0
    test_duration = 5
    
    try:
        response = requests.get("http://speedtest.tele2.net/100MB.zip", stream=True, proxies=proxies,
                                headers={'Cache-Control': 'no-cache'},
                                timeout=test_duration)
        if response.status_code == 200:
            for data in response.iter_content(chunk_size=524288):
                total_length += len(data)
                if time.time() - start_time >= test_duration:
                    break
        else:
            print(f"\n[-] 下载失败，状态码: {response.status_code}")
            speed = 0
    except Exception as e:
        print(f"\n[-] 测试节点 {proxy_name} 下载失败: {e}")
        speed = 0
    else:
        elapsed_time = time.time() - start_time
        speed = total_length / elapsed_time if elapsed_time > 0 else 0
        speed = speed / 1024 / 1024
    
    results_speed.append((proxy_name, f"{speed:.2f}"))
    return speed


def upload_and_generate_urls(file_path=CONFIG_FILE):
    api_url = "https://ade4e1d7-catbox.seczhcom.workers.dev/user/api.php"
    result = {"clash_url": None, "singbox_url": None}

    try:
        if not os.path.isfile(file_path):
            print(f"[-] 错误：文件 {file_path} 不存在。")
            return result
        if os.path.getsize(file_path) > 209715200:
            print("[-] 错误：文件大小超过 200MB 限制。")
            return result
        
        print(f"[*] 正在上传Clash配置文件到云端...")
        with open(file_path, 'rb') as file:
            response = requests.post(api_url, data={"reqtype": "fileupload"}, files={"fileToUpload": file}, timeout=15,
                                     verify=False)
            if response.status_code == 200:
                clash_url = response.text.strip()
                result["clash_url"] = clash_url
                print(f"[*] Clash 配置文件上传成功！直链：{clash_url}")

                sb_full_url = f'https://url.v1.mk/sub?target=singbox&url={clash_url}&insert=false&config=https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/config/ACL4SSR_Online_Full_NoAuto.ini&emoji=true&list=false&xudp=false&udp=false&tfo=false&expand=true&scv=false&fdn=false'
                encoded_url = base64.urlsafe_b64encode(sb_full_url.encode()).decode()
                response = requests.post("https://v1.mk/short", json={"longUrl": encoded_url}, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if data.get("Code") == 1:
                        singbox_url = data["ShortUrl"]
                        result["singbox_url"] = singbox_url
                        print(f"[*] singbox 配置文件上传成功！直链：{singbox_url}")
                    else:
                        print(f"[-] singbox短链生成失败: {data.get('Message', '未知错误')}")
    except requests.exceptions.Timeout:
        print("[-] 上传文件请求超时。")
    except Exception as e:
        print(f"[-] 发生错误：{e}")
        
    subs_file = "subs.json"
    if result["clash_url"] or result["singbox_url"]:
        try:
            subs_data = {"clash": [], "singbox": []}
            if os.path.exists(subs_file):
                try:
                    with open(subs_file, 'r', encoding='utf-8') as f:
                        subs_data = json.load(f)
                except:
                    pass
            if result["clash_url"] and result["clash_url"] not in subs_data.get("clash", []):
                if "clash" not in subs_data: subs_data["clash"] = []
                subs_data["clash"].append(result["clash_url"])
            if result["singbox_url"] and result["singbox_url"] not in subs_data.get("singbox", []):
                if "singbox" not in subs_data: subs_data["singbox"] = []
                subs_data["singbox"].append(result["singbox_url"])
            with open(subs_file, 'w', encoding='utf-8') as f:
                json.dump(subs_data, f, ensure_ascii=False, indent=2)
            print(f"[*] 已将订阅链接记录到 {subs_file}")
        except Exception as e:
            print(f"[-] 记录订阅链接失败: {str(e)}")

    return result


def work(links, check=False, allowed_types=[], only_check=False):
    clash_process = None
    try:
        if not only_check:
            load_nodes = read_yaml_files(folder_path=INPUT)
            if allowed_types:
                load_nodes = filter_by_types_alt(allowed_types, nodes=load_nodes)
            links = merge_lists(read_txt_files(folder_path=INPUT), links)
            if not links and not load_nodes:
                print("[-] 没有找到任何可用的代理链接或节点。请检查 'links' 列表和 'input' 文件夹。")
                return
            generate_clash_config(links, load_nodes)
            
        if check or only_check:
            if not os.path.exists(CONFIG_FILE) and not os.path.exists(f'{CONFIG_FILE}.json'):
                print(f"[-] 错误: 配置文件 {CONFIG_FILE} 或 {CONFIG_FILE}.json 不存在，无法进行检测。")
                return
            
            kill_clash()
            time.sleep(1)
            
            print(f"\n===================启动clash并初始化配置======================")
            clash_process = start_clash()
            switch_proxy('DIRECT')
            
            asyncio.run(proxy_clean())
            print(f'[*] 批量检测完毕')
            
            switch_proxy("自动选择")
            upload_and_generate_urls()
            
    except KeyboardInterrupt:
        print("\n[*] 用户中断执行")
        sys.exit(0)
    except Exception as e:
        print(f"[-] 程序执行失败: {e}")
        sys.exit(1)
    finally:
        if clash_process and clash_process.poll() is None:
            print(f'[*] 关闭Clash API')
            clash_process.kill()
            clash_process.wait()


if __name__ == '__main__':
    links = [
        "https://raw.githubusercontent.com/qjlxg/HA/main/link.yaml"
    ]
    work(links, check=True, only_check=False, allowed_types=["ss", "hysteria2", "hy2", "vless", "vmess", "trojan"])
