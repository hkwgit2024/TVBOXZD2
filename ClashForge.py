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
import logging
import concurrent.futures
import statistics
from geoip2.database import Reader as GeoIPReader
from playwright.async_api import async_playwright
import socket

ssl._create_default_https_context = ssl._create_unverified_context
import warnings

warnings.filterwarnings('ignore')
import psutil

TEST_URL = "https://www.instagram.com"
SECONDARY_TEST_URL = "https://www.youtube.com"
CLASH_API_PORTS = [9090]
CLASH_API_HOST = "127.0.0.1"
CLASH_API_SECRET = ""
TIMEOUT = 3
SPEED_TEST = True
SPEED_TEST_URL = "http://speed.cloudflare.com/__down?bytes=52428800"
SPEED_TEST_LIMIT = 968
results_speed = []
MAX_CONCURRENT_TESTS = 120
LIMIT = 10000
CONFIG_FILE = 'clash_config.yaml'
INPUT = "input"
BAN = ["中国", "China", "CN", "电信", "移动", "联通", "Hong Kong", "Taiwan", "HK", "TW"]
headers = {
    'Accept-Charset': 'utf-8',
    'Accept': 'text/html,application/x-yaml,*/*',
    'User-Agent': 'Clash Verge/1.7.7'
}
STABILITY_TESTS = 3
STABILITY_INTERVAL = 2
MIN_SUCCESS_RATE = 0.8
MAX_STD_DEV = 200
GEOIP_DB_PATH = "GeoLite2-Country.mmdb"
switch_lock = threading.Lock()

clash_config_template = {
    "port": 7890,
    "socks-port": 7891,
    "redir-port": 7892,
    "allow-lan": True,
    "mode": "rule",
    "log-level": "info",
    "external-controller": "127.0.0.1:9090",
    "geodata-mode": True,
    'geox-url': {
        'geoip': 'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/geoip.dat',
        'mmdb': 'https://raw.githubusercontent.com/Loyalsoldier/geoip/release/GeoLite2-Country.mmdb'
    },
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

def parse_hysteria2_link(link):
    link = link[14:]
    parts = link.split('@')
    uuid = parts[0]
    server_info = parts[1].split('?')
    server = server_info[0].split(':')[0]
    port = int(server_info[0].split(':')[1].split('/')[0].strip())
    query_params = urllib.parse.parse_qs(server_info[1] if len(server_info) > 1 else '')
    insecure = '1' in query_params.get('insecure', ['0'])
    sni = query_params.get('sni', [''])[0]
    name = urllib.parse.unquote(link.split('#')[-1].strip())
    return {
        "name": f"{name}",
        "server": server,
        "port": port,
        "type": "hysteria2",
        "password": uuid,
        "auth": uuid,
        "sni": sni,
        "skip-cert-verify": not insecure,
        "client-fingerprint": "chrome"
    }

def parse_ss_link(link):
    link = link[5:]
    if "#" in link:
        config_part, name = link.split('#')
    else:
        config_part, name = link, ""
    decoded = base64.urlsafe_b64decode(config_part.split('@')[0] + '=' * (-len(config_part.split('@')[0]) % 4)).decode('utf-8')
    method_passwd = decoded.split(':')
    cipher, password = method_passwd if len(method_passwd) == 2 else (method_passwd[0], "")
    server_info = config_part.split('@')[1]
    server, port = server_info.split(':') if ":" in server_info else (server_info, "")
    return {
        "name": urllib.parse.unquote(name),
        "type": "ss",
        "server": server,
        "port": int(port),
        "cipher": cipher,
        "password": password,
        "udp": True
    }

def parse_trojan_link(link):
    link = link[9:]
    config_part, name = link.split('#')
    user_info, host_info = config_part.split('@')
    username, password = user_info.split(':') if ":" in user_info else ("", user_info)
    host, port_and_query = host_info.split(':') if ":" in host_info else (host_info, "")
    port, query = port_and_query.split('?', 1) if '?' in port_and_query else (port_and_query, "")
    return {
        "name": urllib.parse.unquote(name),
        "type": "trojan",
        "server": host,
        "port": int(port),
        "password": password,
        "sni": urllib.parse.parse_qs(query).get("sni", [""])[0],
        "skip-cert-verify": urllib.parse.parse_qs(query).get("skip-cert-verify", ["false"])[0] == "true"
    }

def parse_vless_link(link):
    link = link[8:]
    config_part, name = link.split('#')
    user_info, host_info = config_part.split('@')
    uuid = user_info
    host, query = host_info.split('?', 1) if '?' in host_info else (host_info, "")
    port = host.split(':')[-1] if ':' in host else ""
    host = host.split(':')[0] if ':' in host else ""
    return {
        "name": urllib.parse.unquote(name),
        "type": "vless",
        "server": host,
        "port": int(port),
        "uuid": uuid,
        "security": urllib.parse.parse_qs(query).get("security", ["none"])[0],
        "tls": urllib.parse.parse_qs(query).get("security", ["none"])[0] == "tls",
        "sni": urllib.parse.parse_qs(query).get("sni", ""),
        "skip-cert-verify": urllib.parse.parse_qs(query).get("skip-cert-verify", ["false"])[0] == "true",
        "network": urllib.parse.parse_qs(query).get("type", ["tcp"])[0],
        "ws-opts": {
            "path": urllib.parse.parse_qs(query).get("path", [""])[0],
            "headers": {
                "Host": urllib.parse.parse_qs(query).get("host", [""])[0]
            }
        } if urllib.parse.parse_qs(query).get("type", ["tcp"])[0] == "ws" else {}
    }

def parse_vmess_link(link):
    link = link[8:]
    decoded_link = base64.urlsafe_b64decode(link + '=' * (-len(link) % 4)).decode("utf-8")
    vmess_info = json.loads(decoded_link)
    return {
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
    }

def parse_ss_sub(link):
    new_links = []
    try:
        response = requests.get(link, headers=headers, verify=False, allow_redirects=True)
        if response.status_code == 200:
            data = response.json()
            new_links = [{"name": x['remarks'], "type": "ss", "server": x['server'], "port": x['server_port'],
                          "cipher": x['method'], "password": x['password'], "udp": True} for x in data]
            return new_links
    except requests.RequestException as e:
        print(f"请求错误: {e}")
        return new_links

def parse_md_link(link):
    try:
        response = requests.get(link)
        response.raise_for_status()
        content = response.text
        content = urllib.parse.unquote(content)
        pattern = r'(?:vless|vmess|trojan|hysteria2|ss):\/\/[^#\s]*(?:#[^\s]*)?'
        matches = re.findall(pattern, content)
        return matches
    except requests.RequestException as e:
        print(f"请求错误: {e}")
        return []

async def js_render(url):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, args=['--no-sandbox', '--disable-dev-shm-usage'])
        page = await browser.new_page()
        try:
            await page.goto(url, timeout=4000)
            content = await page.content()
            await browser.close()
            return content
        except Exception as e:
            print(f"Playwright 渲染失败: {e}")
            await browser.close()
            return ""

def match_nodes(text):
    proxy_pattern = r"\{[^}]*name\s*:\s*['\"][^'\"]+['\"][^}]*server\s*:\s*[^,]+[^}]*\}"
    nodes = re.findall(proxy_pattern, text, re.DOTALL)
    proxies_list = []
    for node in nodes:
        node_dict = yaml.safe_load(node)
        proxies_list.append(node_dict)
    yaml_data = {"proxies": proxies_list}
    return yaml_data

def process_url(url):
    isyaml = False
    try:
        response = requests.get(url, headers=headers, verify=False, allow_redirects=True)
        if response.status_code == 200:
            content = response.content.decode('utf-8')
            if 'proxies:' in content:
                if '</pre>' in content:
                    content = content.replace('<pre style="word-wrap: break-word; white-space: pre-wrap;">', '').replace('</pre>', '')
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
                except:
                    content = asyncio.run(js_render(url))
                    if 'external-controller' in content:
                        try:
                            yaml_data = yaml.safe_load(content)
                        except:
                            yaml_data = match_nodes(content)
                        if 'proxies' in yaml_data:
                            isyaml = True
                            return yaml_data['proxies'], isyaml
                    else:
                        pattern = r'([A-Za-z0-9_+/\-]+={0,2})'
                        matches = re.findall(pattern, content)
                        stdout = matches[-1] if matches else []
                        decoded_bytes = base64.b64decode(stdout)
                        decoded_content = decoded_bytes.decode('utf-8')
                        return decoded_content.splitlines(), isyaml
        else:
            print(f"Failed to retrieve data from {url}, status code: {response.status_code}")
            return [], isyaml
    except requests.RequestException as e:
        print(f"An error occurred while requesting {url}: {e}")
        return [], isyaml

def parse_proxy_link(link):
    try:
        if link.startswith(("hysteria2://", "hy2://")):
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
        return None

def deduplicate_proxies(proxies_list):
    unique_proxies = []
    seen = set()
    for proxy in proxies_list:
        key = (proxy['server'], proxy['port'], proxy['type'], proxy['password']) if proxy.get("password") else (
        proxy['server'], proxy['port'], proxy['type'])
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
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
            all_lines.extend(line.strip() for line in lines)
    if all_lines:
        print(f'加载【{folder_path}】目录下所有txt中节点')
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
            print(f"Error reading {file_path}: {str(e)}")
    if load_nodes:
        print(f'加载【{folder_path}】目录下yaml/yml中所有节点')
    return load_nodes

def filter_by_types_alt(allowed_types, nodes):
    return [x for x in nodes if x.get('type') in allowed_types]

def merge_lists(*lists):
    return [item for item in chain.from_iterable(lists) if item != '']

def handle_links(new_links, resolve_name_conflicts):
    try:
        for new_link in new_links:
            if new_link.startswith(("hysteria2://", "hy2://", "trojan://", "ss://", "vless://", "vmess://")):
                node = parse_proxy_link(new_link)
                if node:
                    resolve_name_conflicts(node)
            else:
                print(f"跳过无效或不支持的链接: {new_link}")
    except Exception as e:
        pass

def generate_clash_config(links, load_nodes):
    now = datetime.now()
    print(f"当前时间: {now}\n---")
    final_nodes = []
    existing_names = set()
    config = clash_config_template.copy()

    def resolve_name_conflicts(node):
        server = node.get("server")
        if not server:
            return
        name = str(node["name"])
        if not_contains(name, server):
            if name in existing_names:
                name = add_random_suffix(name, existing_names)
            existing_names.add(name)
            node["name"] = name
            final_nodes.append(node)

    for node in load_nodes:
        resolve_name_conflicts(node)

    for link in links:
        if link.startswith(("hysteria2://", "hy2://", "trojan://", "ss://", "vless://", "vmess://")):
            node = parse_proxy_link(link)
            if not node:
                continue
            resolve_name_conflicts(node)
        else:
            if '|links' in link or '.md' in link:
                link = link.replace('|links', '')
                new_links = parse_md_link(link)
                handle_links(new_links, resolve_name_conflicts)
            if '|ss' in link:
                link = link.replace('|ss', '')
                new_links = parse_ss_sub(link)
                for node in new_links:
                    resolve_name_conflicts(node)
            if '{' in link:
                link = resolve_template_url(link)
            print(f'当前正在处理link: {link}')
            try:
                new_links, isyaml = process_url(link)
            except Exception as e:
                print(f"error: {e}")
                continue
            if isyaml:
                for node in new_links:
                    resolve_name_conflicts(node)
            else:
                handle_links(new_links, resolve_name_conflicts)
    final_nodes = deduplicate_proxies(final_nodes)
    config["proxy-groups"][1]["proxies"] = []
    for node in final_nodes:
        name = str(node["name"])
        if not_contains(name, node["server"]):
            config["proxy-groups"][1]["proxies"].append(name)
            proxies = list(set(config["proxy-groups"][1]["proxies"]))
            config["proxy-groups"][1]["proxies"] = proxies
            config["proxy-groups"][2]["proxies"] = proxies
            config["proxy-groups"][3]["proxies"] = proxies
    config["proxies"] = final_nodes

    if config["proxies"]:
        global CONFIG_FILE
        CONFIG_FILE = CONFIG_FILE[:-5] if CONFIG_FILE.endswith('.json') else CONFIG_FILE
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            yaml.dump(config, f, allow_unicode=True, default_flow_style=False)
        with open(f'{CONFIG_FILE}.json', "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False)
        print(f"已经生成Clash配置文件{CONFIG_FILE}|{CONFIG_FILE}.json")
    else:
        print('没有节点数据更新')

def not_contains(name, server=None):
    try:
        if any(k in name for k in BAN):
            return False
        if server and os.path.exists(GEOIP_DB_PATH):
            try:
                ip_address = socket.gethostbyname(server)
            except (socket.gaierror, ValueError):
                # 如果无法解析为主机名，或者不是有效的IP，则跳过GeoIP检查
                return True
            with GeoIPReader(GEOIP_DB_PATH) as reader:
                response = reader.country(ip_address)
                if response.country.iso_code == "CN":
                    return False
        return True
    except Exception as e:
        print(f"GeoIP 过滤错误: {e}")
        return not any(k in name for k in BAN)

class ClashAPIException(Exception):
    pass

class ProxyTestResult:
    def __init__(self, name: str, delays: List[Optional[float]] = None):
        self.name = name
        self.delays = delays if delays is not None else []
        valid_delays = [d for d in self.delays if d is not None]
        self.success_rate = len(valid_delays) / len(self.delays) if self.delays else 0
        self.average_delay = sum(valid_delays) / len(valid_delays) if valid_delays else float('inf')
        self.std_dev = statistics.stdev(valid_delays) if len(valid_delays) > 1 else 0
        self.status = "ok" if self.is_valid else "fail"
        self.tested_time = datetime.now()

    @property
    def is_valid(self) -> bool:
        return self.success_rate >= MIN_SUCCESS_RATE and self.std_dev <= MAX_STD_DEV

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
        proxies.remove(problem_proxy_name)
        for group in config["proxy-groups"][1:]:
            group["proxies"] = proxies
        with open(config_file_path, 'w', encoding='utf-8') as file:
            file.write(json.dumps(config, ensure_ascii=False))
        print(f'配置异常：{error_message}修复配置异常，移除proxy[{problem_index}] {problem_proxy_name} 完毕，耗时{time.time() - start_time}s\n')
        return True
    except Exception as e:
        print(f"处理配置文件时出错: {str(e)}")
        return False

def download_and_extract_latest_release():
    url = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
    response = requests.get(url)
    if response.status_code != 200:
        print("Failed to retrieve data")
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
        return
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
        print(f"正在下载最新 Clash 核心: {download_url}")
        response = requests.get(download_url, stream=True)
        if response.status_code == 200:
            if os_type == "windows":
                with open("clash.zip", "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                with zipfile.ZipFile("clash.zip", "r") as zip_ref:
                    zip_ref.extractall()
                os.remove("clash.zip")
                for file in os.listdir():
                    if targets["windows"] in file:
                        os.rename(file, new_name)
                        break
            else:
                with open("clash.gz", "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        f.write(chunk)
                with gzip.open("clash.gz", "rb") as f_in:
                    with open(new_name, "wb") as f_out:
                        shutil.copyfileobj(f_in, f_out)
                os.remove("clash.gz")
            ensure_executable(new_name)
            print(f"已下载并解压 Clash 核心到: {new_name}")
        else:
            print(f"下载失败，状态码: {response.status_code}")

def start_clash():
    download_and_extract_latest_release()
    os_type = platform.system().lower()
    clash_binary = f"clash-{os_type}" if os_type != "windows" else "clash.exe"
    if not os.path.exists(clash_binary):
        print(f"未找到 Clash 可执行文件: {clash_binary}")
        sys.exit(1)
    global CONFIG_FILE
    config_file = CONFIG_FILE
    if not os.path.exists(config_file):
        config_file = f'{CONFIG_FILE}.json'
    if not os.path.exists(config_file):
        print(f"未找到配置文件: {config_file}")
        sys.exit(1)
    for proc in psutil.process_iter(['name']):
        if proc.info['name'].startswith('clash'):
            proc.kill()
            time.sleep(1)
    cmd = [f"./{clash_binary}", "-f", config_file]
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding='utf-8'
    )
    time.sleep(2)
    if process.poll() is not None:
        stdout, stderr = process.communicate()
        if "Fatal error" in stderr:
            if handle_clash_error(stderr, config_file):
                process = subprocess.Popen(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    encoding='utf-8'
                )
                time.sleep(2)
                if process.poll() is not None:
                    stdout, stderr = process.communicate()
                    print(f"Clash 启动失败: {stderr}")
                    sys.exit(1)
            else:
                print(f"Clash 启动失败: {stderr}")
                sys.exit(1)
    for port in CLASH_API_PORTS:
        try:
            response = requests.get(f"http://{CLASH_API_HOST}:{port}/version", timeout=2)
            if response.status_code == 200:
                print(f"Clash API 在端口 {port} 上运行正常")
                break
        except requests.RequestException:
            print(f"Clash API 端口 {port} 不可达")
            if port == CLASH_API_PORTS[-1]:
                print("所有 Clash API 端口均不可达，启动失败")
                sys.exit(1)
    return process

def switch_proxy(proxy_name):
    with switch_lock:
        max_retries = 3
        for attempt in range(max_retries):
            for port in CLASH_API_PORTS:
                try:
                    url = f"http://{CLASH_API_HOST}:{port}/proxies/节点选择"
                    headers = {"Authorization": f"Bearer {CLASH_API_SECRET}"} if CLASH_API_SECRET else {}
                    data = {"name": urllib.parse.quote(proxy_name, safe='')}
                    response = requests.put(url, headers=headers, json=data, timeout=TIMEOUT)
                    response.raise_for_status()
                    print(f"成功切换到代理节点: {proxy_name}")
                    return True
                except requests.RequestException as e:
                    print(f"切换代理节点 {proxy_name} 失败 (尝试 {attempt + 1}/{max_retries}): {e}")
                    if isinstance(e, requests.HTTPError) and e.response:
                        print(f"响应内容: {e.response.text}")
                    time.sleep(1)
            if attempt < max_retries - 1:
                print(f"重试切换代理节点 {proxy_name}")
        return False

class ClashAPI:
    def __init__(self, host: str, ports: List[int], secret: str = ""):
        self.host = host
        self.ports = ports
        self.secret = secret
        self.base_url = None
        self.client = httpx.AsyncClient(verify=False)
        self.semaphore = Semaphore(MAX_CONCURRENT_TESTS)
        self.headers = {"Authorization": f"Bearer {secret}"} if secret else {}
        self._test_results_cache = {}

    async def __aenter__(self):
        for port in self.ports:
            base_url = f"http://{self.host}:{port}"
            if await self.check_connection(base_url):
                self.base_url = base_url
                break
        if not self.base_url:
            raise ClashAPIException("无法连接到任何 Clash API 端口")
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()

    async def check_connection(self, base_url: str = None) -> bool:
        base_url = base_url or self.base_url
        if not base_url:
            return False
        try:
            response = await self.client.get(f"{base_url}/version", headers=self.headers, timeout=TIMEOUT)
            response.raise_for_status()
            print(f"成功连接到 Clash API: {base_url}")
            return True
        except httpx.HTTPStatusError as e:
            print(f"HTTP 错误: {e}")
            return False
        except httpx.RequestError as e:
            print(f"请求错误: {e}")
            return False

    async def test_proxy_delay(self, proxy_name: str, secondary_test: bool = False) -> ProxyTestResult:
        if not self.base_url:
            raise ClashAPIException("未建立与 Clash API 的连接")
        cache_key = f"{proxy_name}_{'secondary' if secondary_test else 'primary'}"
        if cache_key in self._test_results_cache:
            cached_result = self._test_results_cache[cache_key]
            if (datetime.now() - cached_result.tested_time).total_seconds() < 60:
                return cached_result
        async with self.semaphore:
            delays = []
            for _ in range(STABILITY_TESTS):
                try:
                    test_url = SECONDARY_TEST_URL if secondary_test else TEST_URL
                    response = await self.client.get(
                        f"{self.base_url}/proxies/{urllib.parse.quote(proxy_name, safe='')}/delay",
                        headers=self.headers,
                        params={"url": test_url, "timeout": int(TIMEOUT * 1000)}
                    )
                    response.raise_for_status()
                    delay = response.json().get("delay")
                    delays.append(delay)
                except httpx.HTTPError:
                    delays.append(None)
                except Exception as e:
                    delays.append(None)
                if _ < STABILITY_TESTS - 1:
                    await asyncio.sleep(STABILITY_INTERVAL)
            result = ProxyTestResult(proxy_name, delays)
            self._test_results_cache[cache_key] = result
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
            print(f"找不到配置文件: {self.config_path}")
            sys.exit(1)
        except yaml.YAMLError as e:
            print(f"配置文件格式错误: {e}")
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
            valid_proxies = [p for p in self.config["proxies"]
                             if p.get("name") not in invalid_proxies]
            self.config["proxies"] = valid_proxies
        for group in self.proxy_groups:
            if "proxies" in group:
                group["proxies"] = [p for p in group["proxies"] if p not in invalid_proxies]
        global LIMIT
        left = LIMIT if len(self.config['proxies']) > LIMIT else len(self.config['proxies'])
        print(f"已从配置中移除 {len(invalid_proxies)} 个失效节点，最终保留{left}个延迟最小的节点")

    def keep_proxies_by_limit(self, proxy_names):
        if "proxies" in self.config:
            self.config["proxies"] = [p for p in self.config["proxies"] if p["name"] in proxy_names]

    def update_group_proxies(self, group_name: str, results: List[ProxyTestResult]):
        self.remove_invalid_proxies(results)
        valid_results = [r for r in results if r.is_valid]
        valid_results = list(set(valid_results))
        valid_results.sort(key=lambda x: x.average_delay)
        proxy_names = [r.name for r in valid_results]
        for group in self.proxy_groups:
            if group["name"] == group_name:
                group["proxies"] = proxy_names
                break
        return proxy_names

    def update_proxies_names(self, name_mapping: Dict[str, str]):
        if "proxies" in self.config:
            for proxy in self.config["proxies"]:
                if proxy["name"] in name_mapping:
                    proxy["name"] = name_mapping[proxy["name"]]
        for group in self.proxy_groups:
            if "proxies" in group:
                group["proxies"] = [name_mapping.get(p, p) for p in group["proxies"]]

    def save(self):
        try:
            yaml_cfg = self.config_path.strip('.json') if self.config_path.endswith('.json') else self.config_path
            with open(yaml_cfg, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, allow_unicode=True, sort_keys=False)
            with open(f'{yaml_cfg}.json', "w", encoding="utf-8") as f:
                json.dump(self.config, f, ensure_ascii=False)
        except Exception as e:
            print(f"保存配置文件失败: {e}")
            sys.exit(1)

def print_test_summary(group_name: str, results: List[ProxyTestResult], test_type: str = "Primary"):
    valid_results = [r for r in results if r.is_valid]
    invalid_results = [r for r in results if not r.is_valid]
    total = len(results)
    valid = len(valid_results)
    invalid = len(invalid_results)
    print(f"\n策略组 '{group_name}' {test_type} 测试结果:")
    print(f"总节点数: {total}")
    print(f"可用节点数: {valid}")
    print(f"失效节点数: {invalid}")
    delays = []
    if valid > 0:
        avg_delay = sum(r.average_delay for r in valid_results) / valid
        avg_std_dev = sum(r.std_dev for r in valid_results) / valid
        avg_success_rate = sum(r.success_rate * 100 for r in valid_results) / valid
        print(f"平均延迟: {avg_delay:.2f}ms")
        print(f"平均标准差: {avg_std_dev:.2f}ms (波动性)")
        print(f"平均成功率: {avg_success_rate:.2f}%")
        print(f"\n{test_type} 节点延迟统计 (按平均延迟排序):")
        sorted_results = sorted(valid_results, key=lambda x: x.average_delay)
        for i, result in enumerate(sorted_results[:LIMIT], 1):
            delays.append({"name": result.name, "Avg_Delay_ms": round(result.average_delay, 2), "Std_Dev": round(result.std_dev, 2), "Success_Rate": round(result.success_rate * 100, 2)})
            print(f"{i}. {result.name}: 平均 {result.average_delay:.2f}ms, 标准差 {result.std_dev:.2f}ms, 成功率 {result.success_rate * 100:.2f}%")
    return delays

async def test_group_proxies(clash_api: ClashAPI, proxies: List[str], secondary_test: bool = False) -> List[ProxyTestResult]:
    test_type = "Secondary" if secondary_test else "Primary"
    print(f"开始{test_type}测试 {len(proxies)} 个节点 (最大并发: {MAX_CONCURRENT_TESTS})")
    tasks = [clash_api.test_proxy_delay(proxy_name, secondary_test=secondary_test) for proxy_name in proxies]
    results = []
    for future in asyncio.as_completed(tasks):
        result = await future
        results.append(result)
        done = len(results)
        total = len(tasks)
        print(f"\r{test_type} 测试进度: {done}/{total} ({done / total * 100:.1f}%)", end="", flush=True)
    print()
    return results

async def proxy_clean():
    delays = []
    global MAX_CONCURRENT_TESTS, TIMEOUT, CLASH_API_SECRET, LIMIT, CONFIG_FILE
    CONFIG_FILE = f'{CONFIG_FILE}.json' if os.path.exists(f'{CONFIG_FILE}.json') else CONFIG_FILE
    print(f"===================节点批量检测基本信息======================")
    print(f"配置文件: {CONFIG_FILE}")
    print(f"API 端口: {CLASH_API_PORTS[0]}")
    print(f"并发数量: {MAX_CONCURRENT_TESTS}")
    print(f"超时时间: {TIMEOUT}秒")
    print(f"保留节点：最多保留{LIMIT}个延迟最小的有效节点")
    print(f'加载配置文件{CONFIG_FILE}')
    config = ClashConfig(CONFIG_FILE)
    available_groups = config.get_group_names()[1:]
    groups_to_test = available_groups
    invalid_groups = set(groups_to_test) - set(available_groups)
    if invalid_groups:
        print(f"警告: 以下策略组不存在: {', '.join(invalid_groups)}")
        groups_to_test = list(set(groups_to_test) & set(available_groups))
    if not groups_to_test:
        print("错误: 没有找到要测试的有效策略组")
        print(f"可用的策略组: {', '.join(available_groups)}")
        return
    print(f"\n将测试以下策略组: {', '.join(groups_to_test)}")
    start_time = datetime.now()
    async with ClashAPI(CLASH_API_HOST, CLASH_API_PORTS, CLASH_API_SECRET) as clash_api:
        if not await clash_api.check_connection():
            return
        try:
            all_test_results = []
            group_name = groups_to_test[0]
            print(f"\n======================== 开始 Primary 测试策略组: {group_name} ====================")
            proxies = config.get_group_proxies(group_name)
            if not proxies:
                print(f"策略组 '{group_name}' 中没有代理节点")
                return
            primary_results = await test_group_proxies(clash_api, proxies, secondary_test=False)
            all_test_results.extend(primary_results)
            delays = print_test_summary(group_name, primary_results, test_type="Primary")
            valid_proxies = [r.name for r in primary_results if r.is_valid]
            if not valid_proxies:
                print(f"没有节点通过 Primary 测试，停止后续测试")
                return
            print(f"\n======================== 开始 Secondary 测试策略组: {group_name} ====================")
            secondary_results = await test_group_proxies(clash_api, valid_proxies, secondary_test=True)
            all_test_results.extend(secondary_results)
            secondary_delays = print_test_summary(group_name, secondary_results, test_type="Secondary")
            valid_proxies = [r.name for r in secondary_results if r.is_valid]
            if not valid_proxies:
                print(f"没有节点通过 Secondary 测试，停止后续测试")
                return
            print('\n===================移除失效节点并按延迟排序======================\n')
            config.remove_invalid_proxies(all_test_results)
            proxy_names = set()
            group_proxies = config.get_group_proxies(group_name)
            group_results = [r for r in secondary_results if r.name in group_proxies and r.is_valid]
            if LIMIT:
                group_results = group_results[:LIMIT]
            for r in group_results:
                proxy_names.add(r.name)
            for group_name in groups_to_test:
                proxy_names = config.update_group_proxies(group_name, group_results)
                print(f"'{group_name}'已按延迟大小重新排序")
            if LIMIT:
                config.keep_proxies_by_limit(proxy_names)
            config.save()
            if SPEED_TEST:
                print('\n===================检测节点速度======================\n')
                name_mapping = start_download_test(proxy_names, speed_limit=0.1)
                config.update_proxies_names(name_mapping)
                config.save()
            total_time = (datetime.now() - start_time).total_seconds()
            print(f"\n总耗时: {total_time:.2f} 秒")
            return delays
        except ClashAPIException as e:
            print(f"Clash API 错误: {e}")
        except Exception as e:
            print(f"发生错误: {e}")
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
    match = re.match(r'https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/[^/]+/[^/]+/([^/]+)', github_url)
    if not match:
        raise ValueError("无法从URL中提取owner和repo信息")
    owner, repo, branch = match.groups()
    path_part = github_url.split(f'/refs/heads/{branch}/')[-1]
    path_part = re.sub(r'\{x\}' + re.escape(file_suffix) + '(?:/|$)', '', path_part)
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path_part}"
    response = requests.get(api_url)
    if response.status_code != 200:
        raise Exception(f"GitHub API请求失败: {response.status_code} {response.text}")
    files = response.json()
    matching_files = [f['name'] for f in files if f['name'].endswith(file_suffix)]
    if not matching_files:
        raise Exception(f"未找到匹配的{file_suffix}文件")
    return matching_files[0]

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

def load_speed_cache():
    cache_file = "speed_cache.json"
    cache = {}
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'r', encoding='utf-8') as f:
                cache = json.load(f)
        except:
            pass
    return cache

def save_speed_cache(cache):
    cache_file = "speed_cache.json"
    try:
        with open(cache_file, 'w', encoding='utf-8') as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"保存速度缓存失败: {e}")

def start_download_test(proxy_names, speed_limit=0.1):
    test_all_proxies(proxy_names[:SPEED_TEST_LIMIT])
    filtered_list = [item for item in results_speed if float(item[1]) >= float(f'{speed_limit}')]
    sorted_proxy_names = []
    name_mapping = {}
    sorted_list = sorted(filtered_list, key=lambda x: float(x[1]), reverse=True)
    print(f'节点速度统计:')
    for i, (proxy_name, speed) in enumerate(sorted_list[:LIMIT], 1):
        base_name = re.sub(r'(_\d+\.\d+Mb/s)+$', '', proxy_name)
        new_name = f"{base_name}_{speed}Mb/s"
        sorted_proxy_names.append(new_name)
        name_mapping[proxy_name] = new_name
        print(f"{i}. {new_name}: {speed}Mb/s")
    added_elements = set(sorted_proxy_names)
    for item in proxy_names:
        if item not in [x[0] for x in sorted_list]:
            if item not in added_elements:
                sorted_proxy_names.append(item)
                name_mapping[item] = item
                added_elements.add(item)
    return name_mapping

def test_all_proxies(proxy_names):
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_CONCURRENT_TESTS) as executor:
            futures = [executor.submit(test_proxy_speed, proxy_name) for proxy_name in proxy_names]
            for i, future in enumerate(concurrent.futures.as_completed(futures), 1):
                try:
                    future.result()
                    print(f"\r测速进度: {i}/{len(proxy_names)} ({i / len(proxy_names) * 100:.1f}%)", end="", flush=True)
                except Exception as e:
                    print(f"\n测速任务出错: {e}")
        print("\r" + " " * 50 + "\r", end='')
    except Exception as e:
        print(f"测试节点速度时出错: {e}")

def test_proxy_speed(proxy_name):
    cache = load_speed_cache()
    cache_key = proxy_name
    if cache_key in cache:
        cached = cache[cache_key]
        if (datetime.now() - datetime.fromisoformat(cached['timestamp'])).total_seconds() < 24 * 3600:
            speed = cached['speed']
            results_speed.append((proxy_name, f"{speed:.2f}"))
            print(f"\r正在测速节点: {proxy_name} (缓存: {speed:.2f}Mb/s)", flush=True, end='')
            return speed
    if not switch_proxy(proxy_name):
        print(f"\n节点 {proxy_name} 切换失败，跳过速度测试")
        return 0
    proxies = {
        "http": 'http://127.0.0.1:7890',
        "https": 'http://127.0.0.1:7890',
    }
    start_time = time.time()
    total_length = 0
    test_duration = 10
    max_retries = 3
    retry_count = 0
    with httpx.Client(proxies=proxies, verify=False) as client:
        while retry_count < max_retries:
            try:
                response = client.get(SPEED_TEST_URL, headers={'Cache-Control': 'no-cache'}, timeout=test_duration)
                for data in response.iter_bytes(chunk_size=524288):
                    total_length += len(data)
                    if time.time() - start_time >= test_duration:
                        break
                break
            except (httpx.RequestError, httpx.TimeoutException) as e:
                retry_count += 1
                print(f"\n测试节点 {proxy_name} 下载失败 (重试 {retry_count}/{max_retries}): {e}")
                if retry_count == max_retries:
                    print(f"节点 {proxy_name} 测试失败，跳过")
                    return 0
                time.sleep(1)
    elapsed_time = time.time() - start_time
    speed = total_length / elapsed_time / 1024 / 1024 if elapsed_time > 0 else 0
    results_speed.append((proxy_name, f"{speed:.2f}"))
    cache[cache_key] = {"speed": speed, "timestamp": datetime.now().isoformat()}
    save_speed_cache(cache)
    print(f"\r正在测速节点: {proxy_name} ({speed:.2f}Mb/s)", flush=True, end='')
    return speed

def upload_and_generate_urls(file_path=CONFIG_FILE):
    result = {"clash_url": None, "singbox_url": None}
    try:
        if not os.path.isfile(file_path):
            print(f"错误：文件 {file_path} 不存在。")
            return result
        if os.path.getsize(file_path) > 209715200:
            print("错误：文件大小超过 200MB 限制。")
            return result
        subs_file = "subs.json"
        try:
            subs_data = {"clash": [], "singbox": []}
            if os.path.exists(subs_file):
                try:
                    with open(subs_file, 'r', encoding='utf-8') as f:
                        subs_data = json.load(f)
                except:
                    pass
            with open(subs_file, 'w', encoding='utf-8') as f:
                json.dump(subs_data, f, ensure_ascii=False, indent=2)
            print(f"已将订阅链接记录到 {subs_file}")
        except Exception as e:
            print(f"记录订阅链接失败: {str(e)}")
    except Exception as e:
        print(f"发生错误：{e}")
    return result

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
                print(f"===================启动clash并初始化配置======================")
                clash_process = start_clash()
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
        "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/link_cleaned.yaml"
    ]
    work(links, check=True, only_check=False, allowed_types=["ss", "hysteria2", "hy2", "vless", "vmess", "trojan"])
