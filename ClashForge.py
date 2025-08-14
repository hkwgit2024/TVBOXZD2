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
results_speed = []
MAX_CONCURRENT_TESTS = 100
LIMIT = 1086 # 最多保留LIMIT个节点
CONFIG_FILE = 'clash_config.yaml'
# 从文件中加载代理节点，支持yaml/yml、txt(每条代理链接占一行)
# INPUT = os.getenv("INPUT", "input")
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
        "DOMAIN,app.adjust.com,DIRECT",
        "GEOIP,CN,DIRECT",
        "MATCH,节点选择"
    ]
}

# 解析 Hysteria2 链接
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

# 解析 Shadowsocks 链接
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

# 解析 Trojan 链接
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

# 解析 VLESS 链接
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
        "sni": urllib.parse.parse_qs(query).get("sni", [""])[0],
        "skip-cert-verify": urllib.parse.parse_qs(query).get("skip-cert-verify", ["false"])[0] == "true",
        "network": urllib.parse.parse_qs(query).get("type", ["tcp"])[0],
        "ws-opts": {
            "path": urllib.parse.parse_qs(query).get("path", [""])[0],
            "headers": {
                "Host": urllib.parse.parse_qs(query).get("host", [""])[0]
            }
        } if urllib.parse.parse_qs(query).get("type", ["tcp"])[0] == "ws" else {}
    }

# 解析 VMESS 链接
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

# 解析ss订阅源
def parse_ss_sub(link):
    new_links = []
    try:
        # 发送请求并获取内容
        response = requests.get(link, headers=headers, verify=False, allow_redirects=True)
        if response.status_code == 200:
            data = response.json()
            new_links = [{"name": x['remarks'], "type": "ss", "server": x['server'], "port": x['server_port'], "cipher": x['method'],"password": x['password'], "udp": True} for x in data]
            return new_links
    except requests.RequestException as e:
        print(f"请求错误: {e}")
        return new_links

def parse_md_link(link):
    try:
        # 发送请求并获取内容
        response = requests.get(link)
        response.raise_for_status()  # 检查请求是否成功
        content = response.text
        content = urllib.parse.unquote(content)
        # 定义正则表达式模式，匹配所需的协议链接
        pattern = r'(?:vless|vmess|trojan|hysteria2|ss):\/\/[^#\s]*(?:#[^\s]*)?'

        # 使用re.findall()提取所有匹配的链接
        matches = re.findall(pattern, content)
        return matches

    except requests.RequestException as e:
        print(f"请求错误: {e}")
        return []

# js渲染页面
def js_render(url):
    timeout = 4
    if timeout > 15:
        timeout = 15
    browser_args = ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--disable-software-rasterizer','--disable-setuid-sandbox']
    session = HTMLSession(browser_args=browser_args)
    r = session.get(f'{url}', headers=headers, timeout=timeout, verify=False)
    # 等待页面加载完成，Requests-HTML 会自动等待 JavaScript 执行完成
    r.html.render(timeout=timeout)
    return r

# je_render返回的text没有缩进，通过正则表达式匹配proxies下的所有代理节点
def match_nodes(text):
    proxy_pattern = r"\{[^}]*name\s*:\s*['\"][^'\"]+['\"][^}]*server\s*:\s*[^,]+[^}]*\}"
    nodes = re.findall(proxy_pattern, text, re.DOTALL)

    # 将每个节点字符串转换为字典
    proxies_list = []
    for node in nodes:
        # 使用yaml.safe_load来加载每个节点
        node_dict = yaml.safe_load(node)
        proxies_list.append(node_dict)

    yaml_data = {"proxies": proxies_list}
    return yaml_data

# link非代理协议时(https)，请求url解析
def process_url(url):
    isyaml = False
    try:
        # 发送GET请求
        response = requests.get(url, headers=headers, verify=False, allow_redirects=True)
        # 确保响应状态码为200
        if response.status_code == 200:
            content = response.content.decode('utf-8')
            if 'proxies:' in content:
                if '</pre>' in content:
                    content = content.replace('<pre style="word-wrap: break-word; white-space: pre-wrap;">','').replace('</pre>','')
                # YAML格式
                yaml_data = yaml.safe_load(content)
                if 'proxies' in yaml_data:
                    isyaml = True
                    proxies = yaml_data['proxies'] if yaml_data['proxies'] else []
                    return proxies,isyaml
            else:
                # 尝试Base64解码
                try:
                    decoded_bytes = base64.b64decode(content)
                    decoded_content = decoded_bytes.decode('utf-8')
                    decoded_content = urllib.parse.unquote(decoded_content)
                    return decoded_content.splitlines(),isyaml
                except Exception as e:
                    try:
                        res = js_render(url)
                        if 'external-controller' in res.html.text:
                            # YAML格式
                            try:
                                yaml_data = yaml.safe_load(res.html.text)
                            except Exception as e:
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
                        # 如果不是Base64编码，直接按行处理
                        return [],isyaml
        else:
            print(f"Failed to retrieve data from {url}, status code: {response.status_code}")
            return [],isyaml
    except requests.RequestException as e:
        print(f"An error occurred while requesting {url}: {e}")
        return [],isyaml

# 解析不同的代理链接
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
        return None

# 根据server和port共同约束去重
def deduplicate_proxies(proxies_list):
    unique_proxies = []
    seen = set()
    for proxy in proxies_list:
        key = (proxy['server'], proxy['port'], proxy['type'], proxy['password']) if proxy.get("password") else (proxy['server'], proxy['port'], proxy['type'])
        if key not in seen:
            seen.add(key)
            unique_proxies.append(proxy)
    return unique_proxies

# 出现节点name相同时，加上4位随机字符串
def add_random_suffix(name, existing_names):
    # 生成4位随机字符串
    suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
    new_name = f"{name}-{suffix}"
    # 确保生成的新名字不在已存在的名字列表中
    while new_name in existing_names:
        suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
        new_name = f"{name}-{suffix}"
    return new_name

# 从指定目录下的txt读取代理链接
def read_txt_files(folder_path):
    all_lines = []  # 用于存储所有文件的行

    # 使用 glob 获取指定文件夹下的所有 txt 文件
    txt_files = glob.glob(os.path.join(folder_path, '*.txt'))

    for file_path in txt_files:
        with open(file_path, 'r', encoding='utf-8') as file:
            # 读取文件内容并按行存入数组
            lines = file.readlines()
            all_lines.extend(line.strip() for line in lines)  # 去除每行的换行符并添加到数组中
    if all_lines:
        print(f'加载【{folder_path}】目录下所有txt中节点')
    return all_lines

# 从指定目录下的yaml/yml读取proxies
def read_yaml_files(folder_path):
    load_nodes = []
    # 使用 glob 获取指定文件夹下的所有 yaml/yml 文件
    yaml_files = glob.glob(os.path.join(folder_path, '*.yaml'))
    yaml_files.extend(glob.glob(os.path.join(folder_path, '*.yml')))

    for file_path in yaml_files:
        try:
            with open(file_path, 'r', encoding='utf-8') as file:
                # 读取并解析yaml文件
                config = yaml.safe_load(file)
                # 如果存在proxies字段，添加到nodes列表
                if config and 'proxies' in config:
                    load_nodes.extend(config['proxies'])
        except Exception as e:
            print(f"Error reading {file_path}: {str(e)}")
    if load_nodes:
        print(f'加载【{folder_path}】目录下yaml/yml中所有节点')
    return load_nodes

# 进行type过滤
def filter_by_types_alt(allowed_types,nodes):
    # 进行过滤
    return [x for x in nodes if x.get('type') in allowed_types]

# 合并links列表
def merge_lists(*lists):
    return [item for item in chain.from_iterable(lists) if item != '']


def handle_links(new_links,resolve_name_conflicts):
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

# 生成 Clash 配置文件
def generate_clash_config(links,load_nodes):
    now = datetime.now()
    print(f"当前时间: {now}\n---")

    final_nodes = []
    existing_names = set()  # 存储所有节点名字以检查重复
    config = clash_config_template.copy()


    # 名称已存在的节点加随机后缀
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

    for node in load_nodes:
        resolve_name_conflicts(node)


    for link in links:
        if link.startswith(("hysteria2://", "hy2://","trojan://", "ss://", "vless://", "vmess://")):
            node = parse_proxy_link(link)
            if not node:
                continue
            resolve_name_conflicts(node)
        else:
            if '|links' in link or '.md' in link:
                link = link.replace('|links', '')
                new_links = parse_md_link(link)
                handle_links(new_links,resolve_name_conflicts)
            if '|ss' in link:
                link = link.replace('|ss', '')
                new_links = parse_ss_sub(link)
                for node in new_links:
                    resolve_name_conflicts(node)
            if '{' in link:
                link = resolve_template_url(link)
            print(f'当前正在处理link: {link}')
            # 处理非特定协议的链接
            try:
                new_links,isyaml = process_url(link)
            except Exception as e:
                print(f"error: {e}")
                continue
            if isyaml:
                for node in new_links:
                    resolve_name_conflicts(node)
            else:
                handle_links(new_links, resolve_name_conflicts)
    final_nodes = deduplicate_proxies(final_nodes)
    # 重置group中节点name
    config["proxy-groups"][1]["proxies"] = []
    for node in final_nodes:
        name = str(node["name"])
        if not_contains(name):
            # 0节点选择 1 自动选择 2故障转移 3手动选择
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
            json.dump(config,f,ensure_ascii=False)
        print(f"已经生成Clash配置文件{CONFIG_FILE}|{CONFIG_FILE}.json")
    else:
        print('没有节点数据更新')

# 判断不包含
def not_contains(s):
    return not any(k in s for k in BAN)

# 自定义 Clash API 异常
class ClashAPIException(Exception):
    """自定义 Clash API 异常"""
    pass

# 代理测试结果类
class ProxyTestResult:
    """代理测试结果类"""

    def __init__(self, name: str, delay: Optional[float] = None):
        self.name = name
        self.delay = delay if delay is not None else float('inf')
        self.status = "ok" if delay is not None else "fail"
        self.tested_time = datetime.now()

    @property
    def is_valid(self) -> bool:
        return self.status == "ok"

def ensure_executable(file_path):
    """ 确保文件具有可执行权限（仅适用于 Linux 和 macOS） """
    if platform.system().lower() in ['linux', 'darwin']:
        os.chmod(file_path, 0o755)  # 设置文件为可执行

# 处理 Clash 配置错误，解析错误信息并更新配置文件
def handle_clash_error(error_message, config_file_path):
    start_time = time.time()
    config_file_path = f'{config_file_path}.json' if os.path.exists(f'{config_file_path}.json') else config_file_path

    proxy_index_match = re.search(r'proxy (\d+):', error_message)
    if not proxy_index_match:
        return False

    problem_index = int(proxy_index_match.group(1))

    try:
        # 读取配置文件
        with open(config_file_path, 'r', encoding='utf-8') as file:
            config = json.load(file)

        # 获取要删除的节点的name
        problem_proxy_name = config['proxies'][problem_index]['name']
        # 删除问题节点
        del config['proxies'][problem_index]

        # 从所有proxy-groups中删除该节点引用
        proxies = config['proxy-groups'][1]["proxies"]
        proxies.remove(problem_proxy_name)
        for group in config["proxy-groups"][1:]:
            group["proxies"] = proxies

        # 保存更新后的配置
        with open(config_file_path, 'w', encoding='utf-8') as file:
            file.write(json.dumps(config,ensure_ascii=False))

        print(f'配置异常：{error_message}修复配置异常，移除proxy[{problem_index}] {problem_proxy_name} 完毕，耗时{time.time() - start_time}s\n')
        return True

    except Exception as e:
        print(f"处理配置文件时出错: {str(e)}")
        return False

# 下载最新mihomo
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

    # 确定下载链接和新名称
    download_url = None
    new_name = f"clash-{os_type}" if os_type != "windows" else "clash.exe"

    # 检查是否已存在二进制文件
    if os.path.exists(new_name):
        return

    for asset in assets:
        name = asset.get("name", "")
        # 根据操作系统确定下载文件的名称和后缀
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
        download_url = f"{download_url}"
        print(f"Downloading file from {download_url}")
        filename = download_url.split('/')[-1]
        response = requests.get(download_url)

        # 保存下载的文件
        with open(filename, 'wb') as f:
            f.write(response.content)

        # 解压文件并重命名
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

        # 重命名并删除下载的文件
        for file_name in extracted_files:
            if os.path.exists(file_name):
                os.rename(file_name, new_name)
                break

        os.remove(filename)  # 删除下载的压缩文件
    else:
        print("No suitable release found for the current operating system.")

def read_output(pipe, output_lines):
    while True:
        line = pipe.readline()
        if line:
            output_lines.append(line)
        else:
            break

def kill_clash():
    """
    在 macOS、Linux 和 Windows 上强制杀掉 Clash 进程。
    支持配置文件：clash_config.yaml 和 clash_config.yaml.json
    """
    # 根据操作系统定义 Clash 进程名
    system = platform.system()
    clash_process_names = {
        "Windows": "clash.exe",
        "Linux": "clash-linux",
        "Darwin": "clash-darwin"  # macOS
    }
    config_files = ["clash_config.yaml", "clash_config.yaml.json"]
    
    # 检查是否支持当前操作系统
    if system not in clash_process_names:
        print("不支持的操作系统")
        return
    
    # 获取当前系统的 Clash 进程名
    process_name = clash_process_names[system]
    
    # 遍历所有进程，查找并终止 Clash 进程
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            # 如果进程名不匹配，跳过
            if proc.info['name'] != process_name:
                continue
            
            # 获取命令行参数并检查配置文件
            cmdline = proc.info['cmdline']
            if cmdline and len(cmdline) >= 3 and cmdline[1] == '-f' and cmdline[2] in config_files:
                # 强制终止进程
                proc.kill()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # 忽略进程不存在、权限不足或僵尸进程的异常
            pass

def start_clash():
    download_and_extract_latest_release()
    system_platform = platform.system().lower()

    if system_platform == 'windows':
        clash_binary = '.\\clash.exe'
    elif system_platform in ["linux", "darwin"]:
        clash_binary = f'./clash-{system_platform}'
        ensure_executable(clash_binary)
    else:
        raise OSError("Unsupported operating system.")

    not_started = True

    global CONFIG_FILE
    CONFIG_FILE = f'{CONFIG_FILE}.json' if os.path.exists(f'{CONFIG_FILE}.json') else CONFIG_FILE
    while not_started:
        clash_process = subprocess.Popen(
            [clash_binary, '-f', CONFIG_FILE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8'
        )

        output_lines = []

        # 启动线程来读取标准输出和标准错误
        stdout_thread = threading.Thread(target=read_output, args=(clash_process.stdout, output_lines))

        stdout_thread.start()

        timeout = 3
        start_time = time.time()
        while time.time() - start_time < timeout:
            stdout_thread.join(timeout=0.5)
            if output_lines:
                # 检查输出是否包含错误信息
                if 'GeoIP.dat' in output_lines[-1]:
                    print(output_lines[-1])
                    time.sleep(5)
                    if is_clash_api_running():
                        return clash_process

                if "Parse config error" in output_lines[-1]:
                    if handle_clash_error(output_lines[-1], CONFIG_FILE):
                        clash_process.kill()
                        output_lines = []
            if is_clash_api_running():
                return clash_process


        if not_started:
            clash_process.kill()
            continue
        return clash_process


def is_clash_api_running():
    try:
        url = f"http://{CLASH_API_HOST}:{CLASH_API_PORTS[0]}/configs"
        response = requests.get(url)
        # 检查响应状态码，200表示正常
        print(f'Clash API启动成功，开始批量检测')
        return response.status_code == 200
    except requests.exceptions.RequestException:
        # 捕获所有请求异常，包括连接错误等
        return False

# 调用ClashAPI
class ClashAPI:
    def __init__(self, host: str, ports: List[int], secret: str = ""):
        self.host = host
        self.ports = ports
        self.base_url = None  # 将在连接检查时设置
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

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()

    async def check_connection(self) -> bool:
        """检查与 Clash API 的连接状态，自动尝试不同端口"""
        for port in self.ports:
            try:
                test_url = f"http://{self.host}:{port}"
                response = await self.client.get(f"{test_url}/version")
                if response.status_code == 200:
                    version = response.json().get('version', 'unknown')
                    print(f"成功连接到 Clash API (端口 {port})，版本: {version}")
                    self.base_url = test_url
                    return True
            except httpx.RequestError:
                print(f"端口 {port} 连接失败，尝试下一个端口...")
                continue

        print("所有端口均连接失败")
        print(f"请确保 Clash 正在运行，并且 External Controller 已启用于以下端口之一: {', '.join(map(str, self.ports))}")
        return False

    async def get_proxies(self) -> Dict:
        """获取所有代理节点信息"""
        if not self.base_url:
            raise ClashAPIException("未建立与 Clash API 的连接")

        try:
            response = await self.client.get(
                f"{self.base_url}/proxies",
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                print("认证失败，请检查 API Secret 是否正确")
            raise ClashAPIException(f"HTTP 错误: {e}")
        except httpx.RequestError as e:
            raise ClashAPIException(f"请求错误: {e}")

    async def test_proxy_delay(self, proxy_name: str) -> ProxyTestResult:
        """测试指定代理节点的延迟，使用缓存避免重复测试"""
        if not self.base_url:
            raise ClashAPIException("未建立与 Clash API 的连接")

        # 检查缓存
        if proxy_name in self._test_results_cache:
            cached_result = self._test_results_cache[proxy_name]
            # 如果测试结果不超过60秒，直接返回缓存的结果
            if (datetime.now() - cached_result.tested_time).total_seconds() < 60:
                return cached_result

        async with self.semaphore:
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
            except Exception as e:
                result = ProxyTestResult(proxy_name)
            finally:
                # 更新缓存
                self._test_results_cache[proxy_name] = result
                return result

# 更新clash配置
class ClashConfig:
    """Clash 配置管理类"""

    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = self._load_config()
        self.proxy_groups = self._get_proxy_groups()

    def _load_config(self) -> dict:
        """加载配置文件"""
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
        """获取所有代理组信息"""
        return self.config.get("proxy-groups", [])

    def get_group_names(self) -> List[str]:
        """获取所有代理组名称"""
        return [group["name"] for group in self.proxy_groups]

    def get_group_proxies(self, group_name: str) -> List[str]:
        """获取指定组的所有代理"""
        for group in self.proxy_groups:
            if group["name"] == group_name:
                return group.get("proxies", [])
        return []

    def remove_invalid_proxies(self, results: List[ProxyTestResult]):
        """从配置中完全移除失效的节点"""
        # 获取所有失效节点名称
        invalid_proxies = {r.name for r in results if not r.is_valid}

        if not invalid_proxies:
            return

        # 从 proxies 部分移除失效节点
        valid_proxies = []
        if "proxies" in self.config:
            valid_proxies = [p for p in self.config["proxies"]
                             if p.get("name") not in invalid_proxies]
            self.config["proxies"] = valid_proxies

        # 从所有代理组中移除失效节点
        for group in self.proxy_groups:
            if "proxies" in group:
                group["proxies"] = [p for p in group["proxies"] if p not in invalid_proxies]
        global LIMIT
        left = LIMIT if len(self.config['proxies']) > LIMIT else len(self.config['proxies'])
        print(f"已从配置中移除 {len(invalid_proxies)} 个失效节点，最终保留{left}个延迟最小的节点")

    def keep_proxies_by_limit(self,proxy_names):
        if "proxies" in self.config:
            self.config["proxies"] = [p for p in self.config["proxies"] if p["name"] in proxy_names]
    def update_group_proxies(self, group_name: str, results: List[ProxyTestResult]):
        """更新指定组的代理列表，仅保留有效节点并按延迟排序"""
        # 移除失效节点
        self.remove_invalid_proxies(results)

        # 获取有效节点并按延迟排序
        valid_results = [r for r in results if r.is_valid]
        valid_results = list(set(valid_results))
        valid_results.sort(key=lambda x: x.delay)

        # 更新代理组
        proxy_names = [r.name for r in valid_results]
        for group in self.proxy_groups:
            if group["name"] == group_name:
                group["proxies"] = proxy_names
                break
        return proxy_names

    def save(self):
        """保存配置到文件"""
        try:
            # 保存新配置
            yaml_cfg = self.config_path.strip('.json') if self.config_path.endswith('.json') else self.config_path
            with open(yaml_cfg, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, allow_unicode=True, sort_keys=False)
            with open(f'{yaml_cfg}.json', "w", encoding="utf-8") as f:
                json.dump(self.config,f,ensure_ascii=False)

        except Exception as e:
            print(f"保存配置文件失败: {e}")
            sys.exit(1)

# 打印测试结果摘要
def print_test_summary(group_name: str, results: List[ProxyTestResult]):
    """打印测试结果摘要"""
    valid_results = [r for r in results if r.is_valid]
    invalid_results = [r for r in results if not r.is_valid]
    total = len(results)
    valid = len(valid_results)
    invalid = len(invalid_results)

    print(f"\n策略组 '{group_name}' 测试结果:")
    print(f"总节点数: {total}")
    print(f"可用节点数: {valid}")
    print(f"失效节点数: {invalid}")

    delays = []

    if valid > 0:
        avg_delay = sum(r.delay for r in valid_results) / valid
        print(f"平均延迟: {avg_delay:.2f}ms")
        print("\n节点延迟统计:")
        sorted_results = sorted(valid_results, key=lambda x: x.delay)
        for i, result in enumerate(sorted_results[:LIMIT], 1):
            delays.append({"name":result.name, "Delay_ms": round(result.delay, 2)})
            print(f"{i}. {result.name}: {result.delay:.2f}ms")
    return delays


# 测试一组代理节点
async def test_group_proxies(clash_api: ClashAPI, proxies: List[str]) -> List[ProxyTestResult]:
    """测试一组代理节点"""
    print(f"开始测试 {len(proxies)} 个节点 (最大并发: {MAX_CONCURRENT_TESTS})")

    # 创建所有测试任务
    tasks = [clash_api.test_proxy_delay(proxy_name) for proxy_name in proxies]

    # 使用进度显示执行所有任务
    results = []
    for future in asyncio.as_completed(tasks):
        result = await future
        results.append(result)
        # 显示进度
        done = len(results)
        total = len(tasks)
        print(f"\r进度: {done}/{total} ({done / total * 100:.1f}%)", end="", flush=True)

    return results

async def proxy_clean():
    # 更新全局配置
    delays = []
    global MAX_CONCURRENT_TESTS, TIMEOUT, CLASH_API_SECRET, LIMIT, CONFIG_FILE
    CONFIG_FILE = f'{CONFIG_FILE}.json' if os.path.exists(f'{CONFIG_FILE}.json') else CONFIG_FILE
    print(f"===================节点批量检测基本信息======================")
    print(f"配置文件: {CONFIG_FILE}")
    print(f"API 端口: {CLASH_API_PORTS[0]}")
    print(f"并发数量: {MAX_CONCURRENT_TESTS}")
    print(f"超时时间: {TIMEOUT}秒")
    print(f"保留节点：最多保留{LIMIT}个延迟最小的有效节点")

    # 加载配置
    print(f'加载配置文件{CONFIG_FILE}')
    config = ClashConfig(CONFIG_FILE)
    available_groups = config.get_group_names()[1:]

    # 确定要测试的策略组
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

    # 开始测试
    start_time = datetime.now()

    # 创建支持多端口的API实例
    async with ClashAPI(CLASH_API_HOST, CLASH_API_PORTS, CLASH_API_SECRET) as clash_api:
        if not await clash_api.check_connection():
            return

        try:
            all_test_results = []  # 收集所有测试结果

            # 测试策略组，只需要测试其中一个即可
            group_name = groups_to_test[0]
            print(f"\n======================== 开始测试策略组: {group_name} ====================")
            proxies = config.get_group_proxies(group_name)

            if not proxies:
                print(f"策略组 '{group_name}' 中没有代理节点")
            else:
                # 测试该组的所有节点
                results = await test_group_proxies(clash_api, proxies)
                all_test_results.extend(results)
                # 打印测试结果摘要
                delays = print_test_summary(group_name, results)

            print('\n===================移除失效节点并按延迟排序======================\n')
            # 一次性移除所有失效节点并更新配置
            config.remove_invalid_proxies(all_test_results)

            # 为每个组更新有效节点的顺序
            proxy_names = set()
            # 只对一个group的proxies排序即可
            group_proxies = config.get_group_proxies(group_name)
            group_results = [r for r in all_test_results if r.name in group_proxies]
            if LIMIT:
                group_results = group_results[:LIMIT]
            for r in group_results:
                proxy_names.add(r.name)

            for group_name in groups_to_test:
                proxy_names = config.update_group_proxies(group_name, group_results)
                print(f"'{group_name}'已按延迟大小重新排序")

            if LIMIT:
                config.keep_proxies_by_limit(proxy_names)

            # 保存更新后的配置
            config.save()
            # 显示总耗时
            total_time = (datetime.now() - start_time).total_seconds()
            print(f"\n总耗时: {total_time:.2f} 秒")
            return delays
        except ClashAPIException as e:
            print(f"Clash API 错误: {e}")
        except Exception as e:
            print(f"发生错误: {e}")
            raise

# 获取当前时间的各个组成部分
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

# 移除URL中的代理前缀
def strip_proxy_prefix(url):
    proxy_pattern = r'^https?://[^/]+/https://'
    match = re.match(proxy_pattern, url)
    if match:
        real_url = re.sub(proxy_pattern, 'https://', url)
        proxy_prefix = url[:match.end() - 8]
        return real_url, proxy_prefix
    return url, None

# 判断是否为GitHub raw URL
def is_github_raw_url(url):
    return 'raw.githubusercontent.com' in url

# 从URL中提取文件模式，返回占位符前后的部分
def extract_file_pattern(url):
    # 查找形如 {x}<suffix> 的模式
    match = re.search(r'\{x\}(\.[a-zA-Z0-9]+)(?:/|$)', url)
    if match:
        return match.group(1)  # 返回文件后缀，如 '.yaml', '.txt', '.json'
    return None

# 从GitHub API获取匹配指定后缀的文件名
def get_github_filename(github_url, file_suffix):
    match = re.match(r'https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/[^/]+/[^/]+/([^/]+)', github_url)
    if not match:
        raise ValueError("无法从URL中提取owner和repo信息")
    owner, repo,branch = match.groups()

    # 构建API URL
    path_part = github_url.split(f'/refs/heads/{branch}/')[-1]
    # 移除 {x}<suffix> 部分来获取目录路径
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

# 解析URL模板，支持任意组合的日期时间变量和分隔符
def parse_template(template_url, datetime_vars):
    def replace_template(match):
        """替换单个模板块的内容"""
        template_content = match.group(1)
        if template_content == 'x':
            return '{x}'  # 保持 {x} 不变，供后续处理

        result = ''
        # 用于临时存储当前字符
        current_char = ''

        # 遍历模板内容中的每个字符
        for char in template_content:
            if char in datetime_vars:
                # 如果是日期时间变量，替换为对应值
                if current_char:
                    # 添加之前累积的非变量字符
                    result += current_char
                    current_char = ''
                result += datetime_vars[char]
            else:
                # 如果是其他字符（分隔符），直接保留
                current_char += char

        # 添加最后可能剩余的非变量字符
        if current_char:
            result += current_char

        return result

    # 使用正则表达式查找并替换所有模板块
    return re.sub(r'\{([^}]+)\}', replace_template, template_url)

# 完整解析模板URL
def resolve_template_url(template_url):
    # 先处理代理前缀
    url, proxy_prefix = strip_proxy_prefix(template_url)

    # 获取日期时间变量
    datetime_vars = parse_datetime_variables()

    # 替换日期时间变量
    resolved_url = parse_template(url, datetime_vars)

    # 如果是GitHub URL且包含{x}，则处理文件名
    if is_github_raw_url(resolved_url) and '{x}' in resolved_url:
        # 提取文件后缀
        file_suffix = extract_file_pattern(resolved_url)
        if file_suffix:
            filename = get_github_filename(resolved_url, file_suffix)
            # 替换 {x}<suffix> 为实际文件名
            resolved_url = re.sub(r'\{x\}' + re.escape(file_suffix), filename, resolved_url)

    # 如果有代理前缀，重新添加上
    if proxy_prefix:
        resolved_url = f"{proxy_prefix}{resolved_url}"

    return resolved_url

def work(links,check=False,allowed_types=[],only_check=False):
    try:
        load_nodes = []
        if not only_check:
            # 检查 INPUT 是否为本地文件夹路径
            if os.path.exists('input') and os.path.isdir('input'):
                load_nodes.extend(read_yaml_files(folder_path='input'))
                links.extend(read_txt_files(folder_path='input'))
            
            if allowed_types:
                load_nodes = filter_by_types_alt(allowed_types,nodes=load_nodes)
            
            # 合并所有链接
            links = merge_lists(links)
            if links or load_nodes:
                generate_clash_config(links,load_nodes)

        if check or only_check:
            clash_process = None
            try:
                # 启动clash
                print(f"===================启动clash并初始化配置======================")
                clash_process = start_clash()
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
    # 从环境变量中获取 INPUT
    input_value = os.getenv("INPUT")
    links_from_env = []
    
    # 检查 INPUT 是否为 URL
    if input_value and (input_value.startswith('http://') or input_value.startswith('https://')):
        print(f"从环境变量中读取到 URL: {input_value}")
        links_from_env.append(input_value)
    
    work(links=links_from_env, check=True, only_check=False, allowed_types=["ss","hysteria2","hy2","vless","vmess","trojan"])
