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

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

TEST_URL = "http://www.pinterest.com"
CLASH_API_PORTS = [9090]
CLASH_API_HOST = "127.0.0.1"
CLASH_API_SECRET = ""
TIMEOUT = 3
SPEED_TEST = False
SPEED_TEST_LIMIT = 5
results_speed = []
MAX_CONCURRENT_TESTS = 30  # 降低并发数量，适应 GitHub 环境
LIMIT = 10000
CONFIG_FILE = 'clash_config.yaml'
INPUT = "input"
BAN = ["中国", "China", "CN", "电信", "移动", "联通"]
headers = {
    'Accept-Charset': 'utf-8',
    'Accept': 'text/html,application/x-yaml,*/*',
    'User-Agent': 'Clash Verge/1.7.7'
}

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
        "GEOIP,CN,DIRECT",
        "MATCH,节点选择"
    ]
}

def parse_hysteria2_link(link):
    logger.info(f"解析 Hysteria2 链接: {link}")
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
    logger.info(f"解析 Shadowsocks 链接: {link}")
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
    logger.info(f"解析 Trojan 链接: {link}")
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
    logger.info(f"解析 VLESS 链接: {link}")
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

def parse_vmess_link(link):
    logger.info(f"解析 VMESS 链接: {link}")
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
    logger.info(f"解析 Shadowsocks 订阅: {link}")
    new_links = []
    try:
        response = requests.get(link, headers=headers, verify=False, allow_redirects=True, timeout=10)
        if response.status_code == 200:
            data = response.json()
            new_links = [{"name": x['remarks'], "type": "ss", "server": x['server'], "port": x['server_port'], "cipher": x['method'], "password": x['password'], "udp": True} for x in data]
            logger.info(f"成功解析 Shadowsocks 订阅，获取 {len(new_links)} 个节点")
        else:
            logger.error(f"请求 Shadowsocks 订阅失败，状态码: {response.status_code}")
    except requests.RequestException as e:
        logger.error(f"请求 Shadowsocks 订阅错误: {e}")
    return new_links

def parse_md_link(link):
    logger.info(f"解析 Markdown 链接: {link}")
    try:
        response = requests.get(link, timeout=10)
        response.raise_for_status()
        content = response.text
        content = urllib.parse.unquote(content)
        pattern = r'(?:vless|vmess|trojan|hysteria2|ss):\/\/[^#\s]*(?:#[^\s]*)?'
        matches = re.findall(pattern, content)
        logger.info(f"从 Markdown 链接中解析出 {len(matches)} 个代理链接")
        return matches
    except requests.RequestException as e:
        logger.error(f"请求 Markdown 链接错误: {e}")
        return []

def js_render(url):
    logger.info(f"执行 JavaScript 渲染: {url}")
    timeout = 4
    if timeout > 15:
        timeout = 15
    browser_args = ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--disable-software-rasterizer', '--disable-setuid-sandbox']
    session = HTMLSession(browser_args=browser_args)
    try:
        r = session.get(f'{url}', headers=headers, timeout=timeout, verify=False)
        r.html.render(timeout=timeout)
        logger.info(f"JavaScript 渲染完成")
        return r
    except Exception as e:
        logger.error(f"JavaScript 渲染失败: {e}")
        return None

def match_nodes(text):
    logger.info("匹配 YAML 节点")
    proxy_pattern = r"\{[^}]*name\s*:\s*['\"][^'\"]+['\"][^}]*server\s*:\s*[^,]+[^}]*\}"
    nodes = re.findall(proxy_pattern, text, re.DOTALL)
    proxies_list = []
    for node in nodes:
        node_dict = yaml.safe_load(node)
        proxies_list.append(node_dict)
    yaml_data = {"proxies": proxies_list}
    logger.info(f"匹配到 {len(proxies_list)} 个节点")
    return yaml_data

def process_url(url):
    logger.info(f"处理 URL: {url}")
    isyaml = False
    try:
        response = requests.get(url, headers=headers, verify=False, allow_redirects=True, timeout=10)
        if response.status_code == 200:
            content = response.content.decode('utf-8')
            if 'proxies:' in content:
                if '</pre>' in content:
                    content = content.replace('<pre style="word-wrap: break-word; white-space: pre-wrap;">', '').replace('</pre>', '')
                yaml_data = yaml.safe_load(content)
                if 'proxies' in yaml_data:
                    isyaml = True
                    proxies = yaml_data['proxies'] if yaml_data['proxies'] else []
                    logger.info(f"从 URL 解析到 {len(proxies)} 个 YAML 节点")
                    return proxies, isyaml
            else:
                try:
                    decoded_bytes = base64.b64decode(content)
                    decoded_content = decoded_bytes.decode('utf-8')
                    decoded_content = urllib.parse.unquote(decoded_content)
                    logger.info(f"从 Base64 解码得到 {len(decoded_content.splitlines())} 行")
                    return decoded_content.splitlines(), isyaml
                except Exception:
                    res = js_render(url)
                    if res and 'external-controller' in res.html.text:
                        try:
                            yaml_data = yaml.safe_load(res.html.text)
                        except Exception:
                            yaml_data = match_nodes(res.html.text)
                        if 'proxies' in yaml_data:
                            isyaml = True
                            logger.info(f"从 JavaScript 渲染解析到 {len(yaml_data['proxies'])} 个 YAML 节点")
                            return yaml_data['proxies'], isyaml
                    else:
                        pattern = r'([A-Za-z0-9_+/\-]+={0,2})'
                        matches = re.findall(pattern, res.html.text if res else '')
                        stdout = matches[-1] if matches else []
                        decoded_bytes = base64.b64decode(stdout)
                        decoded_content = decoded_bytes.decode('utf-8')
                        logger.info(f"从 JavaScript 渲染 Base64 解码得到 {len(decoded_content.splitlines())} 行")
                        return decoded_content.splitlines(), isyaml
        else:
            logger.error(f"请求 URL 失败，状态码: {response.status_code}")
            return [], isyaml
    except requests.RequestException as e:
        logger.error(f"请求 URL 错误: {e}")
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
        logger.error(f"解析代理链接失败: {link}, 错误: {e}")
        return None

def deduplicate_proxies(proxies_list):
    logger.info("执行节点去重")
    unique_proxies = []
    seen = set()
    for proxy in proxies_list:
        key = (proxy['server'], proxy['port'], proxy['type'], proxy.get('password', ''))
        if key not in seen:
            seen.add(key)
            unique_proxies.append(proxy)
    logger.info(f"去重后保留 {len(unique_proxies)} 个节点")
    return unique_proxies

def add_random_suffix(name, existing_names):
    suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
    new_name = f"{name}-{suffix}"
    while new_name in existing_names:
        suffix = ''.join(random.choices(string.ascii_letters + string.digits, k=4))
        new_name = f"{name}-{suffix}"
    return new_name

def read_txt_files(folder_path):
    logger.info(f"读取目录 {folder_path} 下的 TXT 文件")
    all_lines = []
    txt_files = glob.glob(os.path.join(folder_path, '*.txt'))
    for file_path in txt_files:
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
            all_lines.extend(line.strip() for line in lines)
    if all_lines:
        logger.info(f"从 {folder_path} 目录下的 TXT 文件加载 {len(all_lines)} 行")
    return all_lines

def read_yaml_files(folder_path):
    logger.info(f"读取目录 {folder_path} 下的 YAML 文件")
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
            logger.error(f"读取 YAML 文件 {file_path} 错误: {e}")
    if load_nodes:
        logger.info(f"从 {folder_path} 目录下的 YAML 文件加载 {len(load_nodes)} 个节点")
    return load_nodes

def filter_by_types_alt(allowed_types, nodes):
    logger.info(f"按类型过滤节点: {allowed_types}")
    filtered = [x for x in nodes if x.get('type') in allowed_types]
    logger.info(f"过滤后保留 {len(filtered)} 个节点")
    return filtered

def merge_lists(*lists):
    logger.info("合并链接列表")
    merged = [item for item in chain.from_iterable(lists) if item != '']
    logger.info(f"合并得到 {len(merged)} 个链接")
    return merged

def handle_links(new_links, resolve_name_conflicts):
    logger.info(f"处理 {len(new_links)} 个链接")
    for new_link in new_links:
        if new_link.startswith(("hysteria2://", "hy2://", "trojan://", "ss://", "vless://", "vmess://")):
            node = parse_proxy_link(new_link)
            if node:
                resolve_name_conflicts(node)
        else:
            logger.warning(f"跳过无效或不支持的链接: {new_link}")

def generate_clash_config(links, load_nodes):
    logger.info("开始生成 Clash 配置文件")
    now = datetime.now()
    logger.info(f"当前时间: {now}")
    final_nodes = []
    existing_names = set()
    config = clash_config_template.copy()

    def resolve_name_conflicts(node):
        server = node.get("server")
        if not server:
            logger.warning("节点缺少 server 字段，跳过")
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
            logger.info(f"处理链接: {link}")
            try:
                new_links, isyaml = process_url(link)
            except Exception as e:
                logger.error(f"处理链接错误: {e}")
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
        if not_contains(name):
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
        logger.info(f"生成 Clash 配置文件: {CONFIG_FILE} 和 {CONFIG_FILE}.json")
    else:
        logger.warning("没有节点数据更新")

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
        logger.info(f"设置文件 {file_path} 为可执行")

def handle_clash_error(error_message, config_file_path):
    logger.info("处理 Clash 配置错误")
    start_time = time.time()
    config_file_path = f'{config_file_path}.json' if os.path.exists(f'{config_file_path}.json') else config_file_path
    proxy_index_match = re.search(r'proxy (\d+):', error_message)
    if not proxy_index_match:
        logger.error("无法从错误信息中提取代理索引")
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
        logger.info(f"修复配置异常，移除 proxy[{problem_index}] {problem_proxy_name}，耗时 {time.time() - start_time:.2f}s")
        return True
    except Exception as e:
        logger.error(f"处理配置文件错误: {e}")
        return False

def read_output(pipe, output_lines):
    while True:
        line = pipe.readline()
        if line:
            output_lines.append(line)
            logger.info(f"Clash 输出: {line.strip()}")
        else:
            break

def kill_clash():
    logger.info("尝试终止 Clash 进程")
    system = platform.system()
    clash_process_names = {
        "Windows": "mihomo",
        "Linux": "mihomo",
        "Darwin": "mihomo"
    }
    config_files = ["clash_config.yaml", "clash_config.yaml.json"]
    if system not in clash_process_names:
        logger.error("不支持的操作系统")
        return
    process_name = clash_process_names[system]
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['name'] != process_name:
                continue
            cmdline = proc.info['cmdline']
            if cmdline and len(cmdline) >= 3 and cmdline[1] == '-f' and cmdline[2] in config_files:
                proc.kill()
                logger.info(f"终止 Clash 进程 (PID: {proc.pid})")
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass
    logger.info("Clash 进程终止检查完成")

def start_clash():
    logger.info("启动 Clash 进程")
    system_platform = platform.system().lower()
    clash_binary = '/mihomo/mihomo-linux-amd64-compatible-v1.19.13'  # 指定正确的 mihomo 路径
    if not os.path.exists(clash_binary):
        logger.error(f"Clash 二进制文件 {clash_binary} 不存在")
        raise FileNotFoundError(f"No such file or directory: '{clash_binary}'")
    if system_platform in ["linux", "darwin"]:
        ensure_executable(clash_binary)
    else:
        logger.error("不支持的操作系统")
        raise OSError("Unsupported operating system.")
    not_started = True
    global CONFIG_FILE
    CONFIG_FILE = f'{CONFIG_FILE}.json' if os.path.exists(f'{CONFIG_FILE}.json') else CONFIG_FILE
    logger.info(f"加载配置文件: {CONFIG_FILE}")
    max_attempts = 3
    attempt = 0
    while not_started and attempt < max_attempts:
        attempt += 1
        logger.info(f"尝试启动 Clash (第 {attempt}/{max_attempts})")
        clash_process = subprocess.Popen(
            [clash_binary, '-f', CONFIG_FILE],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding='utf-8'
        )
        output_lines = []
        stdout_thread = threading.Thread(target=read_output, args=(clash_process.stdout, output_lines))
        stdout_thread.start()
        timeout = 5
        start_time = time.time()
        while time.time() - start_time < timeout:
            stdout_thread.join(timeout=0.5)
            if output_lines:
                if 'GeoIP.dat' in output_lines[-1]:
                    logger.info(output_lines[-1])
                    time.sleep(5)
                    if is_clash_api_running():
                        logger.info("Clash 进程启动成功")
                        not_started = False
                        return clash_process
                if "Parse config error" in output_lines[-1]:
                    logger.error(f"配置解析错误: {output_lines[-1]}")
                    if handle_clash_error(output_lines[-1], CONFIG_FILE):
                        clash_process.kill()
                        output_lines = []
                        break
            if is_clash_api_running():
                logger.info("Clash API 已运行")
                not_started = False
                return clash_process
        clash_process.kill()
        logger.warning(f"Clash 启动失败，重试...")
    logger.error(f"Clash 在 {max_attempts} 次尝试后未能启动")
    raise RuntimeError("Failed to start Clash after multiple attempts")

def is_clash_api_running():
    logger.info("检查 Clash API 是否运行")
    try:
        url = f"http://{CLASH_API_HOST}:{CLASH_API_PORTS[0]}/configs"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            logger.info("Clash API 启动成功")
            return True
        else:
            logger.error(f"Clash API 请求失败，状态码: {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Clash API 请求错误: {e}")
        return False

def switch_proxy(proxy_name='DIRECT'):
    logger.info(f"切换到代理节点: {proxy_name}")
    url = f"http://{CLASH_API_HOST}:{CLASH_API_PORTS[0]}/proxies/节点选择"
    data = {"name": proxy_name}
    try:
        response = requests.put(url, json=data, timeout=5)
        if response.status_code == 204:
            logger.info(f"成功切换到 '节点选择-{proxy_name}'")
            return {"status": "success", "message": f"Switched to proxy '{proxy_name}'."}
        else:
            logger.error(f"切换代理失败，状态码: {response.status_code}")
            return response.json()
    except Exception as e:
        logger.error(f"切换代理错误: {e}")
        return {"status": "error", "message": str(e)}

class ClashAPI:
    def __init__(self, host: str, ports: List[int], secret: str = ""):
        self.host = host
        self.ports = ports
        self.base_url = None
        self.headers = {
            "Authorization": f"Bearer {secret}" if secret else "",
            "Content-Type": "application/json"
        }
        self.client = httpx.AsyncClient(timeout=1)
        self.semaphore = Semaphore(MAX_CONCURRENT_TESTS)
        self._test_results_cache: Dict[str, ProxyTestResult] = {}
        logger.info(f"初始化 ClashAPI，主机: {host}, 端口: {ports}")

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()
        logger.info("关闭 ClashAPI 客户端")

    async def check_connection(self) -> bool:
        logger.info("检查 Clash API 连接")
        for port in self.ports:
            try:
                test_url = f"http://{self.host}:{port}"
                response = await self.client.get(f"{test_url}/version", timeout=5)
                if response.status_code == 200:
                    version = response.json().get('version', 'unknown')
                    logger.info(f"成功连接到 Clash API (端口 {port})，版本: {version}")
                    self.base_url = test_url
                    return True
            except httpx.RequestError as e:
                logger.error(f"端口 {port} 连接失败: {e}")
                continue
        logger.error("所有端口连接失败")
        return False

    async def get_proxies(self) -> Dict:
        if not self.base_url:
            logger.error("未建立 Clash API 连接")
            raise ClashAPIException("未建立与 Clash API 的连接")
        try:
            response = await self.client.get(f"{self.base_url}/proxies", headers=self.headers)
            response.raise_for_status()
            logger.info("成功获取代理节点信息")
            return response.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"获取代理节点 HTTP 错误: {e}")
            raise ClashAPIException(f"HTTP 错误: {e}")
        except httpx.RequestError as e:
            logger.error(f"获取代理节点请求错误: {e}")
            raise ClashAPIException(f"请求错误: {e}")

    async def test_proxy_delay(self, proxy_name: str) -> ProxyTestResult:
        logger.info(f"测试代理节点延迟: {proxy_name}")
        if not self.base_url:
            logger.error("未建立 Clash API 连接")
            raise ClashAPIException("未建立与 Clash API 的连接")
        if proxy_name in self._test_results_cache:
            cached_result = self._test_results_cache[proxy_name]
            if (datetime.now() - cached_result.tested_time).total_seconds() < 60:
                logger.info(f"使用缓存结果 for {proxy_name}")
                return cached_result
        async with self.semaphore:
            try:
                response = await self.client.get(
                    f"{self.base_url}/proxies/{proxy_name}/delay",
                    headers=self.headers,
                    params={"url": TEST_URL, "timeout": int(TIMEOUT * 1000)}
                )
                response.raise_for_status()
                delay = response.json().get("delay")
                result = ProxyTestResult(proxy_name, delay)
            except httpx.HTTPError as e:
                logger.error(f"测试 {proxy_name} 延迟 HTTP 错误: {e}")
                result = ProxyTestResult(proxy_name)
            except Exception as e:
                logger.error(f"测试 {proxy_name} 延迟错误: {e}")
                result = ProxyTestResult(proxy_name)
            finally:
                self._test_results_cache[proxy_name] = result
                return result

class ClashConfig:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = self._load_config()
        self.proxy_groups = self._get_proxy_groups()
        logger.info(f"初始化 ClashConfig，配置文件: {config_path}")

    def _load_config(self) -> dict:
        logger.info(f"加载配置文件: {self.config_path}")
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            logger.error(f"找不到配置文件: {self.config_path}")
            sys.exit(1)
        except yaml.YAMLError as e:
            logger.error(f"配置文件格式错误: {e}")
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
            logger.info("没有失效节点需要移除")
            return
        valid_proxies = []
        if "proxies" in self.config:
            valid_proxies = [p for p in self.config["proxies"] if p.get("name") not in invalid_proxies]
            self.config["proxies"] = valid_proxies
        for group in self.proxy_groups:
            if "proxies" in group:
                group["proxies"] = [p for p in group["proxies"] if p not in invalid_proxies]
        left = LIMIT if len(self.config['proxies']) > LIMIT else len(self.config['proxies'])
        logger.info(f"移除 {len(invalid_proxies)} 个失效节点，保留 {left} 个节点")

    def keep_proxies_by_limit(self, proxy_names):
        if "proxies" in self.config:
            self.config["proxies"] = [p for p in self.config["proxies"] if p["name"] in proxy_names]
            logger.info(f"根据限制保留 {len(self.config['proxies'])} 个节点")

    def update_group_proxies(self, group_name: str, results: List[ProxyTestResult]):
        valid_results = [r for r in results if r.is_valid]
        valid_results = list(set(valid_results))
        valid_results.sort(key=lambda x: x.delay)
        proxy_names = [r.name for r in valid_results]
        for group in self.proxy_groups:
            if group["name"] == group_name:
                group["proxies"] = proxy_names
                break
        logger.info(f"更新策略组 {group_name} 的代理列表，保留 {len(proxy_names)} 个节点")
        return proxy_names

    def save(self):
        logger.info(f"保存配置文件: {self.config_path}")
        try:
            yaml_cfg = self.config_path.strip('.json') if self.config_path.endswith('.json') else self.config_path
            with open(yaml_cfg, 'w', encoding='utf-8') as f:
                yaml.dump(self.config, f, allow_unicode=True, sort_keys=False)
            with open(f'{yaml_cfg}.json', 'w', encoding='utf-8') as f:
                json.dump(self.config, f, ensure_ascii=False)
            logger.info(f"配置文件保存成功: {yaml_cfg} 和 {yaml_cfg}.json")
        except Exception as e:
            logger.error(f"保存配置文件失败: {e}")
            sys.exit(1)

def print_test_summary(group_name: str, results: List[ProxyTestResult]):
    logger.info(f"打印策略组 {group_name} 的测试结果")
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
            delays.append({"name": result.name, "Delay_ms": round(result.delay, 2)})
            print(f"{i}. {result.name}: {result.delay:.2f}ms")
    return delays

async def test_group_proxies(clash_api: ClashAPI, proxies: List[str]) -> List[ProxyTestResult]:
    logger.info(f"开始测试 {len(proxies)} 个节点 (最大并发: {MAX_CONCURRENT_TESTS})")
    tasks = [clash_api.test_proxy_delay(proxy_name) for proxy_name in proxies]
    results = []
    for future in asyncio.as_completed(tasks):
        result = await future
        results.append(result)
        done = len(results)
        total = len(tasks)
        print(f"\r进度: {done}/{total} ({done / total * 100:.1f}%)", end="", flush=True)
    logger.info("节点测试完成")
    return results

async def proxy_clean():
    logger.info("开始节点清理")
    delays = []
    global MAX_CONCURRENT_TESTS, TIMEOUT, CLASH_API_SECRET, LIMIT, CONFIG_FILE
    CONFIG_FILE = f'{CONFIG_FILE}.json' if os.path.exists(f'{CONFIG_FILE}.json') else CONFIG_FILE
    print(f"===================节点批量检测基本信息======================")
    print(f"配置文件: {CONFIG_FILE}")
    print(f"API 端口: {CLASH_API_PORTS[0]}")
    print(f"并发数量: {MAX_CONCURRENT_TESTS}")
    print(f"超时时间: {TIMEOUT}秒")
    print(f"保留节点：最多保留{LIMIT}个延迟最小的有效节点")
    config = ClashConfig(CONFIG_FILE)
    available_groups = config.get_group_names()[1:]
    groups_to_test = available_groups
    invalid_groups = set(groups_to_test) - set(available_groups)
    if invalid_groups:
        logger.warning(f"以下策略组不存在: {', '.join(invalid_groups)}")
        groups_to_test = list(set(groups_to_test) & set(available_groups))
    if not groups_to_test:
        logger.error("没有找到要测试的有效策略组")
        print(f"可用的策略组: {', '.join(available_groups)}")
        return
    print(f"\n将测试以下策略组: {', '.join(groups_to_test)}")
    start_time = datetime.now()
    async with ClashAPI(CLASH_API_HOST, CLASH_API_PORTS, CLASH_API_SECRET) as clash_api:
        if not await clash_api.check_connection():
            logger.error("无法连接到 Clash API，退出")
            return
        try:
            all_test_results = []
            group_name = groups_to_test[0]
            print(f"\n======================== 开始测试策略组: {group_name} ====================")
            proxies = config.get_group_proxies(group_name)
            if not proxies:
                logger.warning(f"策略组 '{group_name}' 中没有代理节点")
            else:
                results = await test_group_proxies(clash_api, proxies)
                all_test_results.extend(results)
                delays = print_test_summary(group_name, results)
            print('\n===================移除失效节点并按延迟排序======================\n')
            config.remove_invalid_proxies(all_test_results)
            proxy_names = set()
            group_proxies = config.get_group_proxies(group_name)
            group_results = [r for r in all_test_results if r.name in group_proxies]
            if LIMIT:
                group_results = group_results[:LIMIT]
            for r in group_results:
                proxy_names.add(r.name)
            for group_name in groups_to_test:
                proxy_names = config.update_group_proxies(group_name, group_results)
                print(f"'{group_name}' 已按延迟大小重新排序")
            if LIMIT:
                config.keep_proxies_by_limit(proxy_names)
            config.save()
            if SPEED_TEST:
                print('\n===================检测节点速度======================\n')
                sorted_proxy_names = start_download_test(proxy_names)
                new_list = sorted_proxy_names.copy()
                added_elements = set(new_list)
                group_proxies = config.get_group_proxies(group_name)
                for item in group_proxies:
                    if item not in added_elements:
                        new_list.append(item)
                        added_elements.add(item)
                for group_name in groups_to_test:
                    for group in config.proxy_groups:
                        if group["name"] == group_name:
                            group["proxies"] = new_list
                config.save()
            total_time = (datetime.now() - start_time).total_seconds()
            print(f"\n总耗时: {total_time:.2f} 秒")
            return delays
        except ClashAPIException as e:
            logger.error(f"Clash API 错误: {e}")
        except Exception as e:
            logger.error(f"发生错误: {e}")
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
    logger.info(f"从 GitHub 获取文件名: {github_url}")
    match = re.match(r'https://raw\.githubusercontent\.com/([^/]+)/([^/]+)/[^/]+/[^/]+/([^/]+)', github_url)
    if not match:
        logger.error("无法从 URL 中提取 owner 和 repo 信息")
        raise ValueError("无法从 URL 中提取 owner 和 repo 信息")
    owner, repo, branch = match.groups()
    path_part = github_url.split(f'/refs/heads/{branch}/')[-1]
    path_part = re.sub(r'\{x\}' + re.escape(file_suffix) + '(?:/|$)', '', path_part)
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path_part}"
    try:
        response = requests.get(api_url, timeout=10)
        if response.status_code != 200:
            logger.error(f"GitHub API 请求失败: {response.status_code} {response.text}")
            raise Exception(f"GitHub API 请求失败: {response.status_code}")
        files = response.json()
        matching_files = [f['name'] for f in files if f['name'].endswith(file_suffix)]
        if not matching_files:
            logger.error(f"未找到匹配的 {file_suffix} 文件")
            raise Exception(f"未找到匹配的 {file_suffix} 文件")
        logger.info(f"找到匹配文件: {matching_files[0]}")
        return matching_files[0]
    except Exception as e:
        logger.error(f"获取 GitHub 文件名错误: {e}")
        raise

def resolve_template_url(template_url):
    logger.info(f"解析模板 URL: {template_url}")
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
    logger.info(f"解析后的 URL: {resolved_url}")
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

def start_download_test(proxy_names, speed_limit=0.1):
    logger.info(f"开始下载速度测试，节点数: {len(proxy_names)}")
    test_all_proxies(proxy_names[:SPEED_TEST_LIMIT])
    filtered_list = [item for item in results_speed if float(item[1]) >= float(f'{speed_limit}')]
    sorted_list = sorted(filtered_list, key=lambda x: float(x[1]), reverse=True)
    sorted_proxy_names = []
    print(f'节点速度统计:')
    for i, result in enumerate(sorted_list[:LIMIT], 1):
        sorted_proxy_names.append(result[0])
        print(f"{i}. {result[0]}: {result[1]}Mb/s")
    logger.info(f"下载速度测试完成，保留 {len(sorted_proxy_names)} 个节点")
    return sorted_proxy_names

def test_all_proxies(proxy_names):
    logger.info(f"测试所有代理节点速度，节点数: {len(proxy_names)}")
    try:
        i = 0
        for proxy_name in proxy_names:
            i += 1
            print(f"\r正在测速节点【{i}】: {proxy_name}", flush=True, end='')
            test_proxy_speed(proxy_name)
        print("\r" + " " * 50 + "\r", end='')
    except Exception as e:
        logger.error(f"测试节点速度错误: {e}")

def test_proxy_speed(proxy_name):
    logger.info(f"测试代理节点速度: {proxy_name}")
    switch_proxy(proxy_name)
    proxies = {
        "http": 'http://127.0.0.1:7890',
        "https": 'http://127.0.0.1:7890',
    }
    start_time = time.time()
    total_length = 0
    test_duration = 5
    try:
        response = requests.get(
            "http://speedtest.tele2.net/100MB.zip",
            stream=True,
            proxies=proxies,
            headers={'Cache-Control': 'no-cache'},
            timeout=test_duration
        )
        for data in response.iter_content(chunk_size=524288):
            total_length += len(data)
            if time.time() - start_time >= test_duration:
                break
    except Exception as e:
        logger.error(f"测试节点 {proxy_name} 下载失败: {e}")
    elapsed_time = time.time() - start_time
    speed = total_length / elapsed_time if elapsed_time > 0 else 0
    results_speed.append((proxy_name, f"{speed / 1024 / 1024:.2f}"))
    logger.info(f"节点 {proxy_name} 速度: {speed / 1024 / 1024:.2f} MB/s")
    return speed / 1024 / 1024

def work(links, check=False, allowed_types=[], only_check=False):
    logger.info("开始执行主程序")
    try:
        kill_clash()  # 确保旧的 Clash 进程被终止
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
                print(f"===================启动 Clash 并初始化配置======================")
                clash_process = start_clash()
                switch_proxy('DIRECT')
                delays = asyncio.run(proxy_clean())
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
    links = [
        "https://raw.githubusercontent.com/qjlxg/HA/main/link.yaml"
    ]
    work(links, check=True, only_check=False, allowed_types=["ss", "hysteria2", "hy2", "vless", "vmess", "trojan"])
