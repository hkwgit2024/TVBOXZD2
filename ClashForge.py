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
CLASH_API_HOST = "127.0.0.1"
CLASH_API_SECRET = ""
TIMEOUT = 3
SPEED_TEST = False
SPEED_TEST_LIMIT = 5
results_speed = []
MAX_CONCURRENT_TESTS = 30  # 降低并发数量，适应 GitHub 环境
NODE_OUTPUT_LIMIT = 386  # 限制最终配置文件的节点数量
CONFIG_FILE = 'clash_config.yaml'
INPUT = "input"
BAN = ["中国", "China", "CN", "香港", "Hong Kong", "HK", "台湾", "Taiwan", "TW", "澳门", "Macau", "MO", "电信", "移动", "联通"]
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
            "exclude-filter": "(?i)中国|China|CN|香港|Hong Kong|HK|台湾|Taiwan|TW|澳门|Macau|MO|电信|移动|联通",
            "proxies": [],
            "url": "http://www.pinterest.com",
            "interval": 300,
            "tolerance": 50
        },
        {
            "name": "故障转移",
            "type": "fallback",
            "exclude-filter": "(?i)中国|China|CN|香港|Hong Kong|HK|台湾|Taiwan|TW|澳门|Macau|MO|电信|移动|联通",
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
        "name": remove_invalid_yaml_chars(name),
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
        "name": remove_invalid_yaml_chars(urllib.parse.unquote(name)),
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
        "name": remove_invalid_yaml_chars(urllib.parse.unquote(name)),
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
        "name": remove_invalid_yaml_chars(urllib.parse.unquote(name)),
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
    logger.info(f"解析 VMESS 链接: {link}")
    link = link[8:]
    decoded_link = base64.urlsafe_b64decode(link + '=' * (-len(link) % 4)).decode("utf-8")
    vmess_info = json.loads(decoded_link)
    return {
        "name": remove_invalid_yaml_chars(urllib.parse.unquote(vmess_info.get("ps", "vmess"))),
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
            new_links = [{"name": remove_invalid_yaml_chars(x['remarks']), "type": "ss", "server": x['server'], "port": x['server_port'], "cipher": x['method'], "password": x['password'], "udp": True} for x in data]
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
        return [remove_invalid_yaml_chars(match) for match in matches]
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
                    for proxy in proxies:
                        if 'name' in proxy:
                            proxy['name'] = remove_invalid_yaml_chars(proxy['name'])
                    logger.info(f"从 URL 解析到 {len(proxies)} 个 YAML 节点")
                    return proxies, isyaml
            else:
                try:
                    decoded_bytes = base64.b64decode(content)
                    decoded_content = decoded_bytes.decode('utf-8')
                    decoded_content = urllib.parse.unquote(decoded_content)
                    logger.info(f"从 Base64 解码得到 {len(decoded_content.splitlines())} 行")
                    return [remove_invalid_yaml_chars(line) for line in decoded_content.splitlines()], isyaml
                except Exception:
                    res = js_render(url)
                    if res and 'external-controller' in res.html.text:
                        try:
                            yaml_data = yaml.safe_load(res.html.text)
                        except Exception:
                            yaml_data = match_nodes(res.html.text)
                        if 'proxies' in yaml_data:
                            isyaml = True
                            for proxy in yaml_data['proxies']:
                                if 'name' in proxy:
                                    proxy['name'] = remove_invalid_yaml_chars(proxy['name'])
                            logger.info(f"从 JavaScript 渲染解析到 {len(yaml_data['proxies'])} 个 YAML 节点")
                            return yaml_data['proxies'], isyaml
                    else:
                        pattern = r'([A-Za-z0-9_+/\-]+={0,2})'
                        matches = re.findall(pattern, res.html.text if res else '')
                        stdout = matches[-1] if matches else []
                        decoded_bytes = base64.b64decode(stdout)
                        decoded_content = decoded_bytes.decode('utf-8')
                        logger.info(f"从 JavaScript 渲染 Base64 解码得到 {len(decoded_content.splitlines())} 行")
                        return [remove_invalid_yaml_chars(line) for line in decoded_content.splitlines()], isyaml
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
        # 清理名称以确保一致性
        if 'name' in proxy:
            proxy['name'] = remove_invalid_yaml_chars(proxy['name'])
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
            logger.warning(f"跳过无效或不支持的链接: {new_link[:50]}...")

def generate_clash_config(links, load_nodes):
    logger.info("开始生成 Clash 配置文件")
    all_proxies = load_nodes
    isyaml = True
    for link in links:
        if link.startswith(("http", "https")):
            proxies_from_url, is_yaml_from_url = process_url(link)
            if is_yaml_from_url:
                all_proxies.extend(proxies_from_url)
            else:
                for proxy_link in proxies_from_url:
                    node = parse_proxy_link(proxy_link)
                    if node:
                        all_proxies.append(node)
        elif link.startswith("ss://") and urllib.parse.urlparse(link).netloc:
            # 这是一个 ss 订阅链接
            proxies_from_ss_sub = parse_ss_sub(link)
            all_proxies.extend(proxies_from_ss_sub)
        elif link.startswith("base64"):
            try:
                decoded_bytes = base64.b64decode(link[7:])
                decoded_content = decoded_bytes.decode('utf-8')
                for proxy_link in decoded_content.splitlines():
                    node = parse_proxy_link(proxy_link)
                    if node:
                        all_proxies.append(node)
            except Exception as e:
                logger.error(f"Base64 解码链接失败: {e}")
        elif link.startswith(("ss", "vmess", "vless", "trojan", "hy2", "hysteria2")):
            node = parse_proxy_link(link)
            if node:
                all_proxies.append(node)
        elif ".md" in link:
            links_from_md = parse_md_link(link)
            for proxy_link in links_from_md:
                node = parse_proxy_link(proxy_link)
                if node:
                    all_proxies.append(node)
        else:
            logger.warning(f"跳过不支持的链接: {link}")

    # 再次遍历所有代理，进行名称清理，作为最终的保障
    for proxy in all_proxies:
        if 'name' in proxy:
            proxy['name'] = remove_invalid_yaml_chars(proxy['name'])
    
    unique_proxies = deduplicate_proxies(all_proxies)
    
    if not unique_proxies:
        logger.error("没有可用的节点，无法生成配置文件。")
        return

    # 在这里，对所有代理名称进行一次统一的清理，防止重复
    proxy_names = [proxy['name'] for proxy in unique_proxies]
    unique_names = set()
    for proxy in unique_proxies:
        original_name = proxy['name']
        if original_name in unique_names:
            proxy['name'] = add_random_suffix(original_name, unique_names)
        unique_names.add(proxy['name'])

    clash_config = clash_config_template.copy()
    clash_config["proxies"] = unique_proxies

    # 更新代理组
    for group in clash_config["proxy-groups"]:
        if group["name"] in ["自动选择", "故障转移", "手动选择"]:
            group["proxies"] = [p["name"] for p in unique_proxies if not any(b in p["name"] for b in BAN)]

    with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
    
    logger.info(f"生成 Clash 配置文件: {CONFIG_FILE} 和 {CONFIG_FILE}.json")
    
    # 额外生成一个 json 文件
    with open(f"{CONFIG_FILE}.json", 'w', encoding='utf-8') as f:
        json.dump(clash_config, f, ensure_ascii=False, indent=4)

def kill_clash():
    logger.info("尝试终止 Clash 进程")
    current_os = platform.system()
    try:
        if current_os == "Windows":
            subprocess.run(["taskkill", "/F", "/IM", "clash.exe"], check=False, creationflags=subprocess.CREATE_NO_WINDOW)
            subprocess.run(["taskkill", "/F", "/IM", "mihomo.exe"], check=False, creationflags=subprocess.CREATE_NO_WINDOW)
        else:
            pids = psutil.pids()
            for pid in pids:
                try:
                    process = psutil.Process(pid)
                    if "clash" in process.name().lower() or "mihomo" in process.name().lower():
                        process.kill()
                        logger.info(f"已终止进程 {process.name()} (PID: {pid})")
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
    except Exception as e:
        logger.error(f"终止 Clash 进程失败: {e}")
    logger.info("Clash 进程终止检查完成")

def start_clash():
    clash_binary = "./mihomo/mihomo-linux-amd64-compatible-v1.19.13"
    
    if not os.path.exists(clash_binary):
        logger.error(f"Clash 二进制文件 {clash_binary} 不存在")
        raise FileNotFoundError(f"{clash_binary}")
    
    os.chmod(clash_binary, 0o755)
    logger.info(f"设置文件 {clash_binary} 为可执行")

    clash_process = subprocess.Popen(
        [clash_binary, "-f", CONFIG_FILE, "-d", "."],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    
    # 等待 Clash 启动
    time.sleep(1)
    
    for line in clash_process.stdout:
        logger.info(f"Clash 输出: {line.strip()}")
        if "External controller listening at" in line:
            return clash_process
        if "Parse config error" in line:
            logger.error(f"配置解析错误: {line.strip()}")
            raise ValueError(f"配置解析错误: {line.strip()}")
    
    logger.error("Clash 进程未能启动或未能输出监听信息。")
    clash_process.kill()
    raise RuntimeError("Clash 进程启动失败。")

def check_proxy_health(proxy_name):
    url = f"http://{CLASH_API_HOST}:{CLASH_API_PORTS[0]}/proxies/{proxy_name}/healthcheck"
    try:
        response = requests.get(url, headers={'Authorization': f'Bearer {CLASH_API_SECRET}'}, timeout=5)
        response.raise_for_status()
        return response.status_code == 200
    except requests.RequestException as e:
        logger.warning(f"代理 {proxy_name} 健康检查失败: {e}")
        return False

def get_proxy_delay(proxy_name):
    url = f"http://{CLASH_API_HOST}:{CLASH_API_PORTS[0]}/proxies/{proxy_name}/delay?url={urllib.parse.quote(TEST_URL)}&timeout=5000"
    try:
        response = requests.get(url, headers={'Authorization': f'Bearer {CLASH_API_SECRET}'}, timeout=5)
        response.raise_for_status()
        data = response.json()
        delay = data.get('delay', -1)
        return delay
    except requests.RequestException as e:
        logger.error(f"获取代理 {proxy_name} 延迟失败: {e}")
        return -1

def switch_proxy(group_name, proxy_name):
    url = f"http://{CLASH_API_HOST}:{CLASH_API_PORTS[0]}/group/{urllib.parse.quote(group_name)}"
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {CLASH_API_SECRET}'
    }
    data = {"name": proxy_name}
    try:
        response = requests.put(url, headers=headers, data=json.dumps(data), timeout=5)
        response.raise_for_status()
        return True
    except requests.RequestException as e:
        logger.error(f"切换代理失败: {e}")
        return False

def get_proxies_from_api():
    url = f"http://{CLASH_API_HOST}:{CLASH_API_PORTS[0]}/proxies"
    headers = {'Authorization': f'Bearer {CLASH_API_SECRET}'}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        response.raise_for_status()
        data = response.json()
        return data.get('proxies', {})
    except requests.RequestException as e:
        logger.error(f"获取代理列表失败: {e}")
        return {}

async def proxy_clean():
    logger.info("开始进行代理清理和测速")
    try:
        proxies_data = get_proxies_from_api()
        if not proxies_data:
            logger.error("无法获取代理列表，跳过测速。")
            return

        all_proxies = proxies_data.keys()
        exclude_proxies = ['DIRECT', '节点选择', '自动选择', '故障转移', '手动选择']
        proxies_to_test = [p for p in all_proxies if p not in exclude_proxies]
        
        logger.info(f"共找到 {len(proxies_to_test)} 个代理需要测速。")

        results = []
        semaphore = Semaphore(MAX_CONCURRENT_TESTS)

        async def test_proxy(proxy_name):
            async with semaphore:
                delay = get_proxy_delay(proxy_name)
                return proxy_name, delay

        tasks = [test_proxy(p) for p in proxies_to_test]

        # 添加进度条
        wrapped_tasks = tqdm(tasks, total=len(tasks), desc="测速进度", unit="节点")
        results = await asyncio.gather(*wrapped_tasks)

        sorted_results = sorted(results, key=lambda x: x[1])
        valid_proxies = [
            name for name, delay in sorted_results 
            if delay > 0 and not any(b in name for b in BAN)
        ][:NODE_OUTPUT_LIMIT]
        
        if not valid_proxies:
            logger.warning("没有可用的代理节点。")
            return
        
        logger.info("测速完成，结果如下:")
        for name, delay in sorted_results:
            logger.info(f"{name}: {delay}ms")

        # 重新生成配置文件
        clash_config = clash_config_template.copy()
        
        proxies_map = {p['name']: p for p in clash_config['proxies']}
        
        # 重新组织代理列表，将可用代理放在前面
        new_proxies_list = [proxies_map[name] for name in valid_proxies if name in proxies_map]
        
        clash_config["proxies"] = new_proxies_list
        
        for group in clash_config["proxy-groups"]:
            if group["name"] in ["自动选择", "故障转移", "手动选择"]:
                group["proxies"] = valid_proxies
        
        with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
            yaml.dump(clash_config, f, allow_unicode=True, sort_keys=False)
            
        logger.info("已根据测速结果重新生成配置文件。")
        return sorted_results
    except Exception as e:
        logger.error(f"代理清理和测速失败: {e}")
        return []

def main(links):
    check = True
    only_check = False
    allowed_types = ['ss', 'hysteria2', 'hy2', 'vless', 'vmess', 'trojan']

    try:
        kill_clash()  # 确保旧的 Clash 进程被终止
        if not only_check:
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
                switch_proxy('节点选择', '自动选择')
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
    initial_links = [
        "https://raw.githubusercontent.com/qjlxg/HA/main/link.yaml"
    ]
    main(links=initial_links)
