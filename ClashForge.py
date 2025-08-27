# -*- coding: utf-8 -*-
#!/usr/bin/env python3
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

# 全局配置
TEST_URL = "http://www.pinterest.com"
CLASH_API_PORTS = [9090]
CLASH_API_HOST = "127.0.0.1"
CLASH_API_SECRET = ""
TIMEOUT = 3
SPEED_TEST = False
results_speed = []
MAX_CONCURRENT_TESTS = 100
LIMIT = 1086
CONFIG_FILE = 'clash_config.yaml'
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

def parse_hysteria2_link(link):
    try:
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
    except Exception:
        return None

def parse_ss_link(link):
    try:
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
    except Exception:
        return None

def parse_trojan_link(link):
    try:
        link = link[9:]
        config_part, name = link.split('#')
        user_info, host_info = config_part.split('@')
        password = user_info
        host, port_and_query = host_info.split(':', 1) if ':' in host_info else (host_info, "")
        port, query = port_and_query.split('?', 1) if '?' in port_and_query else (port_and_query, "")
        if not all([password, host, port]):
            return None
        return {
            "name": urllib.parse.unquote(name),
            "type": "trojan",
            "server": host,
            "port": int(port),
            "password": password,
            "sni": urllib.parse.parse_qs(query).get("sni", [""])[0],
            "skip-cert-verify": urllib.parse.parse_qs(query).get("skip-cert-verify", ["false"])[0] == "true"
        }
    except Exception:
        return None

def parse_vless_link(link):
    try:
        link = link[8:]
        config_part, name = link.split('#')
        uuid = config_part.split('@')[0]
        host_info = config_part.split('@')[1]
        host, query = host_info.split('?', 1) if '?' in host_info else (host_info, "")
        port = host.split(':')[-1] if ':' in host else ""
        host = host.split(':')[0] if ':' in host else ""
        if not all([uuid, host, port]):
            return None
        query_params = urllib.parse.parse_qs(query)
        network = query_params.get("type", ["tcp"])[0]
        ws_opts = {}
        if network == "ws":
            ws_opts = {
                "path": query_params.get("path", [""])[0],
                "headers": {
                    "Host": query_params.get("host", [""])[0]
                }
            }
        security = query_params.get("security", ["none"])[0]
        return {
            "name": urllib.parse.unquote(name),
            "type": "vless",
            "server": host,
            "port": int(port),
            "uuid": uuid,
            "security": security,
            "tls": security == "tls",
            "sni": query_params.get("sni", [""])[0],
            "skip-cert-verify": query_params.get("skip-cert-verify", ["false"])[0] == "true",
            "network": network,
            "ws-opts": ws_opts
        }
    except Exception:
        return None

def parse_vmess_link(link):
    try:
        link = link[8:]
        decoded_link = base64.urlsafe_b64decode(link + '=' * (-len(link) % 4)).decode("utf-8")
        vmess_info = json.loads(decoded_link)
        network = vmess_info.get("net", "tcp")
        ws_opts = {}
        if network == "ws":
            ws_opts = {
                "path": vmess_info.get("path", ""),
                "headers": {
                    "Host": vmess_info.get("host", "")
                }
            }
        return {
            "name": urllib.parse.unquote(vmess_info.get("ps", "vmess")),
            "type": "vmess",
            "server": vmess_info["add"],
            "port": int(vmess_info["port"]),
            "uuid": vmess_info["id"],
            "alterId": int(vmess_info.get("aid", 0)),
            "cipher": "auto",
            "network": network,
            "tls": vmess_info.get("tls", "") == "tls",
            "sni": vmess_info.get("sni", ""),
            "ws-opts": ws_opts
        }
    except Exception:
        return None

async def parse_ss_sub(link):
    new_links = []
    try:
        async with httpx.AsyncClient(headers=headers, timeout=TIMEOUT, verify=False, follow_redirects=True) as client:
            response = await client.get(link)
            response.raise_for_status()
            data = response.json()
            new_links = [{"name": x['remarks'], "type": "ss", "server": x['server'], "port": int(x['server_port']), "cipher": x['method'],"password": x['password'], "udp": True} for x in data]
            return new_links
    except httpx.RequestError as e:
        print(f"请求错误: {e}")
        return new_links

async def parse_md_link(link):
    try:
        async with httpx.AsyncClient(timeout=TIMEOUT) as client:
            response = await client.get(link)
            response.raise_for_status()
            content = response.text
            content = urllib.parse.unquote(content)
            pattern = r'(?:vless|vmess|trojan|hysteria2|ss):\/\/[^#\s]*(?:#[^\s]*)?'
            matches = re.findall(pattern, content)
            return matches
    except httpx.RequestError as e:
        print(f"请求错误: {e}")
        return []

def js_render(url):
    session = None
    try:
        timeout = 4
        if timeout > 15:
            timeout = 15
        browser_args = ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--disable-software-rasterizer','--disable-setuid-sandbox']
        session = HTMLSession(browser_args=browser_args)
        r = session.get(f'{url}', headers=headers, timeout=timeout, verify=False)
        r.html.render(timeout=timeout)
        return r
    except Exception as e:
        print(f"JS渲染失败: {e}")
        return None
    finally:
        if session:
            session.close()

def match_nodes(text):
    proxy_pattern = r"\{[^}]*name\s*:\s*['\"][^'\"]+['\"][^}]*server\s*:\s*[^,]+[^}]*\}"
    nodes = re.findall(proxy_pattern, text, re.DOTALL)
    proxies_list = []
    for node in nodes:
        try:
            node_dict = yaml.safe_load(node)
            proxies_list.append(node_dict)
        except yaml.YAMLError:
            continue
    return {"proxies": proxies_list}

async def process_url(url):
    isyaml = False
    try:
        async with httpx.AsyncClient(headers=headers, timeout=TIMEOUT, verify=False, follow_redirects=True) as client:
            response = await client.get(url)
            response.raise_for_status()
            content = response.content.decode('utf-8')
            if 'proxies:' in content:
                if '</pre>' in content:
                    content = content.replace('<pre style="word-wrap: break-word; white-space: pre-wrap;">','').replace('</pre>','')
                yaml_data = yaml.safe_load(content)
                if 'proxies' in yaml_data:
                    isyaml = True
                    return yaml_data['proxies'] if yaml_data['proxies'] else [], isyaml
            else:
                try:
                    decoded_bytes = base64.b64decode(content)
                    decoded_content = decoded_bytes.decode('utf-8')
                    decoded_content = urllib.parse.unquote(decoded_content)
                    return decoded_content.splitlines(), isyaml
                except Exception:
                    print(f"尝试JS渲染页面 {url}")
                    res = js_render(url)
                    if res and 'external-controller' in res.html.text:
                        try:
                            yaml_data = yaml.safe_load(res.html.text)
                        except yaml.YAMLError:
                            yaml_data = match_nodes(res.html.text)
                        if 'proxies' in yaml_data:
                            isyaml = True
                            return yaml_data['proxies'], isyaml
                    elif res:
                        pattern = r'([A-Za-z0-9_+/\-]+={0,2})'
                        matches = re.findall(pattern, res.html.text)
                        stdout = matches[-1] if matches else []
                        if stdout:
                            decoded_bytes = base64.b64decode(stdout)
                            decoded_content = decoded_bytes.decode('utf-8')
                            return decoded_content.splitlines(), isyaml
                    return [], isyaml
    except httpx.RequestException as e:
        print(f"请求 {url} 失败: {e}")
        return [], isyaml
    except Exception as e:
        print(f"处理 {url} 时出错: {e}")
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
        print(f"解析链接 {link} 失败: {e}")
        return None
    
def deduplicate_proxies(proxies_list):
    unique_proxies = []
    seen = set()
    for proxy in proxies_list:
        server = proxy.get('server')
        port = proxy.get('port')
        node_type = proxy.get('type')
        password = proxy.get('password')
        if not all([server, port, node_type]):
            continue
        key = (server, port, node_type, password) if password else (server, port, node_type)
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
            print(f"读取文件 {file_path} 失败: {e}")
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
            print(f"读取文件 {file_path} 失败: {e}")
    if load_nodes:
        print(f'加载【{folder_path}】目录下yaml/yml中所有节点')
    return load_nodes

def filter_by_types_alt(allowed_types,nodes):
    return [x for x in nodes if x.get('type') in allowed_types]

def merge_lists(*lists):
    return [item for item in chain.from_iterable(lists) if item != '']

async def handle_link(link, resolve_name_conflicts):
    if link.startswith(("hysteria2://", "hy2://", "trojan://", "ss://", "vless://", "vmess://")):
        node = parse_proxy_link(link)
        if node:
            resolve_name_conflicts(node)
    else:
        try:
            new_links = []
            if '|links' in link or '.md' in link:
                new_links = await parse_md_link(link.replace('|links', ''))
            elif '|ss' in link:
                new_links = await parse_ss_sub(link.replace('|ss', ''))
            elif '{' in link:
                link = resolve_template_url(link)
                new_links, _ = await process_url(link)
            else:
                new_links_or_nodes, isyaml = await process_url(link)
                if isyaml:
                    for node in new_links_or_nodes:
                        resolve_name_conflicts(node)
                    return
                else:
                    new_links = new_links_or_nodes

            for new_link in new_links:
                node = parse_proxy_link(new_link)
                if node:
                    resolve_name_conflicts(node)
        except Exception as e:
            print(f"处理链接 {link} 时发生错误: {e}")

async def generate_clash_config(links, load_nodes):
    print(f"当前时间: {datetime.now()}\n---")
    final_nodes = []
    existing_names = set()
    config = clash_config_template.copy()

    def resolve_name_conflicts(node):
        server = node.get("server")
        if not server:
            return
        name = str(node.get("name", "无名称节点"))
        if not_contains(name):
            if name in existing_names:
                name = add_random_suffix(name, existing_names)
            existing_names.add(name)
            node["name"] = name
            final_nodes.append(node)
    
    # 异步处理所有链接
    tasks = [handle_link(link, resolve_name_conflicts) for link in links]
    await asyncio.gather(*tasks)

    # 处理本地加载的节点
    for node in load_nodes:
        resolve_name_conflicts(node)
    
    # 去重
    final_nodes = deduplicate_proxies(final_nodes)
    print(f"总共获取 {len(final_nodes)} 个节点")

    config["proxy-groups"][1]["proxies"] = []
    for node in final_nodes:
        name = str(node["name"])
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
            json.dump(config, f, ensure_ascii=False, indent=2)
        print(f"已经生成Clash配置文件 {CONFIG_FILE} 和 {CONFIG_FILE}.json")
    else:
        print('没有节点数据更新')

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
            file.write(json.dumps(config,ensure_ascii=False, indent=2))
        print(f'配置异常：{error_message}修复配置异常，移除proxy[{problem_index}] {problem_proxy_name} 完毕，耗时{time.time() - start_time}s\n')
        return True
    except Exception as e:
        print(f"处理配置文件时出错: {str(e)}")
        return False

def download_and_extract_latest_release():
    url = "https://api.github.com/repos/MetaCubeX/mihomo/releases/latest"
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Failed to retrieve data from GitHub API: {e}")
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
        print(f"下载文件: {download_url}")
        filename = download_url.split('/')[-1]
        try:
            response = requests.get(download_url, stream=True, timeout=30)
            response.raise_for_status()
            with open(filename, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            print("下载完成，开始解压...")
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
                    print(f"重命名文件为: {new_name}")
                    break
            
            os.remove(filename)
            print("清理下载文件完成。")
        except Exception as e:
            print(f"下载或解压时出错: {e}")
    else:
        print("未找到适合当前操作系统的版本。")

def read_output(pipe, output_lines):
    try:
        while True:
            line = pipe.readline()
            if line:
                output_lines.append(line.strip())
            else:
                break
    except Exception as e:
        print(f"读取Clash输出时出错: {e}")

def kill_clash():
    system = platform.system()
    clash_process_names = {
        "Windows": "clash.exe",
        "Linux": "clash-linux",
        "Darwin": "clash-darwin"
    }
    config_files = ["clash_config.yaml", "clash_config.yaml.json"]
    if system not in clash_process_names:
        return
    process_name = clash_process_names[system]
    for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
        try:
            if proc.info['name'] != process_name:
                continue
            cmdline = proc.info['cmdline']
            if cmdline and len(cmdline) >= 3 and cmdline[1] == '-f' and cmdline[2] in config_files:
                print(f"终止旧的Clash进程: PID {proc.info['pid']}")
                proc.kill()
                time.sleep(1) # 等待进程终止
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
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
        raise OSError("不支持的操作系统。")

    global CONFIG_FILE
    CONFIG_FILE = f'{CONFIG_FILE}.json' if os.path.exists(f'{CONFIG_FILE}.json') else CONFIG_FILE

    retries = 3
    for i in range(retries):
        print(f"尝试启动Clash进程... (第 {i+1} 次)")
        clash_process = subprocess.Popen(
            [clash_binary, '-f', CONFIG_FILE],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            bufsize=1
        )
        output_lines = []
        stdout_thread = threading.Thread(target=read_output, args=(clash_process.stdout, output_lines))
        stdout_thread.daemon = True
        stdout_thread.start()
        
        start_time = time.time()
        while time.time() - start_time < 5:
            if is_clash_api_running():
                print("Clash API已成功启动。")
                return clash_process
            time.sleep(0.5)

        print("Clash API未在预期时间内启动，检查日志...")
        stdout_thread.join(timeout=1)
        if any("Parse config error" in line for line in output_lines):
            error_line = [line for line in output_lines if "Parse config error" in line][-1]
            if handle_clash_error(error_line, CONFIG_FILE):
                clash_process.kill()
                clash_process.wait()
                print("已修复配置错误，准备重试。")
                continue
            else:
                print("无法修复配置错误，终止。")
                clash_process.kill()
                clash_process.wait()
                return None
        
        print("Clash启动失败，或日志中无错误信息，可能是端口占用或其他问题。")
        clash_process.kill()
        clash_process.wait()

    return None

def is_clash_api_running():
    try:
        url = f"http://{CLASH_API_HOST}:{CLASH_API_PORTS[0]}/configs"
        response = requests.get(url, timeout=3)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

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

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.client.aclose()

    async def check_connection(self) -> bool:
        for port in self.ports:
            try:
                test_url = f"http://{self.host}:{port}"
                response = await self.client.get(f"{test_url}/version", timeout=TIMEOUT)
                if response.status_code == 200:
                    version = response.json().get('version', 'unknown')
                    print(f"成功连接到 Clash API (端口 {port})，版本: {version}")
                    self.base_url = test_url
                    return True
            except httpx.RequestError:
                print(f"端口 {port} 连接失败，尝试下一个端口...")
                continue
        print("所有端口均连接失败。请确保 Clash 正在运行。")
        return False

    async def get_proxies(self) -> Dict:
        if not self.base_url:
            raise ClashAPIException("未建立与 Clash API 的连接")
        try:
            response = await self.client.get(f"{self.base_url}/proxies", headers=self.headers)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 401:
                print("认证失败，请检查 API Secret 是否正确")
            raise ClashAPIException(f"HTTP 错误: {e}")
        except httpx.RequestError as e:
            raise ClashAPIException(f"请求错误: {e}")

    async def test_proxy_delay(self, proxy_name: str) -> ProxyTestResult:
        if not self.base_url:
            return ProxyTestResult(proxy_name)
        if proxy_name in self._test_results_cache:
            cached_result = self._test_results_cache[proxy_name]
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
                print(f"测试节点 {proxy_name} 失败: {e}")
                result = ProxyTestResult(proxy_name)
            finally:
                self._test_results_cache[proxy_name] = result
                return result

class ClashConfig:
    def __init__(self, config_path: str):
        self.config_path = config_path
        self.config = self._load_config()
        self.proxy_groups = self.config.get("proxy-groups", [])

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
        if "proxies" in self.config:
            self.config["proxies"] = [p for p in self.config["proxies"] if p.get("name") not in invalid_proxies]
        for group in self.proxy_groups:
            if "proxies" in group:
                group["proxies"] = [p for p in group["proxies"] if p not in invalid_proxies]
        left = LIMIT if len(self.config['proxies']) > LIMIT else len(self.config['proxies'])
        print(f"已从配置中移除 {len(invalid_proxies)} 个失效节点，最终保留{left}个延迟最小的节点")

    def keep_proxies_by_limit(self, proxy_names):
        if "proxies" in self.config:
            self.config["proxies"] = [p for p in self.config["proxies"] if p["name"] in proxy_names]

    def update_group_proxies(self, group_name: str, results: List[ProxyTestResult]):
        self.remove_invalid_proxies(results)
        valid_results = [r for r in results if r.is_valid]
        valid_results = list(set(valid_results))
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
                json.dump(self.config, f, ensure_ascii=False, indent=2)
            print("配置已保存。")
        except Exception as e:
            print(f"保存配置文件失败: {e}")
            sys.exit(1)

def print_test_summary(group_name: str, results: List[ProxyTestResult]):
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

async def test_group_proxies(clash_api: ClashAPI, proxies: List[str]) -> List[ProxyTestResult]:
    print(f"开始测试 {len(proxies)} 个节点 (最大并发: {MAX_CONCURRENT_TESTS})")
    tasks = [clash_api.test_proxy_delay(proxy_name) for proxy_name in proxies]
    results = []
    for i, future in enumerate(asyncio.as_completed(tasks)):
        result = await future
        results.append(result)
        done = i + 1
        total = len(tasks)
        print(f"\r进度: {done}/{total} ({done / total * 100:.1f}%)", end="", flush=True)
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
    print(f'加载配置文件 {CONFIG_FILE}')
    config = ClashConfig(CONFIG_FILE)
    available_groups = config.get_group_names()[1:]
    groups_to_test = available_groups
    if not groups_to_test:
        print("错误: 没有找到要测试的有效策略组")
        return
    print(f"\n将测试以下策略组: {', '.join(groups_to_test)}")
    start_time = datetime.now()
    async with ClashAPI(CLASH_API_HOST, CLASH_API_PORTS, CLASH_API_SECRET) as clash_api:
        if not await clash_api.check_connection():
            return
        try:
            all_test_results = []
            group_name = groups_to_test[0]
            print(f"\n======================== 开始测试策略组: {group_name} ====================")
            proxies = config.get_group_proxies(group_name)
            if not proxies:
                print(f"策略组 '{group_name}' 中没有代理节点")
            else:
                results = await test_group_proxies(clash_api, proxies)
                all_test_results.extend(results)
                delays = print_test_summary(group_name, results)
            print('\n===================移除失效节点并按延迟排序======================\n')
            config.remove_invalid_proxies(all_test_results)
            group_proxies = config.get_group_proxies(group_name)
            group_results = [r for r in all_test_results if r.name in group_proxies]
            if LIMIT:
                group_results = group_results[:LIMIT]
            proxy_names = {r.name for r in group_results}
            for group_name in groups_to_test:
                config.update_group_proxies(group_name, group_results)
                print(f"'{group_name}'已按延迟大小重新排序")
            if LIMIT:
                config.keep_proxies_by_limit(proxy_names)
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
    path_part = github_url.split(f'/{branch}/')[-1]
    path_part = re.sub(r'\{x\}' + re.escape(file_suffix) + '(?:/|$)', '', path_part)
    api_url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path_part}"
    response = requests.get(api_url, timeout=10)
    response.raise_for_status()
    files = response.json()
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

async def work(links, check=False, allowed_types=[], only_check=False):
    try:
        load_nodes = []
        if not only_check:
            if os.path.exists('input') and os.path.isdir('input'):
                load_nodes.extend(read_yaml_files(folder_path='input'))
                links.extend(read_txt_files(folder_path='input'))
            if allowed_types:
                load_nodes = filter_by_types_alt(allowed_types, nodes=load_nodes)
            links = merge_lists(links)
            if links or load_nodes:
                await generate_clash_config(links, load_nodes)

        if check or only_check:
            clash_process = None
            try:
                print(f"===================启动clash并初始化配置======================")
                clash_process = start_clash()
                if clash_process:
                    await proxy_clean()
                print(f'批量检测完毕')
            except Exception as e:
                print("调用Clash API时出错:", e)
            finally:
                print(f'关闭Clash进程')
                if clash_process is not None:
                    clash_process.kill()
                    clash_process.wait()

    except KeyboardInterrupt:
        print("\n用户中断执行")
        sys.exit(0)
    except Exception as e:
        print(f"程序执行失败: {e}")
        sys.exit(1)

if __name__ == '__main__':
    input_value = os.getenv("INPUT")
    links_from_env = []
    if input_value:
        split_links = [link.strip() for link in input_value.split(',')]
        for link in split_links:
            if link.startswith('http://') or link.startswith('https://'):
                links_from_env.append(link)
    
    asyncio.run(work(links=links_from_env, check=True, only_check=False, allowed_types=["ss","hysteria2","hy2","vless","vmess","trojan"]))
