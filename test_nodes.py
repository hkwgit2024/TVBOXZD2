import os
import re
import subprocess
import urllib.request
import json
import base64
import time
from urllib.parse import urlparse, parse_qs
import tempfile
import requests
import glob
from datetime import datetime
import binascii
import socks
import socket

# 确保 data 目录存在
if not os.path.exists("data"):
    os.makedirs("data")

# 目标 URL 和输出文件
url = "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
output_file = "data/collectSub.txt"
speedtest_log = "data/speedtest_errors.log"

# 下载最新 sing-box 二进制文件
def download_sing_box():
    sing_box_bin = "./sing-box"
    if not os.path.exists(sing_box_bin):
        api_url = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
        try:
            response = requests.get(api_url, headers={"Accept": "application/vnd.github+json"})
            response.raise_for_status()
            release = response.json()
            sing_box_url = None
            for asset in release["assets"]:
                if "linux-amd64" in asset["name"] and asset["name"].endswith(".tar.gz"):
                    sing_box_url = asset["browser_download_url"]
                    break
            if not sing_box_url:
                raise Exception("未找到适用于 linux-amd64 的 sing-box 二进制文件")
            sing_box_tar = "sing-box.tar.gz"
            urllib.request.urlretrieve(sing_box_url, sing_box_tar)
            pre_dirs = set(glob.glob("sing-box*"))
            subprocess.run(["tar", "-xzf", sing_box_tar], check=True)
            binary_paths = glob.glob("**/sing-box", recursive=True) or glob.glob("sing-box")
            if not binary_paths:
                raise Exception("未找到解压后的 sing-box 二进制文件")
            subprocess.run(["mv", binary_paths[0], sing_box_bin], check=True)
            subprocess.run(["chmod", "+x", sing_box_bin], check=True)
            if os.path.exists(sing_box_tar):
                os.remove(sing_box_tar)
            post_dirs = set(glob.glob("sing-box*"))
            for dir_path in post_dirs - pre_dirs:
                if os.path.isdir(dir_path):
                    subprocess.run(["rm", "-rf", dir_path], check=True)
        except Exception as e:
            print(f"[{datetime.now()}] 下载 sing-box 失败: {str(e)}")
            raise
    return sing_box_bin

# 解析节点配置
def parse_node(line):
    try:
        if line.startswith("hysteria2://"):
            url = urlparse(line)
            ip_port = url.netloc.split("@")[-1]
            ip, port = ip_port.split(":") if ":" in ip_port else (ip_port, "443")
            query = parse_qs(url.query)
            password = query.get("password", [""])[0]
            sni = query.get("sni", [""])[0]
            insecure = query.get("insecure", ["0"])[0] == "1"
            return {
                "type": "hysteria2",
                "ip": ip,
                "port": port,
                "password": password,
                "sni": sni,
                "insecure": insecure,
                "raw": line
            }
        elif line.startswith("ss://"):
            raw_config = line[5:].split("#")[0]
            # 尝试作为 base64 解码
            base64_str = re.sub(r'[^A-Za-z0-9+/=]', '', raw_config)
            base64_str = base64_str + "=" * (-len(base64_str) % 4)
            try:
                decoded = base64.b64decode(base64_str, validate=True).decode("utf-8", errors="ignore")
                if "@" not in decoded:
                    raise ValueError("解码后不包含 @ 分隔符")
                userinfo, ip_port = decoded.split("@")
                cipher, password = userinfo.split(":")
                ip, port = ip_port.split(":")
                if cipher not in ["aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305"]:
                    raise ValueError(f"不支持的 cipher: {cipher}")
                return {
                    "type": "ss",
                    "ip": ip,
                    "port": port,
                    "cipher": cipher,
                    "password": password,
                    "raw": line
                }
            except binascii.Error as e:
                print(f"[{datetime.now()}] 解析 ss 节点失败 ({line}): 无效 base64 编码 - {str(e)}")
            except ValueError as e:
                print(f"[{datetime.now()}] 解析 ss 节点失败 ({line}): {str(e)}")
            # 尝试非 base64 格式 (cipher:password@ip:port)
            try:
                if "@" in raw_config:
                    userinfo, ip_port = raw_config.split("@")
                    cipher, password = userinfo.split(":")
                    ip, port = ip_port.split(":")
                    if cipher not in ["aes-256-gcm", "aes-128-gcm", "chacha20-ietf-poly1305"]:
                        raise ValueError(f"不支持的 cipher: {cipher}")
                    return {
                        "type": "ss",
                        "ip": ip,
                        "port": port,
                        "cipher": cipher,
                        "password": password,
                        "raw": line
                    }
            except Exception as e:
                print(f"[{datetime.now()}] 解析 ss 节点失败 ({line}): 非 base64 格式解析错误 - {str(e)}")
            return None
        elif line.startswith("trojan://"):
            url = urlparse(line)
            userinfo, ip_port = url.netloc.split("@")
            password = userinfo
            ip, port = ip_port.split(":") if ":" in ip_port else (ip_port, "443")
            return {"type": "trojan", "ip": ip, "port": port, "password": password, "raw": line}
        elif line.startswith("vless://"):
            url = urlparse(line)
            userinfo, ip_port = url.netloc.split("@")
            uuid = userinfo
            ip, port = ip_port.split(":") if ":" in ip_port else (ip_port, "443")
            query = parse_qs(url.query)
            transport = query.get("type", ["tcp"])[0]
            return {
                "type": "vless",
                "ip": ip,
                "port": port,
                "uuid": uuid,
                "transport": transport,
                "raw": line
            }
        elif line.startswith("vmess://"):
            decoded = json.loads(base64.b64decode(line[8:]).decode("utf-8", errors="ignore"))
            transport = decoded.get("net", "tcp")
            return {
                "type": "vmess",
                "ip": decoded["add"],
                "port": str(decoded["port"]),
                "uuid": decoded["id"],
                "transport": transport,
                "raw": line
            }
        else:
            return None
    except Exception as e:
        print(f"[{datetime.now()}] 解析节点失败 ({line}): {str(e)}")
        return None

# 生成 sing-box 配置文件
def generate_sing_box_config(node, temp_config_file):
    config = {
        "log": {"level": "info"},  # 提高日志级别
        "inbounds": [
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": 1080
            }
        ],
        "outbounds": [
            {
                "type": node["type"],
                "tag": "proxy",
                "server": node["ip"],
                "server_port": int(node["port"]),
            }
        ],
        "route": {
            "rules": [
                {
                    "outbound": "proxy",
                    "ip_is_private": False
                }
            ]
        },
        "dns": {  # 添加 DNS 配置
            "servers": [
                {
                    "tag": "google",
                    "address": "8.8.8.8",
                    "detour": "proxy"
                }
            ]
        }
    }
    if node["type"] == "hysteria2":
        config["outbounds"][0]["password"] = node["password"]
        config["outbounds"][0]["tls"] = {
            "enabled": True,
            "server_name": node["sni"] if node["sni"] else node["ip"],
            "insecure": node["insecure"]
        }
    elif node["type"] == "ss":
        config["outbounds"][0]["method"] = node["cipher"]
        config["outbounds"][0]["password"] = node["password"]
    elif node["type"] == "trojan":
        config["outbounds"][0]["password"] = node["password"]
        config["outbounds"][0]["tls"] = {"enabled": True}
    elif node["type"] == "vless":
        config["outbounds"][0]["uuid"] = node["uuid"]
        config["outbounds"][0]["tls"] = {"enabled": True}
        if node["transport"] != "tcp":
            config["outbounds"][0]["transport"] = {"type": node["transport"]}
    elif node["type"] == "vmess":
        config["outbounds"][0]["uuid"] = node["uuid"]
        if node["transport"] != "tcp":
            config["outbounds"][0]["transport"] = {"type": node["transport"]}
    with open(temp_config_file, "w") as f:
        json.dump(config, f, indent=2)

# 测试 HTTP 连通性
def test_http_connectivity():
    try:
        # 设置 SOCKS5 代理
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 1080)
        socket.socket = socks.socksocket
        response = requests.get("http://ipinfo.io/json", timeout=10)
        if response.status_code == 200:
            print(f"[{datetime.now()}] HTTP 连通性测试通过: {response.json().get('ip')}")
            return True
        else:
            print(f"[{datetime.now()}] HTTP 连通性测试失败: 状态码 {response.status_code}")
            return False
    except Exception as e:
        print(f"[{datetime.now()}] HTTP 连通性测试失败: {str(e)}")
        return False
    finally:
        # 重置 socket
        socks.set_default_proxy(None)
        socket.socket = socket._socket.socket

# 测试连通性
def test_connectivity(sing_box_bin, config_file):
    process = None
    try:
        process = subprocess.Popen(
            [sing_box_bin, "run", "-c", config_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        time.sleep(2)
        sock_test = subprocess.run(
            ["nc", "-zv", "127.0.0.1", "1080", "-w
