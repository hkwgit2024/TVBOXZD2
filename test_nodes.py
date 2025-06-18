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
import sys
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# 确保日志实时输出
def log(message):
    print(f"[{datetime.now()}] {message}", flush=True)

# 确保 data 目录存在
if not os.path.exists("data"):
    os.makedirs("data")

# 目标 URL 和输出文件
url = "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
output_file = "data/collectSub.txt"
speedtest_log = "data/speedtest_errors.log"

# 环境检查
log(f"Python 版本: {sys.version}")
log(f"依赖检查: requests={requests.__version__}, speedtest-cli={'installed' if 'speedtest' in sys.modules else 'not installed'}, pysocks={'installed' if 'socks' in sys.modules else 'not installed'}")

# 下载最新 sing-box 二进制文件
def download_sing_box():
    sing_box_bin = "./sing-box"
    if not os.path.exists(sing_box_bin):
        log("开始下载 sing-box")
        api_url = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
        session = requests.Session()
        retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
        session.mount("https://", HTTPAdapter(max_retries=retries))
        try:
            response = session.get(api_url, headers={"Accept": "application/vnd.github+json"}, timeout=10)
            response.raise_for_status()
            release = response.json()
            sing_box_url = None
            for asset in release["assets"]:
                if "linux-amd64" in asset["name"] and asset["name"].endswith(".tar.gz"):
                    sing_box_url = asset["browser_download_url"]
                    break
            if not sing_box_url:
                raise Exception("未找到适用于 linux-amd64 的 sing-box 二进制文件")
            log(f"下载 sing-box tar 文件: {sing_box_url}")
            sing_box_tar = "sing-box.tar.gz"
            with urllib.request.urlopen(sing_box_url, timeout=30) as response, open(sing_box_tar, "wb") as f:
                f.write(response.read())
            pre_dirs = set(glob.glob("sing-box*"))
            subprocess.run(["tar", "-xzf", sing_box_tar], check=True, timeout=30)
            binary_paths = glob.glob("**/sing-box", recursive=True) or glob.glob("sing-box")
            if not binary_paths:
                raise Exception("未找到解压后的 sing-box 二进制文件")
            subprocess.run(["mv", binary_paths[0], sing_box_bin], check=True, timeout=10)
            subprocess.run(["chmod", "+x", sing_box_bin], check=True, timeout=10)
            if os.path.exists(sing_box_tar):
                os.remove(sing_box_tar)
            post_dirs = set(glob.glob("sing-box*"))
            for dir_path in post_dirs - pre_dirs:
                if os.path.isdir(dir_path):
                    subprocess.run(["rm", "-rf", dir_path], check=True, timeout=10)
        except Exception as e:
            log(f"下载 sing-box 失败: {str(e)}")
            raise
    log("sing-box 下载完成")
    return sing_box_bin

# 解析节点配置
def parse_node(line):
    log(f"解析节点: {line[:50]}...")
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
                log(f"解析 ss 节点失败 ({line[:50]}...): 无效 base64 编码 - {str(e)}")
            except ValueError as e:
                log(f"解析 ss 节点失败 ({line[:50]}...): {str(e)}")
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
                log(f"解析 ss 节点失败 ({line[:50]}...): 非 base64 格式解析错误 - {str(e)}")
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
        log(f"解析节点失败 ({line[:50]}...): {str(e)}")
        return None

# 生成 sing-box 配置文件
def generate_sing_box_config(node, temp_config_file):
    log(f"生成 sing-box 配置文件: {node['ip']}:{node['port']} ({node['type']})")
    config = {
        "log": {"level": "info"},
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
        "dns": {
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
    log("开始 HTTP 连通性测试")
    try:
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 1080)
        socket.socket = socks.socksocket
        response = requests.get("http://ipinfo.io/json", timeout=10)
        if response.status_code == 200:
            log(f"HTTP 连通性测试通过: {response.json().get('ip')}")
            return True
        else:
            log(f"HTTP 连通性测试失败: 状态码 {response.status_code}")
            return False
    except Exception as e:
        log(f"HTTP 连通性测试失败: {str(e)}")
        return False
    finally:
        socks.set_default_proxy(None)
        socket.socket = socket._socket.socket

# 测试连通性
def test_connectivity(sing_box_bin, config_file):
    log("开始连通性测试")
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
            ["nc", "-zv", "127.0.0.1", "1080", "-w", "1"],
            capture_output=True,
            text=True,
            timeout=2
        )
        if sock_test.returncode == 0:
            log("sing-box SOCKS5 代理已启动并监听")
            return True
        else:
            stderr = process.stderr.read()
            log(f"sing-box SOCKS5 代理未成功监听: {sock_test.stderr.strip()}")
            if stderr:
                log(f"sing-box 错误输出: {stderr.strip()}")
            return False
    except FileNotFoundError:
        log("nc 或 sing-box 命令未找到，请确保已安装 netcat 和 sing-box")
        return False
    except subprocess.TimeoutExpired:
        log("连接 SOCKS5 端口超时")
        return False
    except Exception as e:
        log(f"连通性测试失败 (sing-box 启动): {str(e)}")
        return False
    finally:
        if process:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()

# 测试下载和上传速度（使用 speedtest-cli Python 库）
def test_download_speed(sing_box_bin, config_file):
    log("开始速度测试")
    proxy_process = None
    try:
        proxy_process = subprocess.Popen(
            [sing_box_bin, "run", "-c", config_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        time.sleep(10)
        log("代理环境变量: socks5://127.0.0.1:1080")
        if not test_http_connectivity():
            log("跳过 speedtest，因 HTTP 连通性测试失败")
            return 0, 0, 0
        import speedtest
        s = speedtest.Speedtest()
        s.get_best_server()
        s.download()
        s.upload()
        results = s.results.dict()
        download_mbps = results["download"] / 1_000_000
        upload_mbps = results["upload"] / 1_000_000
        ping_latency = results["ping"]
        log(f"速度测试完成: 下载 {download_mbps:.2f} Mbps, 上传 {upload_mbps:.2f} Mbps, 延迟 {ping_latency:.2f} ms")
        return download_mbps, upload_mbps, ping_latency
    except ImportError:
        log("speedtest-cli 库未安装，请运行 `pip install speedtest-cli`")
        return 0, 0, 0
    except Exception as e:
        log(f"速度测试失败: {str(e)}")
        with open(speedtest_log, "a") as f:
            f.write(f"[{datetime.now()}] 速度测试失败: {str(e)}\n")
        return 0, 0, 0
    finally:
        if proxy_process:
            stderr = proxy_process.stderr.read()
            if stderr:
                with open(speedtest_log, "a") as f:
                    f.write(f"[{datetime.now()}] sing-box 错误输出: {stderr.strip()}\n")
            proxy_process.terminate()
            try:
                proxy_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy_process.kill()

# 主函数
def main():
    log("脚本开始运行")
    try:
        sing_box_bin = download_sing_box()
    except Exception as e:
        log(f"初始化失败: {str(e)}")
        return
    log("开始下载节点文件")
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    try:
        response = session.get(url, timeout=10)
        response.raise_for_status()
        with open("nodes.txt", "w", encoding="utf-8") as f:
            f.write(response.text)
    except Exception as e:
        log(f"下载节点文件失败: {str(e)}")
        return
    log("节点文件下载完成")
    results = []
    node_count = 0
    max_nodes = 100  # 限制测试节点数量
    with open("nodes.txt", "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if node_count >= max_nodes:
                log(f"达到最大节点限制 ({max_nodes})，停止解析")
                break
            line = line.strip()
            if not line:
                continue
            node = parse_node(line)
            if not node:
                continue
            node_count += 1
            log(f"测试节点: {node['ip']}:{node['port']} ({node['type']})")
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as temp_config:
                generate_sing_box_config(node, temp_config.name)
                is_connected = test_connectivity(sing_box_bin, temp_config.name)
                download_mbps, upload_mbps, ping_latency = 0, 0, 0
                if is_connected:
                    download_mbps, upload_mbps, ping_latency = test_download_speed(sing_box_bin, temp_config.name)
                results.append({
                    "node": node["raw"],
                    "ip": node["ip"],
                    "port": node["port"],
                    "type": node["type"],
                    "connected": is_connected,
                    "download_mbps": round(download_mbps, 2),
                    "upload_mbps": round(upload_mbps, 2),
                    "ping_latency_ms": round(ping_latency, 2),
                })
                os.unlink(temp_config.name)
    results.sort(key=lambda x: x["download_mbps"], reverse=True)
    with open(output_file, "w", encoding="utf-8") as f:
        for result in results:
            f.write(json.dumps(result, ensure_ascii=False) + "\n")
    log(f"测试完成，结果已保存到 {output_file}")

if __name__ == "__main__":
    main()
