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
import psutil

# 确保日志实时输出
def log(message):
    print(f"[{datetime.now()}] {message}", flush=True)

# 确保 data 目录存在
if not os.path.exists("data"):
    os.makedirs("data")

# 目标 URL 和输出文件
url = "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
output_file = "data/collectSub.txt"
speedtest_log = "data/speedtest_errors.log" # 用于记录总体速度测试失败和节点处理失败信息

# 环境检查
log(f"Python 版本: {sys.version}")
try:
    import speedtest
    speedtest_installed = "installed"
except ImportError:
    speedtest_installed = "not installed"
log(f"依赖检查: requests={requests.__version__}, speedtest-cli={speedtest_installed}, pysocks={'installed' if 'socks' in sys.modules else 'not installed'}")

# 清理残留 sing-box 进程
def kill_sing_box():
    for proc in psutil.process_iter(['name']):
        if proc.info['name'] == 'sing-box':
            log(f"发现残留 sing-box 进程 (PID: {proc.pid})，尝试终止")
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except psutil.TimeoutExpired:
                proc.kill()
                log(f"强制杀死 sing-box 进程 (PID: {proc.pid})")

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
                # 尝试非base64编码解析
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
def generate_sing_box_config(node, temp_config_file, log_file_path):
    log(f"生成 sing-box 配置文件: {node['ip']}:{node['port']} ({node['type']})")
    config = {
        "log": {
            "level": "debug",
            "output": log_file_path # 将日志输出到文件
        },
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
                {"tag": "google", "address": "8.8.8.8", "detour": "proxy"},
                {"tag": "cloudflare", "address": "1.1.1.1", "detour": "proxy"}
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
    try:
        with open(temp_config_file, "w") as f:
            json.dump(config, f, indent=2)
    except Exception as e:
        log(f"生成配置文件失败: {str(e)}")
        raise

# 自定义 HTTPAdapter，强制 IPv4
class SocksIPv4Adapter(HTTPAdapter):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, connections, max_runs, block=False):
        # 覆盖此方法以设置 socket_options
        self.poolmanager = self.PoolManager(
            num_pools=connections,
            maxsize=max_runs,
            block=block,
            # 设置 socket_options 来强制 IPv4
            socket_options=[
                (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            ]
        )

# 测试 HTTP 连通性
def test_http_connectivity():
    log("开始 HTTP 连通性测试")
    urls = ["http://ipinfo.io/json", "http://www.google.com"]

    for test_url in urls:
        log(f"测试 URL: {test_url}")
        try:
            # 设置 PySocks 为全局代理
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 1080)
            socket.socket = socks.socksocket
            
            session = requests.Session()
            retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
            
            # 使用自定义的 SocksIPv4Adapter 来强制 IPv4
            session.mount("http://", SocksIPv4Adapter(max_retries=retries))
            session.mount("https://", SocksIPv4Adapter(max_retries=retries)) 

            response = session.get(test_url, timeout=10)
            if response.status_code == 200:
                log(f"HTTP 连通性测试通过: {test_url}")
                return True
            else:
                log(f"HTTP 连通性测试失败: {test_url}, 状态码 {response.status_code}")
        except Exception as e:
            log(f"HTTP 连通性测试失败: {test_url}, 错误: {str(e)}")
        finally:
            # 恢复默认的 socket
            socks.set_default_proxy(None)
            socket.socket = socket._socket.socket

    log("所有 HTTP 测试 URL 均失败")
    return False

# 测试连通性 (检查 sing-box SOCKS5 代理是否在本地端口监听)
def test_connectivity(sing_box_bin, config_file):
    log("开始连通性测试")
    kill_sing_box()  # 清理残留进程
    process = None
    try:
        process = subprocess.Popen(
            [sing_box_bin, "run", "-c", config_file],
            stdout=subprocess.PIPE, # 仍然捕获 stdout
            # stderr 不再直接捕获，因为它被重定向到文件了
            text=True
        )
        time.sleep(2) # 给 sing-box 启动留出时间
        
        # 尝试连接 sing-box 的本地 SOCKS5 端口
        sock_test = subprocess.run(
            ["nc", "-zv", "127.0.0.1", "1080", "-w", "1"], # 使用 netcat 检查端口
            capture_output=True,
            text=True,
            timeout=2
        )
        if sock_test.returncode == 0:
            log("sing-box SOCKS5 代理已启动并监听")
            return True
        else:
            log(f"sing-box SOCKS5 代理未成功监听: {sock_test.stderr.strip()}")
            # 这里不再读取 sing-box 的 stderr，因为它的详细日志已经输出到单独的文件了
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
        # 无论测试成功与否，都尝试终止 sing-box 进程
        if process:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                log("强制终止 sing-box 进程")
            kill_sing_box() # 再次确保清理

# 测试下载和上传速度（使用 speedtest-cli Python 库）
def test_download_speed(sing_box_bin, config_file):
    log("开始速度测试")
    kill_sing_box()  # 清理残留进程
    proxy_process = None
    try:
        proxy_process = subprocess.Popen(
            [sing_box_bin, "run", "-c", config_file],
            stdout=subprocess.PIPE, # 仍然捕获 stdout
            # stderr 不再直接捕获，因为它被重定向到文件了
            text=True
        )
        time.sleep(15)  # 延长等待时间，给 sing-box 充分时间稳定连接
        log("代理环境变量: socks5://127.0.0.1:1080")
        
        # 依赖 HTTP 连通性测试结果来决定是否进行 speedtest
        if not test_http_connectivity():
            log("跳过 speedtest，因 HTTP 连通性测试失败")
            return 0, 0, 0

        log("执行 speedtest-cli 命令")
        
        # 设置环境变量，确保 speedtest-cli 使用 sing-box 代理
        # 注意：这里我们使用 ALL_PROXY, HTTP_PROXY, HTTPS_PROXY 并指定 socks5
        env = os.environ.copy()
        env["ALL_PROXY"] = "socks5://127.0.0.1:1080"
        env["HTTPS_PROXY"] = "socks5://127.0.0.1:1080"
        env["HTTP_PROXY"] = "socks5://127.0.0.1:1080"
        
        # 执行 speedtest 命令
        result = subprocess.run(
            ["speedtest", "--format=json", "--accept-license"], # 使用 --accept-license 避免交互式确认
            env=env,
            capture_output=True,
            text=True,
            timeout=45 # 增加超时时间，等待 speedtest 完成
        )

        if result.returncode == 0:
            speedtest_output = result.stdout.strip()
            try:
                results = json.loads(speedtest_output)
                # speedtest-cli 的 bandwidth 是 bytes/sec，需要乘以 8 转换为 bits/sec
                download_mbps = results["download"]["bandwidth"] * 8 / 1_000_000 # 转换为 Mbps
                upload_mbps = results["upload"]["bandwidth"] * 8 / 1_000_000 # 转换为 Mbps
                ping_latency = results["ping"]["latency"]
                log(f"速度测试完成: 下载 {download_mbps:.2f} Mbps, 上传 {upload_mbps:.2f} Mbps, 延迟 {ping_latency:.2f} ms")
                return download_mbps, upload_mbps, ping_latency
            except json.JSONDecodeError:
                log(f"speedtest 输出非 JSON 格式或解析失败: {speedtest_output}")
                # 写入错误日志
                with open(speedtest_log, "a") as f:
                    f.write(f"[{datetime.now()}] speedtest JSON解析失败: {speedtest_output}\n")
                return 0, 0, 0
        else:
            log(f"speedtest 失败，错误代码: {result.returncode}, 输出: {result.stderr.strip()}")
            # 写入错误日志
            with open(speedtest_log, "a") as f:
                f.write(f"[{datetime.now()}] speedtest 失败，错误代码: {result.returncode}, 输出: {result.stderr.strip()}\n")
            return 0, 0, 0
    except FileNotFoundError:
        log("speedtest 命令未找到，请确保已安装 speedtest CLI (`pip install speedtest-cli` 或通过系统包管理器)")
        return 0, 0, 0
    except subprocess.TimeoutExpired:
        log(f"速度测试超时 ({45}秒)，可能是 sing-box 或远程节点无响应")
        with open(speedtest_log, "a") as f:
            f.write(f"[{datetime.now()}] 速度测试超时\n")
        return 0, 0, 0
    except Exception as e:
        log(f"速度测试失败: {str(e)}")
        with open(speedtest_log, "a") as f:
            f.write(f"[{datetime.now()}] 速度测试失败: {str(e)}\n")
        return 0, 0, 0
    finally:
        # 无论测试成功与否，都尝试终止 sing-box 进程
        if proxy_process:
            proxy_process.terminate()
            try:
                proxy_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proxy_process.kill()
                log("强制终止 sing-box 进程")
            kill_sing_box() # 再次确保清理

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
        response.raise_for_status() # 检查 HTTP 错误状态码
        with open("nodes.txt", "w", encoding="utf-8") as f:
            f.write(response.text)
    except Exception as e:
        log(f"下载节点文件失败: {str(e)}")
        return
    log("节点文件下载完成")
    
    results = []
    node_count = 0
    max_nodes = 100 # 最多测试100个节点，你可以根据需要调整此值
    total_nodes = 0

    try:
        with open("nodes.txt", "r", encoding="utf-8", errors="ignore") as f:
            lines = [line.strip() for line in f if line.strip()]
            total_nodes = len(lines)
            log(f"节点文件包含 {total_nodes} 个节点")
            
            for line in lines:
                if node_count >= max_nodes:
                    log(f"达到最大节点限制 ({max_nodes})，停止解析和测试")
                    break
                
                node = None # 初始化 node 变量
                # 为 sing-box 创建一个独立的日志文件
                sing_box_log_path = os.path.join("data", f"sing-box_node_{node_count + 1}.log") # 从1开始计数
                temp_config_name = None # 初始化临时配置文件名
                
                try:
                    node = parse_node(line)
                    if not node:
                        log(f"跳过无法解析的节点: {line[:50]}...")
                        continue
                    
                    node_count += 1
                    log(f"--- 开始测试节点 {node_count}/{total_nodes}: {node['ip']}:{node['port']} ({node['type']}) ---")
                    
                    # 使用 NamedTemporaryFile 来安全地创建和管理临时文件
                    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as temp_config:
                        temp_config_name = temp_config.name
                        generate_sing_box_config(node, temp_config_name, sing_box_log_path) # 传递日志文件路径

                    # 1. 首先测试 sing-box 本地 SOCKS5 代理是否启动
                    is_socks_connected = test_connectivity(sing_box_bin, temp_config_name)
                    
                    download_mbps, upload_mbps, ping_latency = 0, 0, 0
                    if is_socks_connected:
                        # 2. 如果本地代理启动，则尝试通过代理进行速度测试
                        download_mbps, upload_mbps, ping_latency = test_download_speed(sing_box_bin, temp_config_name)
                    else:
                        log(f"节点 {node['ip']}:{node['port']} 的 sing-box SOCKS5 代理未启动，跳过速度测试。")

                    results.append({
                        "node": node["raw"],
                        "ip": node["ip"],
                        "port": node["port"],
                        "type": node["type"],
                        "connected": (download_mbps > 0 and upload_mbps > 0), # 根据速度判断是否成功连接
                        "download_mbps": round(download_mbps, 2),
                        "upload_mbps": round(upload_mbps, 2),
                        "ping_latency_ms": round(ping_latency, 2),
                    })
                except Exception as e:
                    log(f"处理节点 {node_count}/{total_nodes} ({line[:50]}...) 失败: {str(e)}")
                    with open(speedtest_log, "a") as f:
                        f.write(f"[{datetime.now()}] 处理节点失败: {line[:50]}... - {str(e)}\n")
                    # 如果发生异常，也应该将该节点记录下来
                    results.append({
                        "node": line, # 记录原始行
                        "ip": node['ip'] if node else "N/A",
                        "port": node['port'] if node else "N/A",
                        "type": node['type'] if node else "N/A",
                        "connected": False,
                        "download_mbps": 0,
                        "upload_mbps": 0,
                        "ping_latency_ms": 0,
                        "error": str(e)
                    })
                finally:
                    # 确保临时配置文件被删除
                    if temp_config_name and os.path.exists(temp_config_name):
                        try:
                            os.unlink(temp_config_name)
                        except Exception as e:
                            log(f"删除临时文件 {temp_config_name} 失败: {str(e)}")
    except Exception as e:
        log(f"读取节点文件 'nodes.txt' 失败: {str(e)}")
        return
    
    try:
        # 对结果进行排序，通常按下载速度排序
        results.sort(key=lambda x: x["download_mbps"], reverse=True)
        
        # 将结果写入最终输出文件
        with open(output_file, "w", encoding="utf-8") as f:
            for result in results:
                f.write(json.dumps(result, ensure_ascii=False) + "\n")
        log(f"测试完成，共测试 {node_count} 个节点，结果已保存到 {output_file}")
    except Exception as e:
        log(f"保存结果到 {output_file} 失败: {str(e)}")

if __name__ == "__main__":
    main()
