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

# 确保 data 目录存在
if not os.path.exists("data"):
    os.makedirs("data")

# 目标 URL 和输出文件
url = "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
output_file = "data/collectSub.txt"

# 下载最新 sing-box 二进制文件
def download_sing_box():
    sing_box_bin = "./sing-box"
    if not os.path.exists(sing_box_bin):
        # 使用 GitHub API 获取最新 release
        api_url = "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
        try:
            response = requests.get(api_url, headers={"Accept": "application/vnd.github+json"})
            response.raise_for_status()
            release = response.json()
            # 查找 linux-amd64 的 tar.gz 文件
            sing_box_url = None
            for asset in release["assets"]:
                if "linux-amd64" in asset["name"] and asset["name"].endswith(".tar.gz"):
                    sing_box_url = asset["browser_download_url"]
                    break
            if not sing_box_url:
                raise Exception("未找到适用于 linux-amd64 的 sing-box 二进制文件")
            sing_box_tar = "sing-box.tar.gz"
            urllib.request.urlretrieve(sing_box_url, sing_box_tar)
            subprocess.run(["tar", "-xzf", sing_box_tar], check=True)
            # 查找解压后的 sing-box 二进制文件
            binary_paths = glob.glob("**/sing-box", recursive=True) or glob.glob("sing-box")
            if not binary_paths:
                raise Exception("未找到解压后的 sing-box 二进制文件")
            subprocess.run(["mv", binary_paths[0], sing_box_bin], check=True)
            subprocess.run(["chmod", "+x", sing_box_bin], check=True)
            # 清理临时文件和目录
            if os.path.exists(sing_box_tar):
                os.remove(sing_box_tar)
            for dir_path in glob.glob("sing-box*"):
                if os.path.isdir(dir_path):
                    subprocess.run(["rm", "-rf", dir_path], check=True)
        except Exception as e:
            print(f"下载 sing-box 失败: {str(e)}")
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
            return {"type": "hysteria2", "ip": ip, "port": port, "password": password, "raw": line}
        elif line.startswith("ss://"):
            decoded = base64.b64decode(line[5:].split("#")[0]).decode()
            userinfo, ip_port = decoded.split("@")
            cipher, password = userinfo.split(":")
            ip, port = ip_port.split(":")
            return {"type": "ss", "ip": ip, "port": port, "cipher": cipher, "password": password, "raw": line}
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
            return {"type": "vless", "ip": ip, "port": port, "uuid": uuid, "raw": line}
        elif line.startswith("vmess://"):
            decoded = json.loads(base64.b64decode(line[8:]).decode())
            return {"type": "vmess", "ip": decoded["add"], "port": str(decoded["port"]), "uuid": decoded["id"], "raw": line}
        else:
            return None
    except Exception as e:
        print(f"解析节点失败: {line}, 错误: {str(e)}")
        return None

# 生成 sing-box 配置文件
def generate_sing_box_config(node, temp_config_file):
    config = {
        "log": {"level": "error"},
        "outbounds": [
            {
                "type": node["type"],
                "tag": "proxy",
                "server": node["ip"],
                "server_port": int(node["port"]),
            }
        ]
    }
    if node["type"] == "hysteria2":
        config["outbounds"][0]["password"] = node["password"]
    elif node["type"] == "ss":
        config["outbounds"][0]["method"] = node["cipher"]
        config["outbounds"][0]["password"] = node["password"]
    elif node["type"] == "trojan":
        config["outbounds"][0]["password"] = node["password"]
        config["outbounds"][0]["tls"] = {"enabled": True}
    elif node["type"] == "vless":
        config["outbounds"][0]["uuid"] = node["uuid"]
        config["outbounds"][0]["tls"] = {"enabled": True}
    elif node["type"] == "vmess":
        config["outbounds"][0]["uuid"] = node["uuid"]
    with open(temp_config_file, "w") as f:
        json.dump(config, f, indent=2)

# 测试连通性
def test_connectivity(sing_box_bin, config_file):
    try:
        process = subprocess.Popen(
            [sing_box_bin, "run", "-c", config_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(2)  # 等待连接建立
        process.terminate()
        process.wait(timeout=5)
        return True
    except Exception as e:
        print(f"连通性测试失败: {str(e)}")
        return False

# 测试下载和上传速度
def test_download_speed(sing_box_bin, config_file):
    try:
        # 启动 sing-box 代理
        proxy_process = subprocess.Popen(
            [sing_box_bin, "run", "-c", config_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        time.sleep(2)  # 等待代理启动
        # 使用 speedtest-cli 通过代理测试速度
        result = subprocess.run(
            ["speedtest-cli", "--json", "--server", "socks5://127.0.0.1:1080"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        proxy_process.terminate()
        proxy_process.wait(timeout=5)
        if result.returncode == 0:
            data = json.loads(result.stdout)
            download_mbps = data["download"] / 1_000_000  # 转换为 Mbps
            upload_mbps = data["upload"] / 1_000_000  # 转换为 Mbps
            return download_mbps, upload_mbps
        else:
            print(f"speedtest-cli 失败: {result.stderr}")
            return 0, 0
    except Exception as e:
        print(f"速度测试失败: {str(e)}")
        return 0, 0

# 主函数
def main():
    sing_box_bin = download_sing_box()
    try:
        urllib.request.urlretrieve(url, "nodes.txt")
    except Exception as e:
        print(f"下载节点文件失败: {str(e)}")
        return
    results = []
    with open("nodes.txt", "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            node = parse_node(line)
            if not node:
                continue
            print(f"测试节点: {node['ip']}:{node['port']} ({node['type']})")
            with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as temp_config:
                generate_sing_box_config(node, temp_config.name)
                is_connected = test_connectivity(sing_box_bin, temp_config.name)
                download_mbps, upload_mbps = 0, 0
                if is_connected:
                    download_mbps, upload_mbps = test_download_speed(sing_box_bin, temp_config.name)
                results.append({
                    "node": node["raw"],
                    "ip": node["ip"],
                    "port": node["port"],
                    "type": node["type"],
                    "connected": is_connected,
                    "download_mbps": round(download_mbps, 2),
                    "upload_mbps": round(upload_mbps, 2),
                })
                os.unlink(temp_config.name)
    with open(output_file, "w", encoding="utf-8") as f:
        for result in results:
            f.write(json.dumps(result, ensure_ascii=False) + "\n")
    print(f"测试完成，结果已保存到 {output_file}")

if __name__ == "__main__":
    main()
