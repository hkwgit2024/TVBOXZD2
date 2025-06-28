import requests
import base64
import json
import yaml
import subprocess
import urllib.parse
import re
import os

# 获取节点配置文件
def fetch_nodes(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text.splitlines()
    except requests.RequestException as e:
        print(f"获取节点失败: {e}")
        return []

# 解析不同协议的节点
def parse_node(line):
    try:
        if line.startswith("hysteria2://"):
            return parse_hysteria2(line)
        elif line.startswith("vmess://"):
            return parse_vmess(line)
        elif line.startswith("trojan://"):
            return parse_trojan(line)
        elif line.startswith("ss://"):
            return parse_ss(line)
        elif line.startswith("ssr://"):
            return parse_ssr(line)
        elif line.startswith("vless://"):
            return parse_vless(line)
        return None
    except Exception as e:
        print(f"解析节点 {line[:10]}... 失败: {e}")
        return None

# 解析 hysteria2 协议
def parse_hysteria2(line):
    parsed = urllib.parse.urlparse(line)
    password = parsed.netloc.split("@")[0]
    host_port = parsed.netloc.split("@")[1]
    host, port = host_port.split(":")
    params = urllib.parse.parse_qs(parsed.query)
    return {
        "type": "hysteria2",
        "name": params.get("name", [host])[0],
        "server": host,
        "port": int(port),
        "password": password,
        "sni": params.get("sni", [""])[0],
        "obfs": params.get("obfs", [""])[0]
    }

# 解析 vmess 协议
def parse_vmess(line):
    data = json.loads(base64.b64decode(line[8:]).decode())
    return {
        "type": "vmess",
        "name": data.get("ps", data.get("add")),
        "server": data["add"],
        "port": int(data["port"]),
        "uuid": data["id"],
        "alterId": int(data.get("aid", 0)),
        "cipher": data.get("type", "auto"),
        "tls": data.get("tls") == "tls",
        "network": data.get("net", "tcp")
    }

# 解析 trojan 协议
def parse_trojan(line):
    parsed = urllib.parse.urlparse(line)
    password = parsed.netloc.split("@")[0]
    host_port = parsed.netloc.split("@")[1]
    host, port = host_port.split(":")
    params = urllib.parse.parse_qs(parsed.query)
    return {
        "type": "trojan",
        "name": params.get("name", [host])[0],
        "server": host,
        "port": int(port),
        "password": password,
        "sni": params.get("sni", [""])[0]
    }

# 解析 ss 协议
def parse_ss(line):
    if "@" in line:
        auth, host = line[5:].split("@")
        method_password = base64.b64decode(auth).decode().split(":")
        host_port = host.split("#")[0].split(":")
        name = urllib.parse.unquote(host.split("#")[1]) if "#" in host else host_port[0]
        return {
            "type": "ss",
            "name": name,
            "server": host_port[0],
            "port": int(host_port[1]),
            "cipher": method_password[0],
            "password": method_password[1]
        }
    return None

# 解析 ssr 协议
def parse_ssr(line):
    data = base64.b64decode(line[6:]).decode().split(":")
    params = urllib.parse.parse_qs(data[-1].split("/?")[1])
    return {
        "type": "ssr",
        "name": urllib.parse.unquote(params.get("remarks", [""])[0]),
        "server": data[0],
        "port": int(data[1]),
        "protocol": data[2],
        "cipher": data[3],
        "obfs": data[4],
        "password": base64.b64decode(data[5]).decode()
    }

# 解析 vless 协议
def parse_vless(line):
    parsed = urllib.parse.urlparse(line)
    uuid = parsed.netloc.split("@")[0]
    host_port = parsed.netloc.split("@")[1]
    host, port = host_port.split(":")
    params = urllib.parse.parse_qs(parsed.query)
    return {
        "type": "vless",
        "name": params.get("name", [host])[0],
        "server": host,
        "port": int(port),
        "uuid": uuid,
        "encryption": params.get("encryption", ["none"])[0],
        "flow": params.get("flow", [""])[0]
    }

# 测试节点连通性
def test_node(node):
    try:
        # 创建临时的 Clash 配置文件
        config = {
            "proxies": [node],
            "proxy-groups": [{"name": "auto", "type": "select", "proxies": [node["name"]]}],
            "rules": ["MATCH,auto"]
        }
        with open("config.yaml", "w") as f:
            yaml.dump(config, f)

        # 使用 Clash.Meta 测试连通性
        result = subprocess.run(
            ["clash", "-f", "config.yaml", "-t"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception as e:
        print(f"测试节点 {node['name']} 失败: {e}")
        return False

# 主函数
def main():
    url = "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
    nodes = fetch_nodes(url)
    valid_nodes = []

    for line in nodes:
        line = line.strip()
        if not line:
            continue
        node = parse_node(line)
        if node and test_node(node):
            valid_nodes.append(node)
            print(f"节点 {node['name']} 测试通过")
        else:
            print(f"节点 {line[:10]}... 测试失败或解析失败")

    # 保存结果
    os.makedirs("data", exist_ok=True)
    with open("data/all.txt", "w") as f:
        for node in valid_nodes:
            f.write(json.dumps(node) + "\n")

if __name__ == "__main__":
    main()
