
import requests
import base64
import json
import yaml
import subprocess
import urllib.parse
import re
import os
import uuid
from typing import Dict, List, Optional

# 检查依赖
try:
    import requests
    import yaml
except ImportError as e:
    print(f"缺少依赖: {e}. 请运行 'pip install requests pyyaml'")
    exit(1)

# 检查 Clash.Meta 可执行文件
def check_clash():
    try:
        subprocess.run(["clash", "--version"], capture_output=True, text=True, timeout=5)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        print("Clash.Meta 未安装或不可用")
        return False

# 获取节点配置文件
def fetch_nodes(url: str) -> List[str]:
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text.splitlines()
    except requests.RequestException as e:
        print(f"获取节点失败: {e}")
        return []

# 解析不同协议的节点
def parse_node(line: str) -> Optional[Dict]:
    try:
        if not line or not isinstance(line, str):
            return None
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
def parse_hysteria2(line: str) -> Dict:
    parsed = urllib.parse.urlparse(line)
    if "@" not in parsed.netloc:
        raise ValueError("Invalid hysteria2 format")
    password, host_port = parsed.netloc.split("@", 1)
    host, port = host_port.split(":", 1)
    params = urllib.parse.parse_qs(parsed.query)
    return {
        "type": "hysteria2",
        "name": f"hysteria2_{uuid.uuid4().hex[:8]}",
        "server": host,
        "port": int(port),
        "password": password,
        "sni": params.get("sni", [""])[0],
        "obfs": params.get("obfs", [""])[0]
    }

# 解析 vmess 协议
def parse_vmess(line: str) -> Dict:
    try:
        data = json.loads(base64.b64decode(line[8:]).decode())
        return {
            "type": "vmess",
            "name": f"vmess_{uuid.uuid4().hex[:8]}",
            "server": data["add"],
            "port": int(data["port"]),
            "uuid": data["id"],
            "alterId": int(data.get("aid", 0)),
            "cipher": data.get("type", "auto"),
            "tls": data.get("tls") == "tls",
            "network": data.get("net", "tcp")
        }
    except (json.JSONDecodeError, KeyError) as e:
        raise ValueError(f"Invalid vmess format: {e}")

# 解析 trojan 协议
def parse_trojan(line: str) -> Dict:
    parsed = urllib.parse.urlparse(line)
    if "@" not in parsed.netloc:
        raise ValueError("Invalid trojan format")
    password, host_port = parsed.netloc.split("@", 1)
    host, port = host_port.split(":", 1)
    params = urllib.parse.parse_qs(parsed.query)
    return {
        "type": "trojan",
        "name": f"trojan_{uuid.uuid4().hex[:8]}",
        "server": host,
        "port": int(port),
        "password": password,
        "sni": params.get("sni", [""])[0]
    }

# 解析 ss 协议
def parse_ss(line: str) -> Optional[Dict]:
    try:
        if "@" not in line:
            return None
        auth, host = line[5:].split("@", 1)
        method_password = base64.b64decode(auth).decode().split(":", 1)
        host_port = host.split("#", 1)[0].split(":", 1)
        name = urllib.parse.unquote(host.split("#")[1]) if "#" in host else host_port[0]
        return {
            "type": "ss",
            "name": f"ss_{uuid.uuid4().hex[:8]}",
            "server": host_port[0],
            "port": int(host_port[1]),
            "cipher": method_password[0],
            "password": method_password[1]
        }
    except Exception as e:
        raise ValueError(f"Invalid ss format: {e}")

# 解析 ssr 协议
def parse_ssr(line: str) -> Dict:
    try:
        data = base64.b64decode(line[6:]).decode().split(":", 5)
        params = urllib.parse.parse_qs(data[-1].split("/?", 1)[1])
        return {
            "type": "ssr",
            "name": f"ssr_{uuid.uuid4().hex[:8]}",
            "server": data[0],
            "port": int(data[1]),
            "protocol": data[2],
            "cipher": data[3],
            "obfs": data[4],
            "password": base64.b64decode(data[5]).decode()
        }
    except Exception as e:
        raise ValueError(f"Invalid ssr format: {e}")

# 解析 vless 协议
def parse_vless(line: str) -> Dict:
    parsed = urllib.parse.urlparse(line)
    if "@" not in parsed.netloc:
        raise ValueError("Invalid vless format")
    uuid_str, host_port = parsed.netloc.split("@", 1)
    host, port = host_port.split(":", 1)
    params = urllib.parse.parse_qs(parsed.query)
    return {
        "type": "vless",
        "name": f"vless_{uuid.uuid4().hex[:8]}",
        "server": host,
        "port": int(port),
        "uuid": uuid_str,
        "encryption": params.get("encryption", ["none"])[0],
        "flow": params.get("flow", [""])[0]
    }

# 测试节点连通性
def test_node(node: Dict, timeout: int = 10) -> bool:
    try:
        # 创建临时的 Clash 配置文件
        config = {
            "proxies": [node],
            "proxy-groups": [{"name": "auto", "type": "select", "proxies": [node["name"]]}],
            "rules": ["MATCH,auto"]
        }
        with open("config.yaml", "w") as f:
            yaml.dump(config, f, allow_unicode=True)

        # 测试连通性
        result = subprocess.run(
            ["clash", "-f", "config.yaml", "-t"],
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        print(f"测试节点 {node['name']} 超时")
        return False
    except Exception as e:
        print(f"测试节点 {node['name']} 失败: {e}")
        return False

# 主函数
def main():
    if not check_clash():
        print("Clash.Meta 未找到，退出")
        exit(1)

    url = "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/config_all_merged_nodes.txt"
    nodes = fetch_nodes(url)
    valid_nodes = []

    for line in nodes:
        line = line.strip()
        if not line:
            continue
        node = parse_node(line)
        if node and test_node(node, timeout=10):
            valid_nodes.append(node)
            print(f"节点 {node['name']} 测试通过")
        else:
            print(f"节点 {line[:10]}... 测试失败或解析失败")

    # 保存结果
    try:
        os.makedirs("data", exist_ok=True)
        with open("data/all.txt", "w", encoding="utf-8") as f:
            for node in valid_nodes:
                f.write(json.dumps(node, ensure_ascii=False) + "\n")
    except OSError as e:
        print(f"保存结果失败: {e}")
        exit(1)

if __name__ == "__main__":
    main()
