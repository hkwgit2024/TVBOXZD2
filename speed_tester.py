import base64
import json
import os
import re
import subprocess
import time
import urllib.parse
import requests
import yaml

# 常量定义
CLASH_BIN_PATH = "./clash_bin/mihomo"
CLASH_CONFIG_PATH = "clash_config.yaml"
CLASH_LOG_PATH = "clash_bin/clash_debug.log"
CLASH_API_URL = "http://127.0.0.1:9090"
OUTPUT_SUB_FILE = "data/collectSub.txt"
NODES_SOURCES = [
    {
        "url": "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/nodes.txt",
        "type": "plain",
    },
    {
        "url": "https://raw.githubusercontent.com/qjlxg/aggregator/refs/heads/main/ss.txt",
        "type": "plain",
    },
]
MAX_PROXIES = 1000  # 限制最大代理数量，防止内存溢出

# 确保输出目录存在
os.makedirs(os.path.dirname(OUTPUT_SUB_FILE), exist_ok=True)
os.makedirs(os.path.dirname(CLASH_LOG_PATH), exist_ok=True)

def extract_host_port(netloc_part):
    """提取主机和端口，支持 IPv4 和 IPv6"""
    try:
        if netloc_part.startswith("[") and "]" in netloc_part:
            match = re.match(r"^\[(.*?)\](?::(\d+))?$", netloc_part)
            if match:
                host = match.group(1)
                port = int(match.group(2)) if match.group(2) else None
                return host, port
            else:
                raise ValueError(f"Invalid IPv6 format in netloc: '{netloc_part}'")
        else:
            if ":" in netloc_part:
                host, port_str = netloc_part.rsplit(":", 1)
                port = int(port_str)
                return host, port
            else:
                return netloc_part, None
    except Exception as e:
        raise ValueError(f"Failed to parse host/port: {e}")

def parse_link(link):
    """解析代理链接（支持 ss, ssr, vmess, trojan 等协议）"""
    try:
        if link.startswith("ss://"):
            link_parts = link[5:].split("@", 1)
            if len(link_parts) < 2:
                try:
                    decoded_link = base64.b64decode(
                        link[5:].replace("-", "+").replace("_", "/")
                    ).decode("utf-8")
                    if "@" in decoded_link:
                        link_parts = decoded_link.split("@", 1)
                    else:
                        raise ValueError("Decoded SS link missing @")
                except Exception:
                    raise ValueError("Invalid SS link format (no @ and not decodable Base64)")
            
            cipher_part, address_part = link_parts
            cipher_decoded = base64.b64decode(
                cipher_part.replace("-", "+").replace("_", "/")
            ).decode("utf-8")
            method, password = cipher_decoded.split(":", 1)
            host, port = extract_host_port(address_part.split("#")[0])
            name = urllib.parse.unquote(address_part.split("#")[1]) if "#" in address_part else "Unnamed"
            return {
                "type": "ss",
                "config": {
                    "name": name,
                    "type": "ss",
                    "server": host,
                    "port": port,
                    "cipher": method,
                    "password": password,
                },
            }
        
        elif link.startswith("ssr://"):
            decoded = base64.b64decode(
                link[6:].replace("-", "+").replace("_", "/")
            ).decode("utf-8")
            parts = decoded.split(":")
            if len(parts) < 6:
                raise ValueError("Invalid SSR link format")
            host, port, protocol, method, obfs, password = parts[:6]
            password = base64.b64decode(
                password.replace("-", "+").replace("_", "/")
            ).decode("utf-8")
            params = {}
            if "/?" in decoded:
                param_str = decoded.split("/?")[1]
                for param in param_str.split("&"):
                    key, value = param.split("=", 1)
                    params[key] = base64.b64decode(
                        value.replace("-", "+").replace("_", "/")
                    ).decode("utf-8")
            name = params.get("remarks", "Unnamed")
            return {
                "type": "ssr",
                "config": {
                    "name": name,
                    "type": "ssr",
                    "server": host,
                    "port": int(port),
                    "protocol": protocol,
                    "cipher": method,
                    "obfs": obfs,
                    "password": password,
                    **{f"obfs-{k}": v for k, v in params.items() if k.startswith("obfs")},
                },
            }
        
        elif link.startswith("vmess://"):
            decoded = base64.b64decode(
                link[8:].replace("-", "+").replace("_", "/")
            ).decode("utf-8")
            vmess_data = json.loads(decoded)
            return {
                "type": "vmess",
                "config": {
                    "name": vmess_data.get("ps", "Unnamed"),
                    "type": "vmess",
                    "server": vmess_data.get("add"),
                    "port": int(vmess_data.get("port")),
                    "uuid": vmess_data.get("id"),
                    "alterId": int(vmess_data.get("aid", 0)),
                    "cipher": vmess_data.get("type", "auto"),
                    "tls": vmess_data.get("tls") == "tls",
                    **{
                        k: v
                        for k, v in vmess_data.items()
                        if k in ["network", "ws-opts", "h2-opts", "grpc-opts"]
                    },
                },
            }
        
        elif link.startswith("trojan://"):
            parsed = urllib.parse.urlparse(link)
            password = parsed.username or parsed.password
            host, port = extract_host_port(parsed.netloc)
            name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else "Unnamed"
            query = urllib.parse.parse_qs(parsed.query)
            return {
                "type": "trojan",
                "config": {
                    "name": name,
                    "type": "trojan",
                    "server": host,
                    "port": port or 443,
                    "password": password,
                    "sni": query.get("sni", [host])[0],
                    **{
                        k: query.get(k, [None])[0]
                        for k in ["allowInsecure", "type", "path", "host"]
                        if query.get(k)
                    },
                },
            }
        
        else:
            raise ValueError(f"Unsupported protocol: {link[:10]}")
    
    except Exception as e:
        raise ValueError(f"Error parsing link: {e}")

def fetch_and_parse_nodes():
    """从源获取并解析代理节点"""
    all_parsed_proxies = []
    seen_proxy_names = set()
    for source in NODES_SOURCES:
        print(f"Fetching nodes from {source['url']}...")
        try:
            response = requests.get(source["url"], timeout=15, stream=True)
            response.raise_for_status()
            content = ""
            for line in response.iter_lines(decode_unicode=True):
                if line and len(all_parsed_proxies) < MAX_PROXIES:
                    content += line + "\n"
                if len(all_parsed_proxies) >= MAX_PROXIES:
                    print(f"Reached maximum proxy limit ({MAX_PROXIES}). Stopping parsing.")
                    break
            
            raw_links = content.splitlines()
            print(f"Fetched {len(raw_links)} raw links from {source['url']}.")
            
            for link in raw_links:
                link = link.strip()
                if not link or len(all_parsed_proxies) >= MAX_PROXIES:
                    continue
                try:
                    parsed = parse_link(link)
                    original_name = parsed["config"]["name"]
                    if original_name in seen_proxy_names:
                        counter = sum(
                            1 for name in seen_proxy_names if name.startswith(original_name)
                        )
                        new_name = f"{original_name}-{counter}"
                        parsed["config"]["name"] = new_name
                        print(f"Duplicate proxy name '{original_name}' found. Renamed to '{new_name}'.")
                    seen_proxy_names.add(parsed["config"]["name"])
                    all_parsed_proxies.append(parsed["config"])
                except Exception as e:
                    print(f"Warning: Failed to parse link '{link}'. Error: {e}")
        
        except Exception as e:
            print(f"Error fetching or processing source {source['url']}: {e}")
    
    print(f"Total parsed proxies: {len(all_parsed_proxies)}")
    return all_parsed_proxies

def generate_clash_config(proxies):
    """生成 Clash 配置文件"""
    config = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "debug",
        "external-controller": "127.0.0.1:9090",
        "secret": "",
        "proxies": proxies,
        "proxy-groups": [
            {"name": "测速", "type": "select", "proxies": [p["name"] for p in proxies]},
            {"name": "DIRECT", "type": "direct"},
            {"name": "REJECT", "type": "reject"},
        ],
        "rules": ["MATCH,测速"],
    }
    with open(CLASH_CONFIG_PATH, "w", encoding="utf-8") as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    print(f"Clash config generated at {CLASH_CONFIG_PATH}")

def start_clash():
    """启动 Clash 核心并捕获详细日志"""
    print("Starting Clash core...")
    with open(CLASH_LOG_PATH, "a", encoding="utf-8") as log_file:
        log_file.write(f"--- Clash Core Log Start ({time.strftime('%Y-%m-%d %H:%M:%S')}) ---\n")
        clash_process = subprocess.Popen(
            [CLASH_BIN_PATH, "-f", CLASH_CONFIG_PATH, "-d", "."],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        # 实时捕获输出
        while True:
            stdout_line = clash_process.stdout.readline()
            stderr_line = clash_process.stderr.readline()
            if stdout_line:
                log_file.write(stdout_line)
                print(stdout_line.strip())
            if stderr_line:
                log_file.write(stderr_line)
                print(stderr_line.strip())
            if clash_process.poll() is not None:
                break
        # 读取剩余输出
        stdout_rest, stderr_rest = clash_process.communicate(timeout=5)
        log_file.write(stdout_rest)
        log_file.write(stderr_rest)
        if clash_process.returncode != 0:
            raise Exception(f"Clash core exited with code {clash_process.returncode}. Check log for details.")

    # 检查 API 可用性
    api_ready = False
    for i in range(10):
        try:
            response = requests.get(f"{CLASH_API_URL}/configs", timeout=2)
            if response.status_code == 200:
                print("Clash API is reachable.")
                api_ready = True
                break
        except Exception as e:
            print(f"Error checking Clash API: {e}")
        time.sleep(2)
    if not api_ready:
        raise Exception("Clash API did not become reachable within expected time.")

    print("Clash core started.")
    return clash_process

def test_proxy(proxy_name):
    """测试代理节点速度"""
    try:
        payload = {"name": proxy_name}
        response = requests.put(
            f"{CLASH_API_URL}/proxies/测速", json=payload, timeout=5
        )
        response.raise_for_status()
        start_time = time.time()
        test_response = requests.get(
            "https://www.google.com", proxies={"https": "http://127.0.0.1:7890"}, timeout=10
        )
        elapsed = time.time() - start_time
        if test_response.status_code == 200:
            speed = (len(test_response.content) / 1024 / 1024) / elapsed  # MB/s
            return speed * 8  # 转换为 Mbps
        return 0
    except Exception as e:
        print(f"Error testing proxy {proxy_name}: {e}")
        return 0

def main():
    """主函数"""
    start_time = time.time()
    proxies = fetch_and_parse_nodes()
    print(f"Parsed {len(proxies)} proxies in {time.time() - start_time:.2f} seconds.")
    
    if not proxies:
        print("No valid proxies found. Exiting.")
        return
    
    generate_clash_config(proxies)
    print(f"Generated config in {time.time() - start_time:.2f} seconds.")
    
    clash_process = None
    try:
        clash_process = start_clash()
        results = []
        for proxy in proxies:
            speed = test_proxy(proxy["name"])
            if speed > 0:
                print(f"Proxy: {proxy['name']} # Speed: {speed:.2f} Mbps")
                results.append((proxy, speed))
        
        # 按速度排序并保存前 10 个结果
        results.sort(key=lambda x: x[1], reverse=True)
        with open(OUTPUT_SUB_FILE, "w", encoding="utf-8") as f:
            for proxy, speed in results[:10]:
                f.write(f"{yaml.dump([proxy], allow_unicode=True)}\n# Speed: {speed:.2f} Mbps\n")
        print(f"Results saved to {OUTPUT_SUB_FILE}")
    
    except Exception as e:
        print(f"Error in main loop: {e}")
    
    finally:
        if clash_process and clash_process.poll() is None:
            print("Terminating Clash core...")
            clash_process.terminate()
            try:
                clash_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                clash_process.kill()
        print(f"Total execution time: {time.time() - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
