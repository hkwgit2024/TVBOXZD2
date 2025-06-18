import base64
import json
import os
import re
import subprocess
import time
import urllib.parse
import requests

# 常量定义
SINGBOX_BIN_PATH = "./clash_bin/sing-box"
SINGBOX_CONFIG_PATH = "sing-box-config.json"
SINGBOX_LOG_PATH = "sing-box.log"
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
MAX_PROXIES = 1000  # 限制最大代理数量

# 确保输出目录存在
os.makedirs(os.path.dirname(OUTPUT_SUB_FILE), exist_ok=True)
os.makedirs(os.path.dirname(SINGBOX_LOG_PATH), exist_ok=True)

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
                    "tag": name,
                    "type": "shadowsocks",
                    "server": host,
                    "server_port": port,
                    "method": method,
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
                    "tag": name,
                    "type": "ssr",
                    "server": host,
                    "server_port": int(port),
                    "protocol": protocol,
                    "method": method,
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
                    "tag": vmess_data.get("ps", "Unnamed"),
                    "type": "vmess",
                    "server": vmess_data.get("add"),
                    "server_port": int(vmess_data.get("port")),
                    "uuid": vmess_data.get("id"),
                    "security": vmess_data.get("type", "auto"),
                    "alter_id": int(vmess_data.get("aid", 0)),
                    **{
                        k: v
                        for k, v in vmess_data.items()
                        if k in ["network", "ws-opts", "h2-opts", "grpc-opts"]
                    },
                    "tls": {"enabled": vmess_data.get("tls") == "tls"} if vmess_data.get("tls") else {},
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
                    "tag": name,
                    "type": "trojan",
                    "server": host,
                    "server_port": port or 443,
                    "password": password,
                    "tls": {
                        "enabled": True,
                        "server_name": query.get("sni", [host])[0],
                        "insecure": query.get("allowInsecure", ["0"])[0] == "1",
                    },
                    **{
                        k: query.get(k, [None])[0]
                        for k in ["type", "path", "host"]
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
                    original_name = parsed["config"]["tag"]
                    if original_name in seen_proxy_names:
                        counter = sum(
                            1 for name in seen_proxy_names if name.startswith(original_name)
                        )
                        new_name = f"{original_name}-{counter}"
                        parsed["config"]["tag"] = new_name
                        print(f"Duplicate proxy name '{original_name}' found. Renamed to '{new_name}'.")
                    seen_proxy_names.add(parsed["config"]["tag"])
                    all_parsed_proxies.append(parsed["config"])
                except Exception as e:
                    print(f"Warning: Failed to parse link '{link}'. Error: {e}")
        
        except Exception as e:
            print(f"Error fetching or processing source {source['url']}: {e}")
    
    print(f"Total parsed proxies: {len(all_parsed_proxies)}")
    return all_parsed_proxies

def generate_singbox_config(proxies):
    """生成 sing-box 配置文件"""
    outbounds = []
    for proxy in proxies:
        if proxy["type"] == "shadowsocks":
            outbounds.append(proxy)
        elif proxy["type"] == "vmess":
            outbounds.append(proxy)
        elif proxy["type"] == "trojan":
            outbounds.append(proxy)
        elif proxy["type"] == "ssr":
            print(f"Warning: SSR proxy '{proxy['tag']}' may not be supported by sing-box. Skipping.")
            continue

    config = {
        "log": {
            "level": "debug",
            "output": SINGBOX_LOG_PATH,
        },
        "outbounds": [
            *outbounds,
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ],
        "inbounds": [
            {
                "type": "http",
                "tag": "http-in",
                "listen": "127.0.0.1",
                "listen_port": 7890,
            },
            {
                "type": "socks",
                "tag": "socks-in",
                "listen": "127.0.0.1",
                "listen_port": 7891,
            },
        ],
        "route": {
            "rules": [
                {"outbound": "block", "protocol": ["dns"]},
                {"outbound": outbounds[0]["tag"] if outbounds else "direct", "network": ["tcp", "udp"]},
            ],
        },
    }
    with open(SINGBOX_CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
    print(f"sing-box config generated at {SINGBOX_CONFIG_PATH}")
    return SINGBOX_CONFIG_PATH

def start_singbox(config_path):
    """启动 sing-box 核心并捕获详细日志"""
    print("Starting sing-box core...")
    with open(SINGBOX_LOG_PATH, "a", encoding="utf-8") as log_file:
        log_file.write(f"--- sing-box Core Log Start ({time.strftime('%Y-%m-%d %H:%M:%S')}) ---\n")
        singbox_process = subprocess.Popen(
            [SINGBOX_BIN_PATH, "run", "-c", config_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        while True:
            stdout_line = singbox_process.stdout.readline()
            stderr_line = singbox_process.stderr.readline()
            if stdout_line:
                log_file.write(stdout_line)
                print(stdout_line.strip())
            if stderr_line:
                log_file.write(stderr_line)
                print(stderr_line.strip())
            if singbox_process.poll() is not None:
                break
        stdout_rest, stderr_rest = singbox_process.communicate(timeout=5)
        log_file.write(stdout_rest)
        log_file.write(stderr_rest)
        if singbox_process.returncode != 0:
            raise Exception(f"sing-box core exited with code {singbox_process.returncode}. Check log for details.")

    proxy_ready = False
    for i in range(10):
        try:
            response = requests.get(
                "https://www.google.com",
                proxies={"https": "http://127.0.0.1:7890"},
                timeout=2,
            )
            if response.status_code == 200:
                print("sing-box proxy is reachable.")
                proxy_ready = True
                break
        except Exception as e:
            print(f"Error checking sing-box proxy: {e}")
        time.sleep(2)
    if not proxy_ready:
        raise Exception("sing-box proxy did not become reachable within expected time.")

    print("sing-box core started.")
    return singbox_process

def test_proxy(proxy_name, proxies, config_path):
    """测试代理节点速度"""
    try:
        temp_config = {
            "log": {"level": "debug", "output": SINGBOX_LOG_PATH},
            "outbounds": [
                next(p for p in proxies if p["tag"] == proxy_name),
                {"type": "direct", "tag": "direct"},
                {"type": "block", "tag": "block"},
            ],
            "inbounds": [
                {"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": 7890},
                {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": 7891},
            ],
            "route": {"rules": [{"outbound": proxy_name, "network": ["tcp", "udp"]}]},
        }
        temp_config_path = f"sing-box-temp-{proxy_name}.json"
        with open(temp_config_path, "w", encoding="utf-8") as f:
            json.dump(temp_config, f, ensure_ascii=False, indent=2)
        
        temp_process = start_singbox(temp_config_path)
        
        start_time = time.time()
        test_response = requests.get(
            "https://www.google.com",
            proxies={"https": "http://127.0.0.1:7890"},
            timeout=10,
        )
        elapsed = time.time() - start_time
        if test_response.status_code == 200:
            speed = (len(test_response.content) / 1024 / 1024) / elapsed
            speed_mbps = speed * 8
            print(f"Proxy: {proxy_name} # Speed: {speed_mbps:.2f} Mbps")
            return speed_mbps
        return 0
    
    except Exception as e:
        print(f"Error testing proxy {proxy_name}: {e}")
        return 0
    finally:
        if temp_process and temp_process.poll() is None:
            temp_process.terminate()
            try:
                temp_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                temp_process.kill()
        if os.path.exists(temp_config_path):
            os.remove(temp_config_path)

def main():
    """主函数"""
    start_time = time.time()
    proxies = fetch_and_parse_nodes()
    print(f"Parsed {len(proxies)} proxies in {time.time() - start_time:.2f} seconds.")
    
    if not proxies:
        print("No valid proxies found. Exiting.")
        return
    
    config_path = generate_singbox_config(proxies)
    print(f"Generated config in {time.time() - start_time:.2f} seconds.")
    
    singbox_process = None
    try:
        singbox_process = start_singbox(config_path)
        results = []
        for proxy in proxies:
            if proxy["type"] == "ssr":
                continue
            speed = test_proxy(proxy["tag"], proxies, config_path)
            if speed > 0:
                results.append((proxy, speed))
        
        results.sort(key=lambda x: x[1], reverse=True)
        with open(OUTPUT_SUB_FILE, "w", encoding="utf-8") as f:
            for proxy, speed in results[:10]:
                f.write(f"{json.dumps(proxy, ensure_ascii=False)}\n# Speed: {speed:.2f} Mbps\n")
        print(f"Results saved to {OUTPUT_SUB_FILE}")
    
    except Exception as e:
        print(f"Error in main loop: {e}")
    
    finally:
        if singbox_process and singbox_process.poll() is None:
            print("Terminating sing-box core...")
            singbox_process.terminate()
            try:
                singbox_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                singbox_process.kill()
        print(f"Total execution time: {time.time() - start_time:.2f} seconds.")

if __name__ == "__main__":
    main()
