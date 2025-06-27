import httpx
import yaml
import asyncio
import os
import subprocess
import time
import socket
import re
import json
import urllib.parse
import traceback
import base64

CLASH_BASE_CONFIG_URLS = [
    "https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/data/sub_2.txt",
    "https://raw.githubusercontent.com/freefq/free/master/v2",
    "https://raw.githubusercontent.com/mahdibland/SSAggregator/master/sub/sub_merge_yaml.yml",
    "https://raw.githubusercontent.com/qjlxg/aggregator/main/data/clash.yaml",
    "https://raw.githubusercontent.com/qjlxg/hy2/refs/heads/main/configtg.yaml"
]

def is_valid_reality_short_id(short_id: str | None) -> bool:
    """验证 REALITY 协议的 shortId 是否有效（8 字符十六进制字符串）。"""
    if not short_id or not isinstance(short_id, str):
        return False
    return bool(re.match(r"^[0-9a-fA-F]{8}$", short_id))

def validate_proxy(proxy: dict, index: int) -> bool:
    """验证代理节点是否有效，特别是 REALITY 和 VMess 协议的配置。"""
    missing_fields = []
    if not proxy.get("name"):
        missing_fields.append("name")
    if not proxy.get("server"):
        missing_fields.append("server")
    if not proxy.get("port"):
        missing_fields.append("port")
    
    if missing_fields:
        print(f"⚠️ 跳过无效节点（索引 {index}）：缺少字段 {', '.join(missing_fields)} - {proxy.get('name', '未知节点')} - 完整配置: {json.dumps(proxy, ensure_ascii=False)}")
        return False
    
    if proxy.get("type") == "vless":
        reality_opts = proxy.get("reality-opts")
        if reality_opts:
            if not isinstance(reality_opts, dict):
                print(f"⚠️ 跳过无效 REALITY 节点（索引 {index}）：reality-opts 不是字典 - {proxy.get('name')} - reality-opts: {reality_opts}")
                return False
            short_id = reality_opts.get("shortId")
            if short_id is not None and not is_valid_reality_short_id(short_id):
                print(f"⚠️ 跳过无效 REALITY 节点（索引 {index}）：无效 shortId: {short_id} - {proxy.get('name')} - 完整配置: {json.dumps(proxy, ensure_ascii=False)}")
                return False
        if not proxy.get("uuid"):
            print(f"⚠️ 跳过无效 VLESS 节点（索引 {index}）：缺少 uuid - {proxy.get('name')} - 完整配置: {json.dumps(proxy, ensure_ascii=False)}")
            return False
    
    if proxy.get("type") == "vmess":
        cipher = proxy.get("cipher")
        valid_ciphers = ["auto", "aes-128-gcm", "chacha20-poly1305", "none"]
        if not cipher or cipher not in valid_ciphers:
            print(f"⚠️ 跳过无效 VMess 节点（索引 {index}）：无效 cipher: {cipher} - {proxy.get('name')} - 完整配置: {json.dumps(proxy, ensure_ascii=False)}")
            return False
    
    return True

def to_plaintext_node(proxy: dict, delay: int) -> str:
    """将 Clash 代理配置转换为明文节点链接，附带延迟信息。"""
    try:
        name = urllib.parse.quote(proxy.get("name", "unknown"))
        proxy_type = proxy.get("type")
        
        if proxy_type == "ss":
            method = proxy.get("cipher")
            password = proxy.get("password")
            server = proxy.get("server")
            port = proxy.get("port")
            if method and password and server and port:
                user_info = base64.b64encode(f"{method}:{password}".encode()).decode().rstrip("=")
                return f"ss://{user_info}@{server}:{port}#{name} - {delay}ms"
        
        elif proxy_type == "vmess":
            vmess_config = {
                "v": "2",
                "ps": proxy.get("name"),
                "add": proxy.get("server"),
                "port": proxy.get("port"),
                "id": proxy.get("uuid"),
                "aid": proxy.get("alterId", 0),
                "net": proxy.get("network", "tcp"),
                "type": proxy.get("cipher", "auto"),
                "tls": "tls" if proxy.get("tls", False) else "",
                "host": proxy.get("servername", ""),
                "path": proxy.get("ws-opts", {}).get("path", "")
            }
            encoded = base64.b64encode(json.dumps(vmess_config).encode()).decode().rstrip("=")
            return f"vmess://{encoded}#{name} - {delay}ms"
        
        elif proxy_type == "hysteria2":
            server = proxy.get("server")
            port = proxy.get("port")
            password = proxy.get("password")
            sni = proxy.get("sni", server)
            insecure = "1" if proxy.get("skip-cert-verify", False) else "0"
            if server and port and password:
                return f"hysteria2://{password}@{server}:{port}?sni={sni}&insecure={insecure}#{name} - {delay}ms"
        
        elif proxy_type == "trojan":
            server = proxy.get("server")
            port = proxy.get("port")
            password = proxy.get("password")
            sni = proxy.get("sni", server)
            if server and port and password:
                return f"trojan://{password}@{server}:{port}?sni={sni}#{name} - {delay}ms"
        
        elif proxy_type == "ssr":
            server = proxy.get("server")
            port = proxy.get("port")
            password = proxy.get("password")
            method = proxy.get("cipher")
            protocol = proxy.get("protocol", "origin")
            obfs = proxy.get("obfs", "plain")
            if server and port and password and method:
                params = base64.b64encode(f"{server}:{port}:{protocol}:{method}:{obfs}:{base64.b64encode(password.encode()).decode().rstrip('=')}").decode().rstrip("=")
                return f"ssr://{params}#{name} - {delay}ms"
        
        elif proxy_type == "vless":
            server = proxy.get("server")
            port = proxy.get("port")
            uuid = proxy.get("uuid")
            flow = proxy.get("flow", "")
            security = "tls" if proxy.get("tls", False) else "none"
            sni = proxy.get("sni", server)
            query_params = [f"security={security}", f"sni={sni}"]
            if flow:
                query_params.append(f"flow={flow}")
            ws_opts = proxy.get("ws-opts", {})
            if ws_opts:
                query_params.append(f"type=ws&path={urllib.parse.quote(ws_opts.get('path', ''))}")
            query = "&".join(query_params)
            if server and port and uuid:
                return f"vless://{uuid}@{server}:{port}?{query}#{name} - {delay}ms"
        
        else:
            print(f"⚠️ 跳过不支持的节点类型: {proxy_type} - {name}")
            return ""
    except Exception as e:
        print(f"⚠️ 转换明文节点失败: {proxy.get('name', '未知节点')} - 错误: {e}")
        return ""

def parse_v2ray_subscription(content: str) -> list:
    """解析 V2Ray 订阅链接（vmess://, ss://, hysteria2://, trojan://, ssr://, vless://），转换为 Clash 格式。"""
    proxies = []
    lines = content.splitlines()
    for index, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        try:
            if line.startswith("vmess://"):
                decoded = base64.b64decode(line[8:].strip() + "===").decode('utf-8')
                vmess = json.loads(decoded)
                proxy = {
                    "name": vmess.get("ps", f"vmess-{index}"),
                    "type": "vmess",
                    "server": vmess.get("add"),
                    "port": int(vmess.get("port")),
                    "uuid": vmess.get("id"),
                    "alterId": int(vmess.get("aid", 0)),
                    "cipher": vmess.get("type", "auto"),
                    "tls": vmess.get("tls") == "tls",
                    "network": vmess.get("net", "tcp"),
                    "ws-opts": {"path": vmess.get("path", "")} if vmess.get("net") == "ws" else {}
                }
                proxies.append(proxy)
            elif line.startswith("ss://"):
                try:
                    decoded = base64.b64decode(line[5:].split('#')[0] + "===").decode('utf-8')
                    userinfo, server_port = decoded.split('@')
                    method, password = userinfo.split(':')
                    server, port = server_port.split(':')
                    name = urllib.parse.unquote(line.split('#')[-1]) if '#' in line else f"ss-{index}"
                    proxy = {
                        "name": name,
                        "type": "ss",
                        "server": server,
                        "port": int(port),
                        "cipher": method,
                        "password": password
                    }
                    proxies.append(proxy)
                except base64.binascii.Error:
                    print(f"⚠️ 跳过无效 Shadowsocks 节点（索引 {index}）：base64 解码失败 - {line[:30]}...")
            elif line.startswith("hysteria2://"):
                decoded = urllib.parse.urlparse(line)
                name = urllib.parse.unquote(decoded.fragment) if decoded.fragment else f"hysteria2-{index}"
                query = urllib.parse.parse_qs(decoded.query)
                proxy = {
                    "name": name,
                    "type": "hysteria2",
                    "server": decoded.hostname,
                    "port": int(decoded.port or 443),
                    "password": decoded.username or query.get("password", [""])[0],
                    "sni": query.get("sni", [""])[0] or decoded.hostname,
                    "skip-cert-verify": query.get("insecure", ["0"])[0] == "1"
                }
                proxies.append(proxy)
            elif line.startswith("trojan://"):
                decoded = urllib.parse.urlparse(line)
                name = urllib.parse.unquote(decoded.fragment) if decoded.fragment else f"trojan-{index}"
                query = urllib.parse.parse_qs(decoded.query)
                proxy = {
                    "name": name,
                    "type": "trojan",
                    "server": decoded.hostname,
                    "port": int(decoded.port or 443),
                    "password": decoded.username,
                    "sni": query.get("sni", [""])[0] or decoded.hostname,
                    "skip-cert-verify": query.get("allowInsecure", ["0"])[0] == "1"
                }
                proxies.append(proxy)
            elif line.startswith("ssr://"):
                decoded = base64.b64decode(line[6:].strip() + "===").decode('utf-8')
                parts = decoded.split(':')
                if len(parts) >= 6:
                    server, port, protocol, method, obfs, password = parts[:6]
                    password = base64.b64decode(password).decode('utf-8')
                    name = f"ssr-{index}"
                    if '#' in line:
                        name = urllib.parse.unquote(line.split('#')[-1])
                    proxy = {
                        "name": name,
                        "type": "ssr",
                        "server": server,
                        "port": int(port),
                        "password": password,
                        "cipher": method,
                        "protocol": protocol,
                        "obfs": obfs
                    }
                    proxies.append(proxy)
            elif line.startswith("vless://"):
                decoded = urllib.parse.urlparse(line)
                name = urllib.parse.unquote(decoded.fragment) if decoded.fragment else f"vless-{index}"
                query = urllib.parse.parse_qs(decoded.query)
                proxy = {
                    "name": name,
                    "type": "vless",
                    "server": decoded.hostname or query.get("host", [""])[0],
                    "port": int(decoded.port or 443),
                    "uuid": decoded.username,
                    "flow": query.get("flow", [""])[0],
                    "tls": query.get("security", ["none"])[0] == "tls",
                    "sni": query.get("sni", [""])[0] or decoded.hostname or query.get("host", [""])[0],
                    "ws-opts": {"path": query.get("path", [""])[0]} if query.get("type5", [""])[0] == "ws" else {}
                }
                proxies.append(proxy)
            else:
                print(f"⚠️ 跳过未知协议节点（索引 {index}）：{line[:30]}...")
        except Exception as e:
            print(f"⚠️ 跳过无效订阅节点（索引 {index}）：{line[:30]}... - 错误: {e}")
    return proxies

async def fetch_yaml_configs(urls: list[str]) -> list:
    """从 URL 列表获取 YAML 格式的 Clash 配置文件或订阅链接，并提取代理节点。"""
    all_proxies = []
    async with httpx.AsyncClient(timeout=30.0) as client:
        for url in urls:
            try:
                print(f"🔄 正在从 {url} 获取 YAML 配置文件...")
                response = await client.get(url)
                response.raise_for_status()
                response_text = response.text
                try:
                    # 尝试解析为 YAML
                    if response_text.strip().startswith(("proxies:", "---")):
                        yaml_content = yaml.safe_load(response_text)
                        proxies = yaml_content.get("proxies", [])
                    else:
                        # 尝试 base64 解码
                        try:
                            decoded_text = base64.b64decode(response_text + "===").decode('utf-8', errors='ignore')
                            if decoded_text.strip().startswith(("proxies:", "---")):
                                yaml_content = yaml.safe_load(decoded_text)
                                proxies = yaml_content.get("proxies", [])
                            else:
                                proxies = parse_v2ray_subscription(decoded_text)
                        except base64.binascii.Error:
                            proxies = parse_v2ray_subscription(response_text)
                except yaml.YAMLError:
                    proxies = parse_v2ray_subscription(response_text)
                
                if not proxies:
                    print(f"⚠️ 警告：{url} 中未找到代理节点")
                    continue
                
                parsed_count = 0
                for index, proxy in enumerate(proxies):
                    if index == 1878:
                        print(f"🔍 调试：第 1879 个节点配置: {json.dumps(proxy, ensure_ascii=False)}")
                    if index == 2435:
                        print(f"🔍 调试：第 2436 个节点配置: {json.dumps(proxy, ensure_ascii=False)}")
                    if validate_proxy(proxy, index):
                        all_proxies.append(proxy)
                        parsed_count += 1
                    else:
                        print(f"⚠️ 无效节点详情（索引 {index}）：{json.dumps(proxy, ensure_ascii=False)}")
                print(f"✅ 成功从 {url} 解析到 {parsed_count} 个有效代理节点。")
            except httpx.RequestError as e:
                print(f"❌ 错误：从 {url} 获取 YAML 配置失败：{e}")
            except Exception as e:
                print(f"❌ 发生未知错误，处理 {url} 时出现：{e}")
    return all_proxies

async def test_clash_meta_nodes(clash_core_path: str, config_path: str, all_proxies: list, api_port: int = 9090, retries: int = 3) -> list:
    """启动 Clash.Meta 核心，加载配置文件，测试代理节点延迟，返回测试通过的节点配置。"""
    tested_nodes_info = []
    async def read_stream_and_print(stream, name, log_file):
        with open(log_file, "a", encoding="utf-8") as f:
            while True:
                line = await stream.readline()
                if not line:
                    break
                line_str = line.decode('utf-8', errors='ignore').strip()
                print(f"[{name}] {line_str}")
                f.write(f"[{name}] {line_str}\n")
            print(f"[{name}] Stream finished.")
            f.write(f"[{name}] Stream finished.\n")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex(('127.0.0.1', api_port)) == 0:
            print(f"❌ 错误：端口 {api_port} 已被占用，请更换端口或释放端口")
            return []
    
    proxy_map = {proxy["name"]: proxy for proxy in all_proxies}
    
    for attempt in range(retries):
        clash_process = None
        stdout_task = None
        stderr_task = None
        print(f"\n🚀 尝试启动 Clash.Meta 核心 (第 {attempt + 1}/{retries})...")
        try:
            if not os.path.isfile(clash_core_path) or not os.access(clash_core_path, os.X_OK):
                print(f"❌ 错误：Clash.Meta 可执行文件不可用或无执行权限：{clash_core_path}")
                return []
            clash_process = await asyncio.create_subprocess_exec(
                clash_core_path,
                "-f", config_path,
                "-d", "./data",
                "-ext-ctl", f"0.0.0.0:{api_port}",
                "-ext-ui", "ui",
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            print(f"Clash.Meta 进程已启动，PID: {clash_process.pid}")
            stdout_task = asyncio.create_task(read_stream_and_print(clash_process.stdout, "Clash_STDOUT", "data/clash_stdout.log"))
            stderr_task = asyncio.create_task(read_stream_and_print(clash_process.stderr, "Clash_STDERR", "data/clash_stderr.log"))
            api_url_base = f"http://127.0.0.1:{api_port}"
            proxies_api_url = f"{api_url_base}/proxies"
            max_wait_time = 75
            wait_interval = 2
            print(f"正在尝试连接 Clash.Meta API ({api_url_base})...")
            async with httpx.AsyncClient(timeout=10.0) as client:
                connected = False
                for i in range(int(max_wait_time / wait_interval)):
                    try:
                        response = await client.get(proxies_api_url, timeout=wait_interval)
                        response.raise_for_status()
                        print(f"✅ 成功连接到 Clash.Meta API (耗时约 {i * wait_interval} 秒)。")
                        connected = True
                        break
                    except httpx.RequestError:
                        if clash_process.returncode is not None:
                            print(f"⚠️ Clash.Meta 进程已提前退出 (Exit Code: {clash_process.returncode})")
                            break
                        print(f"⏳ 等待 Clash.Meta API ({i * wait_interval + wait_interval}s/{max_wait_time}s)...")
                        await asyncio.sleep(wait_interval)
                if not connected:
                    print(f"❌ 超过 {max_wait_time} 秒未连接到 Clash.Meta API")
                    continue
                all_proxies_data = response.json()
                proxy_names = []
                for proxy_name, details in all_proxies_data.get("proxies", {}).items():
                    if details.get("type") not in ["Fallback", "Selector", "URLTest", "LoadBalance", "Direct", "Reject"]:
                        proxy_names.append(proxy_name)
                print(f"成功获取到 {len(proxy_names)} 个可测试代理的名称。")
                if not proxy_names:
                    print("🤷 没有找到任何可测试的代理节点。")
                    return []
                print("\n🔬 正在测试代理节点延迟...")
                tasks = []
                for name in proxy_names:
                    test_url = f"{proxies_api_url}/{urllib.parse.quote(name)}/delay?timeout=5000&url=http://www.google.com/generate_204"
                    tasks.append(client.get(test_url, timeout=10))
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for i, result in enumerate(results):
                    node_name = proxy_names[i]
                    if isinstance(result, httpx.Response):
                        try:
                            delay_data = result.json()
                            delay = delay_data.get("delay", -1)
                            if delay > 0:
                                print(f"✅ {node_name}: {delay}ms")
                                if node_name in proxy_map:
                                    tested_nodes_info.append({
                                        "name": node_name,
                                        "delay": delay,
                                        "config": proxy_map[node_name]
                                    })
                                else:
                                    print(f"⚠️ 警告：节点 {node_name} 不在原始代理列表中")
                            else:
                                print(f"💔 {node_name}: 测试失败/超时 ({delay_data.get('message', '未知错误')})")
                        except json.JSONDecodeError:
                            print(f"💔 {node_name}: 响应解析失败")
                    else:
                        print(f"💔 {node_name}: 请求错误 - {result}")
                tested_nodes_info.sort(key=lambda x: x["delay"])
                return tested_nodes_info
        except Exception as e:
            print(f"❌ 节点测试过程中发生错误: {e}")
            print(traceback.format_exc())
        finally:
            if clash_process and clash_process.returncode is None:
                print("🛑 正在停止 Clash.Meta 进程...")
                clash_process.terminate()
                try:
                    await asyncio.wait_for(clash_process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    clash_process.kill()
            if stdout_task:
                stdout_task.cancel()
                try:
                    await stdout_task
                except asyncio.CancelledError:
                    pass
            if stderr_task:
                stderr_task.cancel()
                try:
                    await stderr_task
                except asyncio.CancelledError:
                    pass
    print(f"❌ 经过 {retries} 次尝试，Clash.Meta 测试失败")
    return tested_nodes_info

async def main():
    print("🚀 开始从 URL 获取 YAML 格式的 Clash 配置文件...")
    os.makedirs("data", exist_ok=True)
    for log_file in ["data/clash_stdout.log", "data/clash_stderr.log", "data/all.txt"]:
        if os.path.exists(log_file):
            with open(log_file, "w", encoding="utf-8") as f:
                f.write("")
    
    all_proxies = await fetch_yaml_configs(CLASH_BASE_CONFIG_URLS)
    print(f"\n✅ 总共从 YAML 配置解析到 {len(all_proxies)} 个代理节点。")
    if not all_proxies:
        print("🤷 没有找到任何节点，无法进行测试。")
        with open("data/all.txt", "w", encoding="utf-8") as f:
            f.write("No proxies found.\n")
        return
    
    unique_proxies_map = {}
    for proxy in all_proxies:
        key = (
            proxy.get("type"),
            proxy.get("server"),
            proxy.get("port"),
            proxy.get("password", ""),
            proxy.get("cipher", ""),
            proxy.get("uuid", ""),
            proxy.get("tls", False)
        )
        if key not in unique_proxies_map:
            unique_proxies_map[key] = proxy
        else:
            print(f"  ➡️ 跳过重复节点: {proxy.get('name')} ({proxy.get('type')}, {proxy.get('server')}:{proxy.get('port')})")
    unique_proxies = list(unique_proxies_map.values())
    print(f"✨ 过滤重复后剩余 {len(unique_proxies)} 个唯一节点。")
    
    proxy_names = set()
    for proxy in unique_proxies:
        name = proxy.get("name")
        if name in proxy_names:
            print(f"⚠️ 警告：发现重复代理名称：{name}，正在重命名...")
            proxy["name"] = f"{name}-{len(proxy_names)}"
        proxy_names.add(proxy["name"])
    
    unified_clash_config = {
        "proxies": unique_proxies,
        "proxy-groups": [
            {
                "name": "Proxy All",
                "type": "select",
                "proxies": [p.get("name") for p in unique_proxies if p.get("name")]
            },
            {
                "name": "Auto Select (URLTest)",
                "type": "url-test",
                "proxies": [p.get("name") for p in unique_proxies if p.get("name")],
                "url": "http://www.google.com/generate_204",
                "interval": 300
            }
        ],
        "rules": [
            "MATCH,Proxy All"
        ],
        "dns": {
            "enable": True,
            "ipv6": False,
            "listen": "0.0.0.0:1053",
            "enhanced-mode": "fake-ip",
            "default-nameserver": [
                "114.114.114.114",
                "8.8.8.8"
            ],
            "nameserver": [
                "tls://dns.google/dns-query",
                "https://dns.alidns.com/dns-query"
            ]
        },
        "log-level": "info",
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": True,
        "external-controller": "0.0.0.0:9090",
        "external-ui": "ui"
    }
    
    unified_config_path = "data/unified_clash_config.yaml"
    try:
        with open(unified_config_path, "w", encoding="utf-8") as f:
            yaml.dump(unified_clash_config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        with open(unified_config_path, "r", encoding="utf-8") as f:
            config_content = yaml.safe_load(f)
            if "mode" in config_content:
                print(f"⚠️ 警告：配置文件中包含 mode 字段：{config_content['mode']}")
            else:
                print(f"✅ 配置文件验证通过，无 mode 字段")
        print(f"📦 统一的 Clash 配置文件已生成：{unified_config_path}")
    except Exception as e:
        print(f"❌ 错误：生成统一 Clash 配置文件失败：{e}")
        return
    
    clash_core_path = os.environ.get("CLASH_CORE_PATH")
    if not clash_core_path:
        print(f"❌ 错误：环境变量 CLASH_CORE_PATH 未设置，请设置指向 Clash.Meta 可执行文件的路径。")
        print("例如：export CLASH_CORE_PATH=/path/to/clash-meta")
        return
    
    print("\n--- 开始使用 Clash.Meta 进行节点延迟测试 ---")
    tested_nodes = await test_clash_meta_nodes(clash_core_path, unified_config_path, unique_proxies)
    
    with open("data/all.txt", "w", encoding="utf-8") as f:
        if tested_nodes:
            f.write("Tested Proxy Nodes (plaintext format, sorted by delay):\n")
            for node_info in tested_nodes:
                plaintext_node = to_plaintext_node(node_info["config"], node_info["delay"])
                if plaintext_node:
                    f.write(f"{plaintext_node}\n")
        else:
            f.write("No nodes passed the delay test.\n")
    print(f"📝 已将测试结果（明文节点格式）写入 data/all.txt")
    
    tested_config_path = "data/tested_clash_config.yaml"
    if tested_nodes:
        tested_proxies = [node_info["config"] for node_info in tested_nodes]
        tested_clash_config = {
            "proxies": tested_proxies,
            "proxy-groups": [
                {
                    "name": "Tested Proxies",
                    "type": "select",
                    "proxies": [p["name"] for p in tested_proxies]
                },
                {
                    "name": "Auto Select (URLTest)",
                    "type": "url-test",
                    "proxies": [p["name"] for p in tested_proxies],
                    "url": "http://www.google.com/generate_204",
                    "interval": 300
                }
            ],
            "rules": [
                "MATCH,Tested Proxies"
            ],
            "dns": {
                "enable": True,
                "ipv6": False,
                "listen": "0.0.0.0:1053",
                "enhanced-mode": "fake-ip",
                "default-nameserver": [
                    "114.114.114.114",
                    "8.8.8.8"
                ],
                "nameserver": [
                    "tls://dns.google/dns-query",
                    "https://dns.alidns.com/dns-query"
                ]
            },
            "log-level": "info",
            "port": 7890,
            "socks-port": 7891,
            "allow-lan": True,
            "external-controller": "0.0.0.0:9090",
            "external-ui": "ui"
        }
        try:
            with open(tested_config_path, "w", encoding="utf-8") as f:
                yaml.dump(tested_clash_config, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
            print(f"📦 测试通过的 Clash 配置文件已生成：{tested_config_path}")
        except Exception as e:
            print(f"❌ 错误：生成测试通过的 Clash 配置文件失败：{e}")
    
    print(f"\n✅ 最终的 YAML 配置文件已写入：{unified_config_path}")
    if tested_nodes:
        print(f"✅ 测试通过的 YAML 配置文件已写入：{tested_config_path}")
        print(f"总共输出 {len(tested_proxies)} 个测试通过的代理节点。")
    print(f"总共输出 {len(unique_proxies)} 个代理节点（全部）。")

if __name__ == "__main__":
    asyncio.run(main())
