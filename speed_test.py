import requests
import os
import subprocess
import json
import time
import re
import base64
from urllib.parse import urlparse, unquote, parse_qs

# 尝试导入协议解析库，如果失败则提供警告
try:
    from v2ray_url_parser import parse_url as v2ray_parse_url
except ImportError:
    v2ray_parse_url = None
    print("Warning: v2ray-url-parser not installed. VMess/VLESS/Trojan parsing might be limited.")

try:
    from ssr import parse_ssr_url as ssr_parse_url
except ImportError:
    ssr_parse_url = None
    print("Warning: ssr-parser not installed. SSR parsing might be limited.")


# 代理监听端口
SOCKS_PORT = 10800
HTTP_PORT = 10801
TEST_URL = "https://www.google.com/generate_204" # 用于测速的无内容响应URL
TIMEOUT_SECONDS = 7 # 测速超时时间，适当延长以应对网络波动
PROCESS_STARTUP_DELAY = 3 # 代理启动等待时间

def log_message(level, message):
    """统一日志输出函数"""
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    print(f"[{timestamp}][{level.upper()}] {message}")

def download_node_list(url):
    """从给定的 URL 下载节点列表."""
    try:
        log_message("info", f"尝试从 {url} 下载节点列表...")
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        log_message("info", "节点列表下载成功。")
        return [line.strip() for line in response.text.splitlines() if line.strip()]
    except requests.exceptions.RequestException as e:
        log_message("error", f"下载节点列表失败: {e}")
        return []

def measure_latency(proxy_type="http"):
    """
    通过代理测量到 TEST_URL 的延迟。
    """
    proxies = {
        "http": f"{proxy_type}://127.0.0.1:{HTTP_PORT}",
        "https": f"{proxy_type}://127.0.0.1:{HTTP_PORT}"
    }
    start_time = time.time()
    try:
        response = requests.get(TEST_URL, proxies=proxies, timeout=TIMEOUT_SECONDS, allow_redirects=False)
        response.raise_for_status()
        latency = (time.time() - start_time) * 1000 # 转换为毫秒
        return latency, "Success"
    except requests.exceptions.Timeout:
        return float('inf'), "Timeout"
    except requests.exceptions.ConnectionError:
        return float('inf'), "Connection Error"
    except requests.exceptions.RequestException as e:
        return float('inf'), f"Request Error: {e}"

def generate_singbox_config(node_url):
    """
    根据节点 URL 生成 Sing-Box 配置文件。
    支持 hysteria2, vmess, trojan, ss, vless
    """
    try:
        if node_url.startswith("hysteria2://"):
            # Hysteria2 解析 (简化版，需要根据实际参数完善)
            # 格式举例: hysteria2://password@server:port?insecure=1&upmbps=100&downmbps=100&obfs=none#remark
            parsed_url = urlparse(node_url)
            password = parsed_url.username
            server = parsed_url.hostname
            port = parsed_url.port
            query_params = parse_qs(parsed_url.query)
            remark = unquote(parsed_url.fragment) if parsed_url.fragment else "Hysteria2 Node"

            return json.dumps({
                "log": {"level": "warn"}, # 减少日志量
                "inbounds": [
                    {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": SOCKS_PORT},
                    {"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": HTTP_PORT}
                ],
                "outbounds": [
                    {
                        "type": "hysteria2",
                        "tag": "proxy",
                        "server": server,
                        "server_port": port,
                        "password": password,
                        "tls": {
                            "disable_sni": False,
                            "insecure": query_params.get("insecure", ["0"])[0] == "1",
                            "server_name": query_params.get("sni", [server])[0],
                        },
                        "up_mbps": int(query_params.get("upmbps", ["10"])[0]),
                        "down_mbps": int(query_params.get("downmbps", ["100"])[0]),
                        "obfs": query_params.get("obfs", ["none"])[0],
                        "obfs_password": query_params.get("obfs-password", [""])[0]
                    },
                    {"type": "direct", "tag": "direct"},
                    {"type": "block", "tag": "block"}
                ],
                "route": {"default_outbound": "proxy"}
            }, indent=2)

        elif node_url.startswith(("vmess://", "vless://", "trojan://")):
            if not v2ray_parse_url:
                log_message("warn", f"v2ray-url-parser未安装，无法解析 {node_url}")
                return None
            
            node_data = v2ray_parse_url(node_url)
            if not node_data:
                log_message("warn", f"使用v2ray-url-parser解析 {node_url} 失败.")
                return None

            # 提取通用参数
            protocol = node_data.get("protocol")
            server = node_data.get("address")
            port = node_data.get("port")
            uuid = node_data.get("id")
            password = node_data.get("password")
            alter_id = node_data.get("aid", 0) # VMess Only
            security = node_data.get("security", "auto") # VMess Only
            tls_enabled = node_data.get("tls", False) or node_data.get("network_security") == "tls" # VLESS/Trojan
            sni = node_data.get("sni") or node_data.get("host") # TLS SNI
            network = node_data.get("network", "tcp") # 传输协议

            # 传输协议设置
            transport_settings = {"type": network}
            if network == "ws":
                transport_settings["path"] = node_data.get("path", "/")
                transport_settings["headers"] = {"Host": node_data.get("host", server)}
            elif network == "grpc":
                transport_settings["service_name"] = node_data.get("serviceName", "")
                transport_settings["mode"] = node_data.get("mode", "gun") # gun or multi

            # TLS 设置
            tls_config = {}
            if tls_enabled:
                tls_config = {
                    "enabled": True,
                    "server_name": sni if sni else server,
                    "insecure": node_data.get("allowInsecure", False) # 允许不安全连接
                }
                # Reality 特有配置
                if node_data.get("fingerprint"):
                    tls_config["reality"] = {
                        "enabled": True,
                        "public_key": node_data.get("publicKey"),
                        "short_id": node_data.get("shortId"),
                        "fingerprint": node_data.get("fingerprint"),
                        "spider_x": node_data.get("spiderX", True)
                    }


            outbound_config = {
                "tag": "proxy",
                "server": server,
                "server_port": port,
                "tls": tls_config if tls_config.get("enabled") else None,
                "transport": transport_settings if transport_settings.get("type") != "tcp" else None
            }

            if protocol == "vmess":
                outbound_config.update({
                    "type": "vmess",
                    "uuid": uuid,
                    "security": security,
                    "alter_id": alter_id
                })
            elif protocol == "vless":
                outbound_config.update({
                    "type": "vless",
                    "uuid": uuid,
                    "flow": node_data.get("flow", "xtls-rprx-vision") if tls_enabled else "" # VLESS flow
                })
            elif protocol == "trojan":
                outbound_config.update({
                    "type": "trojan",
                    "password": password
                })
                # Trojan 通常强制 TLS
                if not tls_enabled:
                    outbound_config["tls"] = {"enabled": True, "server_name": sni if sni else server}
            else:
                log_message("warn", f"Sing-Box 暂不支持的 v2ray-url-parser 协议类型: {protocol}")
                return None

            config = {
                "log": {"level": "warn"},
                "inbounds": [
                    {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": SOCKS_PORT},
                    {"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": HTTP_PORT}
                ],
                "outbounds": [outbound_config, {"type": "direct", "tag": "direct"}, {"type": "block", "tag": "block"}],
                "route": {"default_outbound": "proxy"}
            }
            # 移除值为 None 的项，确保JSON干净
            clean_config(config)
            return json.dumps(config, indent=2)

        elif node_url.startswith("ss://"):
            # Shadowsocks 解析 (简化版，仅支持加密方式和密码)
            try:
                # ss://method:password@server:port#remark
                b64_part = node_url[5:].split('#')[0]
                decoded_str = base64.urlsafe_b64decode(b64_part + '=' * (-len(b64_part) % 4)).decode('utf-8')
                method_pass, server_port = decoded_str.split('@')
                method, password = method_pass.split(':')
                server, port = server_port.split(':')
                
                return json.dumps({
                    "log": {"level": "warn"},
                    "inbounds": [
                        {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": SOCKS_PORT},
                        {"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": HTTP_PORT}
                    ],
                    "outbounds": [
                        {
                            "type": "shadowsocks",
                            "tag": "proxy",
                            "server": server,
                            "server_port": int(port),
                            "method": method,
                            "password": password
                        },
                        {"type": "direct", "tag": "direct"},
                        {"type": "block", "tag": "block"}
                    ],
                    "route": {"default_outbound": "proxy"}
                }, indent=2)
            except Exception as e:
                log_message("warn", f"Sing-Box Shadowsocks 解析失败: {e} - {node_url}")
                return None

        elif node_url.startswith("ssr://"):
            if not ssr_parse_url:
                log_message("warn", f"ssr-parser未安装，无法解析 {node_url}")
                return None
            try:
                ssr_config = ssr_parse_url(node_url)
                # Sing-Box 对 SSR 的支持有限，可能需要将 SSR 转为 SS
                # 这是一个简化的转换，不包含所有 SSR 特有参数（如混淆、协议）
                # 如果 Sing-Box 不支持 SSR，你可以选择跳过或转换为支持的协议
                return json.dumps({
                    "log": {"level": "warn"},
                    "inbounds": [
                        {"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": SOCKS_PORT},
                        {"type": "http", "tag": "http-in", "listen": "127.0.0.1", "listen_port": HTTP_PORT}
                    ],
                    "outbounds": [
                        {
                            "type": "shadowsocks", # Sing-Box 通常将 SSR 作为一种 Shadowsocks 变体处理
                            "tag": "proxy",
                            "server": ssr_config['server'],
                            "server_port": ssr_config['port'],
                            "method": ssr_config['method'],
                            "password": ssr_config['password'],
                            # 混淆和协议可能需要特殊处理，Sing-Box 可能不支持所有 SSR 混淆
                            # 比如 plugin, plugin_options
                        },
                        {"type": "direct", "tag": "direct"},
                        {"type": "block", "tag": "block"}
                    ],
                    "route": {"default_outbound": "proxy"}
                }, indent=2)
            except Exception as e:
                log_message("warn", f"Sing-Box SSR 解析失败: {e} - {node_url}")
                return None

        log_message("warn", f"Sing-Box 不支持的协议类型或解析失败: {node_url}")
        return None
    except Exception as e:
        log_message("error", f"生成 Sing-Box 配置时发生未知错误: {e} - {node_url}")
        return None

def generate_xray_config(node_url):
    """
    根据节点 URL 生成 Xray Core 配置文件。
    支持 vmess, trojan, ss, ssr, vless
    Xray 不直接支持 Hysteria2
    """
    try:
        if node_url.startswith(("vmess://", "vless://", "trojan://")):
            if not v2ray_parse_url:
                log_message("warn", f"v2ray-url-parser未安装，无法解析 {node_url}")
                return None

            node_data = v2ray_parse_url(node_url)
            if not node_data:
                log_message("warn", f"使用v2ray-url-parser解析 {node_url} 失败.")
                return None
            
            protocol = node_data.get("protocol")
            server = node_data.get("address")
            port = node_data.get("port")
            uuid = node_data.get("id")
            password = node_data.get("password")
            alter_id = node_data.get("aid", 0)
            network = node_data.get("network", "tcp")
            tls_enabled = node_data.get("tls", False) or node_data.get("network_security") == "tls"
            sni = node_data.get("sni") or node_data.get("host")

            stream_settings = {"network": network}
            if tls_enabled:
                stream_settings["security"] = "tls"
                tls_settings = {"serverName": sni if sni else server}
                if node_data.get("allowInsecure", False):
                    tls_settings["allowInsecure"] = True
                # Reality 特有配置
                if node_data.get("fingerprint"):
                    tls_settings["realitySettings"] = {
                        "publicKey": node_data.get("publicKey"),
                        "shortId": node_data.get("shortId"),
                        "spiderX": node_data.get("spiderX", "")
                    }
                stream_settings["tlsSettings"] = tls_settings

            if network == "ws":
                stream_settings["wsSettings"] = {
                    "path": node_data.get("path", "/"),
                    "headers": {"Host": node_data.get("host", server)}
                }
            elif network == "grpc":
                stream_settings["grpcSettings"] = {
                    "serviceName": node_data.get("serviceName", ""),
                    "multiMode": node_data.get("mode", "gun") == "multi"
                }
            # 更多传输协议（kcp, quic等）需要根据实际情况添加

            outbound_config = {
                "tag": "proxy",
                "settings": {},
                "streamSettings": stream_settings
            }

            if protocol == "vmess":
                outbound_config["protocol"] = "vmess"
                outbound_config["settings"]["vnext"] = [{
                    "address": server,
                    "port": port,
                    "users": [{"id": uuid, "alterId": alter_id, "security": "auto"}]
                }]
            elif protocol == "vless":
                outbound_config["protocol"] = "vless"
                outbound_config["settings"]["vnext"] = [{
                    "address": server,
                    "port": port,
                    "users": [{"id": uuid, "encryption": "none", "flow": node_data.get("flow", "xtls-rprx-vision") if tls_enabled else ""}]
                }]
            elif protocol == "trojan":
                outbound_config["protocol"] = "trojan"
                outbound_config["settings"]["servers"] = [{
                    "address": server,
                    "port": port,
                    "password": password
                }]
            else:
                log_message("warn", f"Xray 暂不支持的 v2ray-url-parser 协议类型: {protocol}")
                return None

            config = {
                "log": {"loglevel": "warning"}, # 减少日志量
                "inbounds": [
                    {"port": SOCKS_PORT, "protocol": "socks"},
                    {"port": HTTP_PORT, "protocol": "http"}
                ],
                "outbounds": [outbound_config, {"protocol": "freedom", "tag": "direct"}, {"protocol": "blackhole", "tag": "blocked"}],
                "routing": {
                    "rules": [
                        {"type": "field", "domain": ["geosite:cn"], "outboundTag": "direct"},
                        {"type": "field", "ip": ["geoip:cn"], "outboundTag": "direct"},
                        {"type": "field", "domain": ["geosite:private"], "outboundTag": "direct"},
                        {"type": "field", "ip": ["geoip:private"], "outboundTag": "direct"}
                    ],
                    "outboundTag": "direct" # 默认直连，但测速时会强制使用 proxy outbound
                }
            }
            clean_config(config)
            return json.dumps(config, indent=2)

        elif node_url.startswith("ss://"):
            # Shadowsocks 解析
            try:
                # Xray 的 Shadowsocks 配置可能需要 plugin 字段
                b64_part = node_url[5:].split('#')[0]
                decoded_str = base64.urlsafe_b64decode(b64_part + '=' * (-len(b64_part) % 4)).decode('utf-8')
                method_pass, server_port = decoded_str.split('@')
                method, password = method_pass.split(':')
                server, port = server_port.split(':')

                return json.dumps({
                    "log": {"loglevel": "warning"},
                    "inbounds": [
                        {"port": SOCKS_PORT, "protocol": "socks"},
                        {"port": HTTP_PORT, "protocol": "http"}
                    ],
                    "outbounds": [
                        {
                            "protocol": "shadowsocks",
                            "settings": {
                                "servers": [{
                                    "address": server,
                                    "port": int(port),
                                    "method": method,
                                    "password": password
                                }]
                            }
                        },
                        {"protocol": "freedom", "tag": "direct"},
                        {"protocol": "blackhole", "tag": "blocked"}
                    ],
                    "routing": {"outboundTag": "direct"}
                }, indent=2)
            except Exception as e:
                log_message("warn", f"Xray Shadowsocks 解析失败: {e} - {node_url}")
                return None

        elif node_url.startswith("ssr://"):
            if not ssr_parse_url:
                log_message("warn", f"ssr-parser未安装，无法解析 {node_url}")
                return None
            try:
                ssr_config = ssr_parse_url(node_url)
                # Xray 对 SSR 的支持通常需要通过 Shadowsocks 协议加上 plugin
                # 这里只进行简化配置，可能无法支持所有 SSR 特性
                stream_settings = {"network": "tcp"}
                if ssr_config.get("obfs"):
                    # Xray plugin for obfs, e.g., simple_obfs
                    # Requires `v2ray-plugin` or `xray-plugin` to be installed and available
                    # This is highly dependent on environment and plugin availability.
                    log_message("warn", f"Xray 对 SSR 混淆 {ssr_config['obfs']} 的支持需要插件，本脚本未配置。")
                
                return json.dumps({
                    "log": {"loglevel": "warning"},
                    "inbounds": [
                        {"port": SOCKS_PORT, "protocol": "socks"},
                        {"port": HTTP_PORT, "protocol": "http"}
                    ],
                    "outbounds": [
                        {
                            "protocol": "shadowsocks",
                            "settings": {
                                "servers": [{
                                    "address": ssr_config['server'],
                                    "port": ssr_config['port'],
                                    "method": ssr_config['method'],
                                    "password": ssr_config['password'],
                                }]
                            },
                            "streamSettings": stream_settings
                        },
                        {"protocol": "freedom", "tag": "direct"},
                        {"protocol": "blackhole", "tag": "blocked"}
                    ],
                    "routing": {"outboundTag": "direct"}
                }, indent=2)
            except Exception as e:
                log_message("warn", f"Xray SSR 解析失败: {e} - {node_url}")
                return None

        log_message("warn", f"Xray 不支持的协议类型或解析失败: {node_url}")
        return None
    except Exception as e:
        log_message("error", f"生成 Xray 配置时发生未知错误: {e} - {node_url}")
        return None

def clean_config(config):
    """递归清理字典中值为 None 的项"""
    if isinstance(config, dict):
        return {k: clean_config(v) for k, v in config.items() if v is not None}
    elif isinstance(config, list):
        return [clean_config(elem) for elem in config if elem is not None]
    else:
        return config

def run_test(core_name, config_path, node_url_original):
    """
    运行 Sing-Box 或 Xray Core 进行测速。
    core_name: 'sing-box' 或 'xray'
    """
    process = None
    try:
        log_message("info", f"尝试启动 {core_name} with config: {config_path}")
        # Xray 在某些情况下需要完整的路由配置，如果默认路由没设好，测速可能不会通过代理
        # 所以这里的 routing default_outbound 都是 'direct'，需要在测速的时候确保请求会走 proxy
        # 注意: 命令行启动时，Xray/Sing-box 不会自动强制路由到 proxy，需要配置 routing rules
        # 这里 Xray 和 Sing-box 的配置都通过 default_outbound "proxy" 来保证测速流量走代理
        
        # 使用 stderr=subprocess.PIPE 来捕获错误输出，以便调试
        process = subprocess.Popen([core_name, 'run', '-c', config_path],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        log_message("info", f"等待 {core_name} 启动...")
        time.sleep(PROCESS_STARTUP_DELAY)

        latency, status_msg = measure_latency(proxy_type="http")
        
        # 即使测速失败，也尝试读取进程输出，可能包含有用错误信息
        stdout_data, stderr_data = "", ""
        try:
            # 使用 communicate() 确保进程完成，并获取所有输出
            stdout_data, stderr_data = process.communicate(timeout=5) 
        except subprocess.TimeoutExpired:
            process.kill()
            stdout_data, stderr_data = process.communicate() # 获取剩余输出
            log_message("warn", f"{core_name} 进程超时被终止。")
        
        if latency == float('inf') and stderr_data:
            log_message("error", f"{core_name} 错误输出: {stderr_data.strip()}")

        return latency, status_msg, stderr_data
    except FileNotFoundError:
        log_message("error", f"{core_name} 可执行文件未找到。请确保它已正确下载并添加到 PATH。")
        return float('inf'), f"{core_name} Executable Not Found", ""
    except Exception as e:
        log_message("error", f"运行 {core_name} 或测速失败: {e}")
        error_output = ""
        if process:
            try:
                # 尝试读取一些输出
                stdout_data, stderr_data = process.communicate(timeout=1)
                error_output = stderr_data
            except subprocess.TimeoutExpired:
                process.kill()
                error_output = "Process hung, killed."
        return float('inf'), f"General Error: {e}. Output: {error_output}", error_output
    finally:
        if process:
            log_message("info", f"终止 {core_name} 进程...")
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            log_message("info", f"{core_name} 进程已终止.")
        # 清理配置文件
        if os.path.exists(config_path):
            os.remove(config_path)

def main():
    node_list_url = "https://raw.githubusercontent.com/qjlxg/collectSub/refs/heads/main/all_nodes.txt"
    nodes = download_node_list(node_list_url)

    if not nodes:
        log_message("error", "未获取到节点列表，退出。")
        return

    os.makedirs('data', exist_ok=True)
    output_file = 'data/sub.txt'

    # 获取当前时间，作为本次测速的标记
    current_timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    
    # 追加模式打开文件
    with open(output_file, "a") as f_out:
        f_out.write(f"\n# Updated by GitHub Actions at {current_timestamp}\n")
        f_out.write("-------------------------------------\n")
        
        for i, node_url in enumerate(nodes):
            node_url = node_url.strip()
            if not node_url:
                continue

            log_message("info", f"\n--- 测试节点 {i+1}/{len(nodes)}: {node_url} ---")
            
            singbox_latency, singbox_status, singbox_stderr = float('inf'), "N/A", ""
            xray_latency, xray_status, xray_stderr = float('inf'), "N/A", ""

            # --- Sing-Box 测速 ---
            singbox_config_content = generate_singbox_config(node_url)
            if singbox_config_content:
                singbox_config_path = f"singbox_config_{i}.json"
                try:
                    with open(singbox_config_path, "w") as f_config:
                        f_config.write(singbox_config_content)
                    singbox_latency, singbox_status, singbox_stderr = run_test('sing-box', singbox_config_path, node_url)
                except Exception as e:
                    log_message("error", f"写入或运行 Sing-Box 配置失败: {e}")
                    singbox_status = f"Config Error: {e}"
            else:
                singbox_status = "Unsupported Protocol or Config Generation Failed"

            # --- Xray Core 测速 ---
            xray_config_content = generate_xray_config(node_url)
            if xray_config_content:
                xray_config_path = f"xray_config_{i}.json"
                try:
                    with open(xray_config_path, "w") as f_config:
                        f_config.write(xray_config_content)
                    xray_latency, xray_status, xray_stderr = run_test('xray', xray_config_path, node_url)
                except Exception as e:
                    log_message("error", f"写入或运行 Xray 配置失败: {e}")
                    xray_status = f"Config Error: {e}"
            else:
                xray_status = "Unsupported Protocol or Config Generation Failed"

            # 格式化并追加结果
            singbox_result = f"Sing-Box | {node_url} | 延迟: {singbox_latency:.2f}ms | 状态: {singbox_status}" \
                             if singbox_latency != float('inf') else f"Sing-Box | {node_url} | 延迟: N/A | 状态: {singbox_status}"
            if singbox_stderr:
                singbox_result += f" | Sing-Box Log: {singbox_stderr.replace('\n', ' ')}" # 将日志扁平化

            xray_result = f"Xray Core | {node_url} | 延迟: {xray_latency:.2f}ms | 状态: {xray_status}" \
                          if xray_latency != float('inf') else f"Xray Core | {node_url} | 延迟: N/A | 状态: {xray_status}"
            if xray_stderr:
                xray_result += f" | Xray Log: {xray_stderr.replace('\n', ' ')}" # 将日志扁平化
            
            f_out.write(singbox_result + "\n")
            f_out.write(xray_result + "\n")
            f_out.flush() # 每次写入后刷新缓冲区，确保内容及时写入文件

        f_out.write("-------------------------------------\n")
        log_message("info", f"\n所有节点测速完成，结果已追加保存到 {output_file}")

if __name__ == "__main__":
    main()
