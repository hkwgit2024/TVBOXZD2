import httpx
import yaml
import asyncio
import base64
import json
import os
import urllib.parse
import subprocess
import time

# 将你的来源链接设置为默认值。
CLASH_BASE_CONFIG_URLS = [
    "https://snippet.host/oouyda/raw"
]

# --- parse_node_link_to_clash_proxy 函数 ---
def parse_node_link_to_clash_proxy(link: str) -> dict | None:
    """
    尝试将一个明文节点链接（ss, vmess, trojan, hy2, vless等）
    解析成Clash代理字典格式。
    """
    if not link or "://" not in link:
        return None

    try:
        scheme, remainder = link.split("://", 1)
        name_part = None
        if "#" in remainder:
            remainder, name_part = remainder.split("#", 1)
            name_part = urllib.parse.unquote(name_part)

        proxy = {"name": name_part if name_part else f"{scheme} Node", "type": scheme}

        if scheme == "ss":
            try:
                # 尝试修复 Base64 填充问题，并捕获解码错误
                base64_part_raw = remainder.split("@", 1)[0]
                # Base64 字符串的长度必须是 4 的倍数，不足时填充 '='
                missing_padding = len(base64_part_raw) % 4
                if missing_padding != 0:
                    base64_part = base64_part_raw + '=' * (4 - missing_padding)
                else:
                    base64_part = base64_part_raw

                decoded_userinfo = base64.urlsafe_b64decode(base64_part).decode()
                method, password = decoded_userinfo.split(":", 1)
                server_port = remainder.split("@", 1)[1]
                server, port = server_port.split(":", 1)

                proxy.update({
                    "type": "ss",
                    "server": server,
                    "port": int(port),
                    "cipher": method,
                    "password": password
                })
            except (base64.binascii.Error, ValueError, IndexError) as e:
                print(f"❌ 错误：解析SS链接失败（Base64解码或格式问题）：{link} - {e}")
                return None
            except Exception as e:
                print(f"❌ 错误：解析SS链接失败：{link} - {e}")
                return None
        elif scheme == "vmess":
            try:
                # 尝试修复 Base64 填充问题，并捕获解码错误
                vmess_base64_raw = remainder
                missing_padding = len(vmess_base64_raw) % 4
                if missing_padding != 0:
                    vmess_base64 = vmess_base64_raw + '=' * (4 - missing_padding)
                else:
                    vmess_base64 = vmess_base64_raw

                decoded_json_str = base64.urlsafe_b64decode(vmess_base64).decode('utf-8')
                vmess_config = json.loads(decoded_json_str)

                proxy.update({
                    "type": "vmess",
                    "server": vmess_config.get("add"),
                    "port": int(vmess_config.get("port")),
                    "uuid": vmess_config.get("id"),
                    "alterId": int(vmess_config.get("aid", 0)),
                    "cipher": vmess_config.get("scy", "auto"),
                    "network": vmess_config.get("net", "tcp"),
                    "tls": vmess_config.get("tls") == "tls",
                    "servername": vmess_config.get("sni"),
                    "ws-path": vmess_config.get("path", "/"),
                    "ws-headers": {"Host": vmess_config.get("host")} if vmess_config.get("host") else {}
                })
                proxy = {k: v for k, v in proxy.items() if v not in [None, '', {}]}
            except (base64.binascii.Error, ValueError, json.JSONDecodeError, IndexError) as e:
                print(f"❌ 错误：解析Vmess链接失败（Base64解码或JSON格式问题）：{link} - {e}")
                return None
            except Exception as e:
                print(f"❌ 错误：解析Vmess链接失败：{link} - {e}")
                return None
        elif scheme == "trojan":
            try:
                password_server_port, query_params_str = remainder.split("?", 1) if "?" in remainder else (remainder, "")
                password, server_port = password_server_port.split("@", 1)
                server, port = server_port.split(":", 1)

                proxy.update({
                    "type": "trojan",
                    "server": server,
                    "port": int(port),
                    "password": urllib.parse.unquote(password)
                })

                if query_params_str:
                    query_params = urllib.parse.parse_qs(query_params_str)
                    if "security" in query_params and query_params["security"][0] == "tls":
                        proxy["tls"] = True
                    if "sni" in query_params:
                        proxy["servername"] = query_params["sni"][0]
                    if "allowInsecure" in query_params and query_params["allowInsecure"][0] == "1":
                        proxy["skip-cert-verify"] = True
                    if "type" in query_params:
                        proxy["network"] = query_params["type"][0]
            except Exception as e:
                print(f"❌ 错误：解析Trojan链接失败：{link} - {e}")
                return None
        elif scheme == "hy2":
            try:
                password_server_port, query_params_str = remainder.split("?", 1) if "?" in remainder else (remainder, "")
                password_encoded, server_port = password_server_port.split("@", 1)
                server, port = server_port.split(":", 1)

                proxy.update({
                    "type": "hysteria2",
                    "server": server,
                    "port": int(port),
                    "password": password_encoded,
                })

                if query_params_str:
                    query_params = urllib.parse.parse_qs(query_params_str)
                    if "insecure" in query_params and query_params["insecure"][0] == "1":
                        proxy["skip-cert-verify"] = True
                    if "sni" in query_params:
                        proxy["servername"] = query_params["sni"][0]
            except Exception as e:
                print(f"❌ 错误：解析Hysteria2链接失败：{link} - {e}")
                return None
        elif scheme == "vless":
            try:
                uuid_server_port, query_params_str = remainder.split("?", 1) if "?" in remainder else (remainder, "")
                uuid, server_port = uuid_server_port.split("@", 1)
                server, port = server_port.split(":", 1)

                proxy.update({
                    "type": "vless",
                    "server": server,
                    "port": int(port),
                    "uuid": uuid,
                    "cipher": "auto"
                })

                if query_params_str:
                    query_params = urllib.parse.parse_qs(query_params_str)
                    if "security" in query_params and query_params["security"][0] == "tls":
                        proxy["tls"] = True
                    if "sni" in query_params:
                        proxy["servername"] = query_params["sni"][0]
                    if "type" in query_params:
                        proxy["network"] = query_params["type"][0]
                    if "path" in query_params:
                        proxy["ws-path"] = query_params["path"][0]
                    if "host" in query_params:
                        proxy["ws-headers"] = {"Host": query_params["host"][0]}
            except Exception as e:
                print(f"❌ 错误：解析Vless链接失败：{link} - {e}")
                return None
        else:
            print(f"⚠️ 警告：跳过不支持的协议类型：{scheme} (链接: {link})")
            return None

        if not proxy.get("name") and name_part:
             proxy["name"] = name_part
        elif not proxy.get("name"):
            proxy["name"] = f"{proxy.get('type', 'unknown').upper()}-{proxy.get('server', 'unknown')}:{proxy.get('port', 'unknown')}"

        return proxy

    except Exception as e:
        print(f"❌ 错误：解析未知链接格式失败：{link} - {e}")
        return None

# --- fetch_all_configs 函数 ---
async def fetch_all_configs(urls: list[str]) -> list:
    """
    从给定的 URL 列表中获取纯文本节点链接，并尝试解析成Clash代理字典。
    """
    all_proxies = []
    async with httpx.AsyncClient() as client:
        for url in urls:
            try:
                print(f"🔄 正在从 {url} 获取节点链接列表...")
                response = await client.get(url, timeout=20)
                response.raise_for_status()
                node_links_content = response.text

                lines = node_links_content.strip().split("\n")
                
                parsed_count = 0
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    
                    proxy_obj = parse_node_link_to_clash_proxy(line)
                    if proxy_obj:
                        all_proxies.append(proxy_obj)
                        parsed_count += 1
                
                print(f"✅ 成功从 {url} 解析到 {parsed_count} 个代理节点。")

            except httpx.RequestError as e:
                print(f"❌ 错误：从 {url} 获取节点链接失败：{e}")
            except Exception as e:
                print(f"❌ 发生未知错误，处理 {url} 时出现：{e}")
    return all_proxies

# --- generate_plaintext_node_link 函数 ---
def generate_plaintext_node_link(proxy: dict) -> str | None:
    """
    根据Clash代理字典生成明文节点链接（例如 ss://, vmess://）。
    """
    p_type = proxy.get("type")
    p_name = proxy.get("name", "Unnamed Node")

    if p_type == "ss":
        server = proxy.get("server")
        port = proxy.get("port")
        password = proxy.get("password")
        cipher = proxy.get("cipher")
        if all([server, port, password, cipher]):
            userinfo = f"{cipher}:{password}@{server}:{port}"
            encoded_userinfo = base64.urlsafe_b64encode(userinfo.encode()).decode().rstrip('=')
            safe_name = urllib.parse.quote(p_name)
            return f"ss://{encoded_userinfo}#{safe_name}"
    elif p_type == "vmess":
        server = proxy.get("server")
        port = proxy.get("port")
        uuid = proxy.get("uuid")
        alterId = proxy.get("alterId", 0)
        cipher = proxy.get("cipher", "auto")
        network = proxy.get("network", "tcp")
        tls = proxy.get("tls", False)
        servername = proxy.get("servername", "")
        ws_path = proxy.get("ws-path", "")
        ws_headers = proxy.get("ws-headers", {}).get("Host", "")

        if all([server, port, uuid]):
            vmess_obj = {
                "v": "2",
                "ps": p_name,
                "add": server,
                "port": str(port),
                "id": uuid,
                "aid": str(alterId),
                "scy": cipher,
                "net": network,
            }
            if ws_path: vmess_obj["path"] = ws_path
            if ws_headers: vmess_obj["host"] = ws_headers
            if tls: vmess_obj["tls"] = "tls"
            if servername: vmess_obj["sni"] = servername

            vmess_obj = {k: v for k, v in vmess_obj.items() if v}
            
            try:
                vmess_json = json.dumps(vmess_obj, ensure_ascii=False)
                encoded_vmess = base64.urlsafe_b64encode(vmess_json.encode('utf-8')).decode('utf-8').rstrip('=')
                return f"vmess://{encoded_vmess}"
            except Exception as e:
                print(f"❌ 错误：生成 Vmess 链接失败，节点：{p_name}，错误：{e}")
                return None
    elif p_type == "trojan":
        server = proxy.get("server")
        port = proxy.get("port")
        password = proxy.get("password")
        tls = proxy.get("tls", False)
        sni = proxy.get("servername", "")
        skip_cert_verify = proxy.get("skip-cert-verify", False)
        network = proxy.get("network", "tcp")

        if all([server, port, password]):
            params = []
            if tls:
                params.append("security=tls")
            if sni:
                params.append(f"sni={sni}")
            if skip_cert_verify:
                params.append("allowInsecure=1")
            if network != "tcp":
                params.append(f"type={network}")
            
            param_str = "&".join(params)
            encoded_password = urllib.parse.quote(password)
            safe_name = urllib.parse.quote(p_name)
            
            link = f"trojan://{encoded_password}@{server}:{port}"
            if param_str:
                link += f"?{param_str}"
            link += f"#{safe_name}"
            return link
    elif p_type == "hy2":
        server = proxy.get("server")
        port = proxy.get("port")
        password = proxy.get("password")
        skip_cert_verify = proxy.get("skip-cert-verify", False)
        servername = proxy.get("servername", "")

        if all([server, port, password]):
            params = []
            if skip_cert_verify:
                params.append("insecure=1")
            if servername:
                params.append(f"sni={servername}")
            
            param_str = "&".join(params)
            encoded_password = urllib.parse.quote(password)
            safe_name = urllib.parse.quote(p_name)

            link = f"hy2://{encoded_password}@{server}:{port}"
            if param_str:
                link += f"?{param_str}"
            link += f"#{safe_name}"
            return link
    elif p_type == "vless":
        server = proxy.get("server")
        port = proxy.get("port")
        uuid = proxy.get("uuid")
        tls = proxy.get("tls", False)
        servername = proxy.get("servername", "")
        network = proxy.get("network", "tcp")
        ws_path = proxy.get("ws-path", "")
        ws_host = proxy.get("ws-headers", {}).get("Host", "")

        if all([server, port, uuid]):
            params = []
            if tls:
                params.append("security=tls")
            if servername:
                params.append(f"sni={servername}")
            if network:
                params.append(f"type={network}")
            if ws_path:
                params.append(f"path={urllib.parse.quote(ws_path)}")
            if ws_host:
                params.append(f"host={urllib.parse.quote(ws_host)}")

            param_str = "&".join(params)
            safe_name = urllib.parse.quote(p_name)

            link = f"vless://{uuid}@{server}:{port}"
            if param_str:
                link += f"?{param_str}"
            link += f"#{safe_name}"
            return link

    return None

# --- test_clash_meta_nodes 函数 ---
async def test_clash_meta_nodes(clash_core_path: str, config_path: str, api_port: int = 9090) -> list:
    """
    启动 Clash.Meta 核心，加载配置文件，并通过其 API 测试所有代理节点的延迟。
    返回一个包含测试结果（节点名和延迟）的列表。
    """
    clash_process = None
    tested_nodes_info = []
    
    # 异步函数：用于从StreamReader中实时读取并打印输出
    async def read_stream_and_print(stream, name):
        while True:
            line = await stream.readline() # 异步读取一行
            if not line: # EOF
                break
            print(f"[{name}] {line.decode('utf-8', errors='ignore').strip()}")
        print(f"[{name}] Stream finished.")

    try:
        print(f"\n🚀 正在启动 Clash.Meta 核心进行测试...")
        # 使用 asyncio.create_subprocess_exec 来启动子进程，它会返回一个 Process 对象
        # 这个 Process 对象的 stdout 和 stderr 是 asyncio.StreamReader，可以直接异步读取
        clash_process = await asyncio.create_subprocess_exec(
            clash_core_path,
            "-f", config_path,
            "-d", "./data",
            "-ext-ctl", f"0.0.0.0:{api_port}",
            "-ext-ui", "ui",
            stdout=asyncio.PIPE,
            stderr=asyncio.PIPE
        )
        print(f"Clash.Meta 进程已启动，PID: {clash_process.pid}")

        # 创建任务来实时读取 Clash.Meta 的输出
        stdout_task = asyncio.create_task(read_stream_and_print(clash_process.stdout, "Clash_STDOUT"))
        stderr_task = asyncio.create_task(read_stream_and_print(clash_process.stderr, "Clash_STDERR"))

        # --- 优化等待逻辑 ---
        api_url_base = f"http://127.0.0.1:{api_port}"
        proxies_api_url = f"{api_url_base}/proxies"
        max_wait_time = 75 # 进一步增加最大等待秒数，给Clash.Meta更多启动时间
        wait_interval = 2 # 每次检查间隔秒数
        
        print(f"正在尝试连接 Clash.Meta API ({api_url_base})...")
        async with httpx.AsyncClient() as client:
            connected = False
            for i in range(int(max_wait_time / wait_interval)):
                try:
                    response = await client.get(proxies_api_url, timeout=wait_interval)
                    response.raise_for_status()
                    print(f"✅ 成功连接到 Clash.Meta API (耗时约 {i * wait_interval} 秒)。")
                    connected = True
                    break # 连接成功，跳出循环
                except httpx.RequestError:
                    # 检查Clash进程是否已经退出，如果退出则无需继续等待
                    if clash_process.returncode is not None: # returncode is not None means process has exited
                        print(f"⚠️ Clash.Meta 进程已提前退出 (Exit Code: {clash_process.returncode})，无法连接API。")
                        break
                    print(f"⏳ 等待 Clash.Meta API ({i * wait_interval + wait_interval}s/{max_wait_time}s)...")
                    await asyncio.sleep(wait_interval)
            
            if not connected:
                print(f"❌ 超过 {max_wait_time} 秒未连接到 Clash.Meta API，跳过测试。")
                return []
        # --- 优化等待逻辑结束 ---

            # 获取所有代理名称
            all_proxies_data = response.json() # 使用上面已成功获取的响应
            proxy_names = []
            for proxy_name, details in all_proxies_data.get("proxies", {}).items():
                # 过滤掉Clash的内置代理组类型，只保留实际的代理节点
                if details.get("type") not in ["Fallback", "Selector", "URLTest", "LoadBalance", "Direct", "Reject"]:
                    proxy_names.append(proxy_name)
            print(f"成功获取到 {len(proxy_names)} 个可测试代理的名称。")
            
            if not proxy_names:
                print("🤷 没有找到任何可测试的代理节点。")
                return []

            print("\n🔬 正在测试代理节点延迟...")
            tasks = []
            for name in proxy_names:
                # 使用 http://www.google.com/generate_204 作为测试URL，因为它返回一个空响应，适合测延迟
                test_url = f"{proxies_api_url}/{urllib.parse.quote(name)}/delay?timeout=5000&url=http://www.google.com/generate_204"
                tasks.append(client.get(test_url, timeout=10))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for i, result in enumerate(results):
                node_name = proxy_names[i]
                if isinstance(result, httpx.Response):
                    try:
                        delay_data = result.json()
                        delay = delay_data.get("delay", -1)
                        if delay > 0: # 延迟大于0表示测试成功
                            print(f"✅ {node_name}: {delay}ms")
                            tested_nodes_info.append({"name": node_name, "delay": delay})
                        else:
                            # 延迟为-1或其他非正值表示测试失败或超时
                            print(f"💔 {node_name}: 测试失败/超时 ({delay_data.get('message', '未知错误')})")
                    except json.JSONDecodeError:
                        print(f"💔 {node_name}: 响应解析失败")
                elif isinstance(result, httpx.RequestError):
                    print(f"💔 {node_name}: 请求错误 - {result}")
                else:
                    print(f"💔 {node_name}: 未知测试错误 - {result}")

    except Exception as e:
        print(f"❌ 节点测试过程中发生错误: {e}")
    finally:
        # 确保停止 Clash.Meta 进程，并等待其输出任务完成
        if clash_process and clash_process.returncode is None: # 如果进程仍在运行
            print("🛑 正在停止 Clash.Meta 进程...")
            clash_process.terminate() # 发送终止信号
            try:
                await asyncio.wait_for(clash_process.wait(), timeout=5) # 异步等待进程结束
            except asyncio.TimeoutError:
                clash_process.kill() # 强制杀死进程

        # 确保日志读取任务被取消和清理
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

    tested_nodes_info.sort(key=lambda x: x["delay"])
    return tested_nodes_info

# --- main 函数 ---
async def main():
    print("🚀 开始从 URL 获取明文节点链接列表并处理...")
    all_proxies = []
    all_proxies = await fetch_all_configs(CLASH_BASE_CONFIG_URLS)

    print(f"\n✅ 总共从链接解析到 {len(all_proxies)} 个代理节点。")

    if not all_proxies:
        print("🤷 没有找到任何节点，无法进行测试和生成链接。")
        with open("data/all.txt", "w", encoding="utf-8") as f:
            f.write("")
        return

    unique_proxies_map = {}
    for proxy in all_proxies:
        # 使用更严格的去重标准：名称、类型、服务器、端口都相同才算重复
        key = (
            proxy.get("name"),
            proxy.get("type"),
            proxy.get("server"),
            proxy.get("port")
        )
        if key not in unique_proxies_map:
             unique_proxies_map[key] = proxy
        else:
             print(f"  ➡️ 跳过重复节点: {proxy.get('name')} ({proxy.get('type')}, {proxy.get('server')}:{proxy.get('port')})")
    
    unique_proxies = list(unique_proxies_map.values())
    print(f"✨ 过滤重复后剩余 {len(unique_proxies)} 个唯一节点。")

    # 生成统一的 Clash 配置文件
    unified_clash_config = {
        "proxies": unique_proxies,
        "proxy-groups": [
            {
                "name": "Proxy All",
                "type": "select",
                "proxies": [p.get("name") for p in unique_proxies if p.get("name")]
            },
            # 增加一个 URLTest 代理组，Clash.Meta 会自动测试其中的节点
            {
                "name": "Auto Select (URLTest)",
                "type": "url-test",
                "proxies": [p.get("name") for p in unique_proxies if p.get("name")],
                "url": "http://www.google.com/generate_204", # 测试URL
                "interval": 300 # 测试间隔，单位秒，这里设置为5分钟
            }
        ],
        "rules": [
            "MATCH,Proxy All" # 默认规则，所有流量走 Proxy All 组
        ],
        "dns": {
            "enable": True,
            "ipv6": False,
            "listen": "0.0.0.0:53",
            "enhanced-mode": True,
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
        "port": 7890, # HTTP代理端口
        "socks-port": 7891, # SOCKS代理端口
        "mode": "rule",
        "allow-lan": True, # 允许局域网访问，方便API调用
        "external-controller": "0.0.0.0:9090", # 外部控制API端口
        "external-ui": "ui" # 如果有UI文件，可以指定
    }

    unified_config_path = "data/unified_clash_config.yaml"
    try:
        with open(unified_config_path, "w", encoding="utf-8") as f:
            yaml.dump(unified_clash_config, f, allow_unicode=True, sort_keys=False)
        print(f"📦 统一的 Clash 配置文件已生成：{unified_config_path}")
    except Exception as e:
        print(f"❌ 错误：生成统一 Clash 配置文件失败：{e}")

    # 检查 CLASH_CORE_PATH 环境变量是否存在
    clash_core_path = os.environ.get("CLASH_CORE_PATH")
    if not clash_core_path:
        print("❌ 错误：环境变量 CLASH_CORE_PATH 未设置，无法执行 Clash.Meta 测试。")
        # 即使无法测试，也要尝试生成原始明文链接，以防万一
        output_file_path = "data/all.txt"
        with open(output_file_path, "w", encoding="utf-8") as f:
            for link in [generate_plaintext_node_link(node) for node in unique_proxies if generate_plaintext_node_link(node)]:
                f.write(link + "\n")
        print(f"➡️ 仅生成明文链接到：{output_file_path}")
        print(f"总共生成 {len(unique_proxies)} 条明文链接。")
        return # 提前退出，不再尝试进行Clash测试

    print("\n--- 开始使用 Clash.Meta 进行节点延迟测试 ---")
    tested_nodes = await test_clash_meta_nodes(clash_core_path, unified_config_path)

    # 根据测试结果生成最终的明文链接列表
    final_output_links = []
    if tested_nodes:
        print("\n--- 延迟测试结果 (按延迟升序) ---")
        for node_info in tested_nodes:
            # 找到原始的代理对象来生成明文链接
            original_node = next((p for p in unique_proxies if p.get("name") == node_info["name"]), None)
            if original_node:
                link = generate_plaintext_node_link(original_node)
                if link:
                    # 将延迟信息添加到链接后面
                    final_output_links.append(f"{link} # {node_info['delay']}ms")
                    print(f"{node_info['name']}: {node_info['delay']}ms -> {link}")
                else:
                    print(f"{node_info['name']}: {node_info['delay']}ms -> 无法生成明文链接")
            else:
                print(f"⚠️ 警告：找不到原始节点信息 '{node_info['name']}'")
    else:
        print("\n😔 没有节点通过延迟测试。")
        # 如果没有节点通过测试，仍然输出原始的明文链接（不带延迟信息）
        # 避免 data/all.txt 为空导致后续的 git commit 警告或失败
        final_output_links = [generate_plaintext_node_link(node) for node in unique_proxies if generate_plaintext_node_link(node)]


    # 将最终的测试结果写入 data/all.txt
    output_file_path = "data/all.txt"
    with open(output_file_path, "w", encoding="utf-8") as f:
        for link in final_output_links:
            f.write(link + "\n")
    print(f"\n✅ 最终的测试结果和明文链接已写入：{output_file_path}")
    print(f"总共输出 {len(final_output_links)} 条结果。")


if __name__ == "__main__":
    # 确保安装了 httpx 和 PyYAML
    # Clash.Meta 核心路径由 GitHub Actions 环境变量提供
    asyncio.run(main())
