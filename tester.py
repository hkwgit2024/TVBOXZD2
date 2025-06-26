import httpx
import yaml # 仍然需要用于生成最终的 Clash YAML 配置
import asyncio
import base64
import json
import os
import urllib.parse # 用于解析URL编码的参数

# 将你的来源链接设置为默认值。
# 现在这个链接不再返回一个完整的Clash YAML配置，
# 而是返回一个每行一个节点链接的纯文本文件。
CLASH_BASE_CONFIG_URLS = [
    "https://snippet.host/oouyda/raw"
]

# --- 新增：解析单行节点链接的函数 ---
def parse_node_link_to_clash_proxy(link: str) -> dict | None:
    """
    尝试将一个明文节点链接（ss, vmess, trojan, hy2, vless等）
    解析成Clash代理字典格式。
    注意：这是一个复杂的过程，需要根据不同的协议实现详细解析。
    这里只包含常见字段和基本解析逻辑。
    """
    if not link or "://" not in link:
        return None

    try:
        scheme, remainder = link.split("://", 1)
        name_part = None
        if "#" in remainder:
            remainder, name_part = remainder.split("#", 1)
            name_part = urllib.parse.unquote(name_part) # 解码URL编码的名称

        proxy = {"name": name_part if name_part else f"{scheme} Node", "type": scheme}

        if scheme == "ss":
            # ss://base64(method:password@server:port)#name
            try:
                base64_part = remainder.split("@", 1)[0]
                decoded_userinfo = base64.urlsafe_b64decode(base64_part + '=' * (-len(base64_part) % 4)).decode()
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
            except Exception as e:
                print(f"❌ 错误：解析SS链接失败：{link} - {e}")
                return None
        elif scheme == "vmess":
            # vmess://base64(json_config)
            try:
                decoded_json_str = base64.urlsafe_b64decode(remainder + '=' * (-len(remainder) % 4)).decode('utf-8')
                vmess_config = json.loads(decoded_json_str)

                proxy.update({
                    "type": "vmess",
                    "server": vmess_config.get("add"),
                    "port": int(vmess_config.get("port")),
                    "uuid": vmess_config.get("id"),
                    "alterId": int(vmess_config.get("aid", 0)),
                    "cipher": vmess_config.get("scy", "auto"), # scy 对应 cipher
                    "network": vmess_config.get("net", "tcp"),
                    "tls": vmess_config.get("tls") == "tls",
                    "servername": vmess_config.get("sni"), # sni 对应 servername
                    "ws-path": vmess_config.get("path", "/"),
                    "ws-headers": {"Host": vmess_config.get("host")} if vmess_config.get("host") else {}
                    # 更多Vmess字段需要进一步解析
                })
                # 清理空值
                proxy = {k: v for k, v in proxy.items() if v not in [None, '', {}]}
            except Exception as e:
                print(f"❌ 错误：解析Vmess链接失败：{link} - {e}")
                return None
        elif scheme == "trojan":
            # trojan://password@server:port?params#name
            try:
                password_server_port, query_params_str = remainder.split("?", 1) if "?" in remainder else (remainder, "")
                password, server_port = password_server_port.split("@", 1)
                server, port = server_port.split(":", 1)

                proxy.update({
                    "type": "trojan",
                    "server": server,
                    "port": int(port),
                    "password": urllib.parse.unquote(password) # 解码密码
                })

                if query_params_str:
                    query_params = urllib.parse.parse_qs(query_params_str)
                    if "security" in query_params and query_params["security"][0] == "tls":
                        proxy["tls"] = True
                    if "sni" in query_params:
                        proxy["servername"] = query_params["sni"][0]
                    if "allowInsecure" in query_params and query_params["allowInsecure"][0] == "1":
                        proxy["skip-cert-verify"] = True # Clash 的 skip-cert-verify
                    if "type" in query_params:
                        proxy["network"] = query_params["type"][0]
                    # Clash 不直接支持 alpn 参数，通常与 tls/servername 关联
            except Exception as e:
                print(f"❌ 错误：解析Trojan链接失败：{link} - {e}")
                return None
        elif scheme == "hy2": # Hysteria 2 协议
            # hy2://password@server:port?params#name
            try:
                password_server_port, query_params_str = remainder.split("?", 1) if "?" in remainder else (remainder, "")
                password_encoded, server_port = password_server_port.split("@", 1)
                server, port = server_port.split(":", 1)

                proxy.update({
                    "type": "hysteria2", # Clash.Meta 中的类型
                    "server": server,
                    "port": int(port),
                    "password": password_encoded, # Hysteria 2 密码可能也需要解码，取决于实际情况
                })

                if query_params_str:
                    query_params = urllib.parse.parse_qs(query_params_str)
                    if "insecure" in query_params and query_params["insecure"][0] == "1":
                        proxy["skip-cert-verify"] = True
                    if "sni" in query_params:
                        proxy["servername"] = query_params["sni"][0]
                    # Hysteria 2 还有很多其他参数，如 up/down, alpn, obfs 等，需要进一步添加
            except Exception as e:
                print(f"❌ 错误：解析Hysteria2链接失败：{link} - {e}")
                return None
        elif scheme == "vless": # Vless 协议
            # vless://uuid@server:port?params#name
            try:
                uuid_server_port, query_params_str = remainder.split("?", 1) if "?" in remainder else (remainder, "")
                uuid, server_port = uuid_server_port.split("@", 1)
                server, port = server_port.split(":", 1)

                proxy.update({
                    "type": "vless", # Clash.Meta 中的类型
                    "server": server,
                    "port": int(port),
                    "uuid": uuid,
                    "cipher": "auto" # Vless 通常是 none 或 auto
                })

                if query_params_str:
                    query_params = urllib.parse.parse_qs(query_params_str)
                    if "security" in query_params and query_params["security"][0] == "tls":
                        proxy["tls"] = True
                    if "sni" in query_params:
                        proxy["servername"] = query_params["sni"][0]
                    if "type" in query_params: # 传输协议类型 (tcp, ws, grpc)
                        proxy["network"] = query_params["type"][0]
                    if "path" in query_params:
                        proxy["ws-path"] = query_params["path"][0] # 如果 network 是 ws
                    if "host" in query_params: # WebSocket Host
                        proxy["ws-headers"] = {"Host": query_params["host"][0]}
                    # Vless 还有许多 XTLS, Reality 等参数，这里仅处理基本情况
            except Exception as e:
                print(f"❌ 错误：解析Vless链接失败：{link} - {e}")
                return None
        else:
            print(f"⚠️ 警告：跳过不支持的协议类型：{scheme} (链接: {link})")
            return None

        # 如果没有获取到有效名称，尝试从链接中提取一个
        if not proxy.get("name") and name_part:
             proxy["name"] = name_part
        elif not proxy.get("name"):
            proxy["name"] = f"{proxy.get('type', 'unknown').upper()}-{proxy.get('server', 'unknown')}:{proxy.get('port', 'unknown')}"

        return proxy

    except Exception as e:
        print(f"❌ 错误：解析未知链接格式失败：{link} - {e}")
        return None

# --- 修改后的 fetch_all_configs 函数 ---
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

                # 将内容按行分割，每行是一个节点链接
                lines = node_links_content.strip().split("\n")
                
                parsed_count = 0
                for line in lines:
                    line = line.strip()
                    if not line: # 跳过空行
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

# --- generate_plaintext_node_link 函数 (保持不变，因为它是从Clash字典生成链接) ---
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
            safe_name = urllib.parse.quote(p_name) # URL编码名称
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
                "port": str(port), # 端口通常是字符串
                "id": uuid,
                "aid": str(alterId),
                "scy": cipher,
                "net": network,
            }
            if ws_path: vmess_obj["path"] = ws_path
            if ws_headers: vmess_obj["host"] = ws_headers
            if tls: vmess_obj["tls"] = "tls"
            if servername: vmess_obj["sni"] = servername

            vmess_obj = {k: v for k, v in vmess_obj.items() if v} # 清理空值
            
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
            if network != "tcp": # Clash 默认是 tcp
                params.append(f"type={network}")
            
            param_str = "&".join(params)
            # 密码和名称也需要 URL 编码
            encoded_password = urllib.parse.quote(password)
            safe_name = urllib.parse.quote(p_name)
            
            link = f"trojan://{encoded_password}@{server}:{port}"
            if param_str:
                link += f"?{param_str}"
            link += f"#{safe_name}"
            return link
    elif p_type == "hysteria2":
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
        network = proxy.get("network", "tcp") # 传输协议 (tcp, ws, grpc)
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
            # Vless 协议还有加密方式（encryption），但通常是 none/auto，不需要显式在链接中
            # XTLS, Reality 等更高级的参数这里不处理

            param_str = "&".join(params)
            safe_name = urllib.parse.quote(p_name)

            link = f"vless://{uuid}@{server}:{port}"
            if param_str:
                link += f"?{param_str}"
            link += f"#{safe_name}"
            return link

    return None

async def main():
    print("🚀 开始从 URL 获取明文节点链接列表并处理...")
    all_proxies = []
    # fetch_all_configs 现在会返回 Clash 字典列表
    all_proxies = await fetch_all_configs(CLASH_BASE_CONFIG_URLS)

    print(f"\n✅ 总共从链接解析到 {len(all_proxies)} 个代理节点。")

    if not all_proxies:
        print("🤷 没有找到任何节点。")
        with open("data/all.txt", "w", encoding="utf-8") as f:
            f.write("")
        return

    # 过滤掉重复的节点
    unique_proxies_map = {}
    for proxy in all_proxies:
        # 使用节点的名称、类型、服务器和端口作为唯一标识符
        key = (
            proxy.get("name"),
            proxy.get("type"),
            proxy.get("server"),
            proxy.get("port")
        )
        # 有些节点可能没有名称，或者名称可能重复，
        # 更严格的去重可以使用节点的完整 Clash 字典表示的哈希
        if key not in unique_proxies_map:
             unique_proxies_map[key] = proxy
        else:
             print(f"  ➡️ 跳过重复节点: {proxy.get('name')} ({proxy.get('type')})")
    
    unique_proxies = list(unique_proxies_map.values())
    print(f"✨ 过滤重复后剩余 {len(unique_proxies)} 个唯一节点。")

    print("\n📝 正在生成明文节点链接和统一的 Clash 配置文件...")
    plaintext_links = []
    
    for node in unique_proxies:
        # generate_plaintext_node_link 现在是从内部 Clash 字典生成外部链接
        link = generate_plaintext_node_link(node)
        if link:
            plaintext_links.append(link)
        
    # 写入明文链接到 data/all.txt
    output_file_path = "data/all.txt"
    with open(output_file_path, "w", encoding="utf-8") as f:
        for link in plaintext_links:
            f.write(link + "\n")
    print(f"➡️ 所有明文节点链接已写入：{output_file_path}")
    print(f"总共生成 {len(plaintext_links)} 条明文链接。")

    # 生成一个统一的 Clash 配置，包含所有解析到的节点
    unified_clash_config = {
        "proxies": unique_proxies, # 直接使用解析后的 Clash 代理字典列表
        "proxy-groups": [
            {
                "name": "Proxy All",
                "type": "select",
                "proxies": [p.get("name") for p in unique_proxies if p.get("name")]
            }
        ],
        "rules": [
            "MATCH,Proxy All"
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
        "port": 7890,
        "mode": "rule"
    }

    unified_config_path = "data/unified_clash_config.yaml"
    try:
        with open(unified_config_path, "w", encoding="utf-8") as f:
            yaml.dump(unified_clash_config, f, allow_unicode=True, sort_keys=False)
        print(f"📦 统一的 Clash 配置文件已生成：{unified_config_path}")
    except Exception as e:
        print(f"❌ 错误：生成统一 Clash 配置文件失败：{e}")


if __name__ == "__main__":
    # 确保安装了 httpx 和 PyYAML
    asyncio.run(main())
