import httpx
import yaml
import asyncio
import base64
import json
import os

# 将你的来源链接设置为默认值
CLASH_BASE_CONFIG_URLS = [
    "https://snippet.host/oouyda/raw"
]

async def fetch_and_parse_clash_config(url: str) -> list:
    """
    从单个 URL 获取 Clash 配置并解析出代理节点。
    """
    proxies = []
    async with httpx.AsyncClient() as client:
        try:
            print(f"🔄 正在从 {url} 获取配置...")
            response = await client.get(url, timeout=20)
            response.raise_for_status() # 如果状态码是 4xx/5xx，则抛出异常
            config_content = response.text

            try:
                config = yaml.safe_load(config_content)
                if not isinstance(config, dict):
                    print(f"❌ 错误：来自 {url} 的配置不是有效的 YAML 字典格式。")
                    return proxies

                if "proxies" in config and isinstance(config["proxies"], list):
                    proxies.extend(config["proxies"])
                    print(f"✅ 成功从 {url} 解析到 {len(config['proxies'])} 个代理节点。")
                else:
                    print(f"⚠️ 警告：来自 {url} 的配置中 'proxies' 键缺失或不是列表。")
            except yaml.YAMLError as e:
                print(f"❌ 错误：无法解析来自 {url} 的 YAML 配置：{e}")
            except Exception as e:
                print(f"❌ 发生未知错误，解析 {url} 时出现：{e}")

        except httpx.RequestError as e:
            print(f"❌ 错误：从 {url} 获取配置失败：{e}")
        except Exception as e:
            print(f"❌ 发生未知错误，处理 {url} 时出现：{e}")
    return proxies

def generate_plaintext_node_link(proxy: dict) -> str | None:
    """
    根据代理类型生成明文节点链接（例如 ss://, vmess://）。
    这是一个简化示例，实际情况可能需要更复杂的逻辑来处理所有类型和字段。
    """
    p_type = proxy.get("type")
    p_name = proxy.get("name", "Unnamed Node") # 使用节点名称

    if p_type == "ss":
        server = proxy.get("server")
        port = proxy.get("port")
        password = proxy.get("password")
        cipher = proxy.get("cipher")
        if all([server, port, password, cipher]):
            userinfo = f"{cipher}:{password}@{server}:{port}"
            encoded_userinfo = base64.b64encode(userinfo.encode()).decode()
            safe_name = p_name.replace("#", "").replace("&", "").strip()
            return f"ss://{encoded_userinfo}#{safe_name}"
    elif p_type == "vmess":
        server = proxy.get("server")
        port = proxy.get("port")
        uuid = proxy.get("uuid")
        alterId = proxy.get("alterId", 0)
        security = proxy.get("security", "auto")
        network = proxy.get("network", "tcp")
        tls = proxy.get("tls", False)
        sni = proxy.get("servername", "")

        if all([server, port, uuid]):
            vmess_obj = {
                "v": "2",
                "ps": p_name, # 备注
                "add": server, # 地址
                "port": port, # 端口
                "id": uuid, # 用户 ID
                "aid": alterId, # 额外 ID
                "scy": security, # 加密方式
                "net": network, # 传输协议
                "type": "none", # 伪装类型（http, srpc, wechat-video 等，Clash里可能不直接写）
                "host": proxy.get("ws-headers", {}).get("Host", ""), # HTTP/WS Host
                "path": proxy.get("ws-path", ""), # WS Path
                "tls": "tls" if tls else "", # TLS
                "sni": sni, # SNI
            }
            vmess_obj = {k: v for k, v in vmess_obj.items() if v} # 清理空值

            try:
                vmess_json = json.dumps(vmess_obj, ensure_ascii=False)
                encoded_vmess = base64.b64encode(vmess_json.encode('utf-8')).decode('utf-8')
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

        if all([server, port, password]):
            params = []
            if tls:
                params.append("security=tls")
            if sni:
                params.append(f"sni={sni}")
            
            param_str = "&".join(params)
            link = f"trojan://{password}@{server}:{port}"
            if param_str:
                link += f"?{param_str}"
            link += f"#{p_name}"
            return link
            
    return None

async def main():
    print("🚀 开始从 URL 获取 Clash 配置并生成明文链接...")
    all_proxies = []
    for url in CLASH_BASE_CONFIG_URLS:
        proxies_from_url = await fetch_and_parse_clash_config(url)
        all_proxies.extend(proxies_from_url)

    print(f"\n✅ 总共获取到 {len(all_proxies)} 个代理节点。")

    if not all_proxies:
        print("🤷 没有找到任何节点。")
        # 即使没有节点，也创建一个空的 all.txt 防止后续步骤报错
        with open("data/all.txt", "w", encoding="utf-8") as f:
            f.write("")
        return

    # 过滤掉重复的节点
    unique_proxies_map = {}
    for proxy in all_proxies:
        key = (proxy.get("name"), proxy.get("type"), proxy.get("server"), proxy.get("port"))
        unique_proxies_map[key] = proxy
    
    unique_proxies = list(unique_proxies_map.values())
    print(f"✨ 过滤重复后剩余 {len(unique_proxies)} 个唯一节点。")

    print("\n📝 正在生成明文节点链接和 Clash 配置文件...")
    plaintext_links = []
    unified_clash_config_proxies = [] 

    for node in unique_proxies:
        link = generate_plaintext_node_link(node)
        if link:
            plaintext_links.append(link)
        
        unified_clash_config_proxies.append(node)

    # 写入明文链接到 data/all.txt
    output_file_path = "data/all.txt"
    with open(output_file_path, "w", encoding="utf-8") as f:
        for link in plaintext_links:
            f.write(link + "\n")
    print(f"➡️ 所有明文节点链接已写入：{output_file_path}")
    print(f"总共生成 {len(plaintext_links)} 条明文链接。")

    # 生成一个统一的 Clash 配置
    unified_clash_config = {
        "proxies": unified_clash_config_proxies,
        "proxy-groups": [
            {
                "name": "Proxy All",
                "type": "select",
                "proxies": [p.get("name") for p in unified_clash_config_proxies if p.get("name")]
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
    asyncio.run(main())
