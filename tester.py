import httpx
import yaml
import asyncio
import base64
import json
import os
import urllib.parse
import subprocess # 用于启动Clash.Meta进程
import time # 用于等待Clash.Meta启动

# ... (CLASH_BASE_CONFIG_URLS, fetch_and_parse_clash_config, generate_plaintext_node_link 保持不变) ...

# --- 新增：使用 Clash.Meta API 进行节点测试的函数 ---
async def test_clash_meta_nodes(clash_core_path: str, config_path: str, api_port: int = 9090) -> list:
    """
    启动 Clash.Meta 核心，加载配置文件，并通过其 API 测试所有代理节点的延迟。
    返回一个包含测试结果（节点名和延迟）的列表。
    """
    clash_process = None
    tested_nodes_info = [] # 存储测试成功的节点信息 {name: ..., delay: ..., link: ...}

    try:
        print(f"\n🚀 正在启动 Clash.Meta 核心进行测试...")
        # 启动 Clash.Meta 进程，加载指定的配置文件
        # -f 指定配置文件路径，-d 指定工作目录（日志、缓存等）
        # 'data' 目录已在 GitHub Actions 中创建
        clash_process = subprocess.Popen(
            [clash_core_path, "-f", config_path, "-d", "./data", "-ext-ctl", f"0.0.0.0:{api_port}", "-ext-ui", "ui"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
            # 注意：在GitHub Actions中，stdout和stderr可以重定向到/dev/null以减少日志，
            # 但这里我们暂时保留，方便调试。
        )
        print(f"Clash.Meta 进程已启动，PID: {clash_process.pid}")

        # 等待 Clash.Meta 完全启动并监听 API 端口
        # 这个等待时间可能需要根据实际情况调整
        print(f"等待 Clash.Meta 启动并监听 {api_port} 端口...")
        await asyncio.sleep(5) # 给5秒钟让Clash.Meta启动

        api_url_base = f"http://127.0.0.1:{api_port}"
        proxies_api_url = f"{api_url_base}/proxies"

        async with httpx.AsyncClient() as client:
            # 1. 获取所有代理名称
            retries = 3
            proxy_names = []
            for attempt in range(retries):
                try:
                    response = await client.get(proxies_api_url, timeout=5)
                    response.raise_for_status()
                    all_proxies_data = response.json()
                    
                    # 提取所有可测试的代理名称
                    for proxy_name, details in all_proxies_data.get("proxies", {}).items():
                        if details.get("type") not in ["Fallback", "Selector", "URLTest", "LoadBalance"]:
                            proxy_names.append(proxy_name)
                    print(f"成功获取到 {len(proxy_names)} 个可测试代理的名称。")
                    break
                except (httpx.RequestError, json.JSONDecodeError) as e:
                    print(f"❌ 尝试 {attempt+1}/{retries} 访问 Clash API 失败: {e}")
                    await asyncio.sleep(2) # 等待后重试
            else:
                print("❌ 无法从 Clash.Meta API 获取代理列表，跳过测试。")
                return []
            
            if not proxy_names:
                print("🤷 没有找到任何可测试的代理节点。")
                return []

            # 2. 逐个测试代理延迟
            print("\n🔬 正在测试代理节点延迟...")
            tasks = []
            for name in proxy_names:
                # 触发延迟测试的API endpoint
                test_url = f"{proxies_api_url}/{urllib.parse.quote(name)}/delay?timeout=5000&url=http://www.google.com/generate_204"
                tasks.append(client.get(test_url, timeout=10)) # 每个测试请求10秒超时

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for i, result in enumerate(results):
                node_name = proxy_names[i]
                if isinstance(result, httpx.Response):
                    try:
                        delay_data = result.json()
                        delay = delay_data.get("delay", -1)
                        if delay > 0:
                            print(f"✅ {node_name}: {delay}ms")
                            tested_nodes_info.append({"name": node_name, "delay": delay})
                        else:
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
        if clash_process and clash_process.poll() is None: # 检查进程是否仍在运行
            print("🛑 正在停止 Clash.Meta 进程...")
            clash_process.terminate() # 尝试终止进程
            try:
                clash_process.wait(timeout=5) # 等待进程结束
            except subprocess.TimeoutExpired:
                clash_process.kill() # 如果没结束，强制杀死

    # 对测试成功的节点按延迟排序
    tested_nodes_info.sort(key=lambda x: x["delay"])
    return tested_nodes_info

# ... (main 函数的定义) ...
async def main():
    print("🚀 开始从 URL 获取明文节点链接列表并处理...")
    all_proxies = []
    all_proxies = await fetch_all_configs(CLASH_BASE_CONFIG_URLS)

    print(f"\n✅ 总共从链接解析到 {len(all_proxies)} 个代理节点。")

    if not all_proxies:
        print("🤷 没有找到任何节点，无法进行测试和生成链接。")
        # 即使没有节点，也创建一个空的 all.txt 防止后续步骤报错
        with open("data/all.txt", "w", encoding="utf-8") as f:
            f.write("")
        return

    # 过滤掉重复的节点
    unique_proxies_map = {}
    for proxy in all_proxies:
        key = (
            proxy.get("name"),
            proxy.get("type"),
            proxy.get("server"),
            proxy.get("port")
        )
        if key not in unique_proxies_map:
             unique_proxies_map[key] = proxy
        else:
             print(f"  ➡️ 跳过重复节点: {proxy.get('name')} ({proxy.get('type')})")
    
    unique_proxies = list(unique_proxies_map.values())
    print(f"✨ 过滤重复后剩余 {len(unique_proxies)} 个唯一节点。")

    # 生成统一的 Clash 配置
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

    # --- 实际执行节点测试 ---
    clash_core_path = os.environ.get("CLASH_CORE_PATH")
    if not clash_core_path:
        print("❌ 错误：环境变量 CLASH_CORE_PATH 未设置，无法执行 Clash.Meta 测试。")
        # 此时仍然尝试输出all.txt，但测试功能缺失
        output_file_path = "data/all.txt"
        with open(output_file_path, "w", encoding="utf-8") as f:
            for link in [generate_plaintext_node_link(node) for node in unique_proxies if generate_plaintext_node_link(node)]:
                f.write(link + "\n")
        print(f"➡️ 仅生成明文链接到：{output_file_path}")
        print(f"总共生成 {len(plaintext_links)} 条明文链接。")
        return # 提前退出

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
                    final_output_links.append(f"{link} # {node_info['delay']}ms")
                    print(f"{node_info['name']}: {node_info['delay']}ms -> {link}")
                else:
                    print(f"{node_info['name']}: {node_info['delay']}ms -> 无法生成明文链接")
            else:
                print(f"⚠️ 警告：找不到原始节点信息 '{node_info['name']}'")
    else:
        print("\n😔 没有节点通过延迟测试。")
        # 如果没有节点通过测试，仍然输出原始的明文链接（不带延迟信息）
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
