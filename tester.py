# -*- coding: utf-8 -*-

import asyncio
import httpx
import yaml
import os
import subprocess
import socket
import re
import json
import urllib.parse

# --- 配置区 ---
# 请将您的 Clash 节点源 URL 列表放在这里
CLASH_SOURCE_URLS = [
    "https://raw.githubusercontent.com/qjlxg/NoMoreWalls/refs/heads/master/snippets/nodes_JP.meta.yml",
    # 在这里可以添加更多的 URL
]

# Clash.Meta 核心可执行文件的路径
# 在 Windows 上可能是 "Clash.Meta-windows-amd64-compatible.exe"
# 在 Linux/macOS 上可能是 "./Clash.Meta-linux-amd64-compatible"
# 推荐使用环境变量进行配置，如果未设置，请在此处直接指定路径
CLASH_CORE_PATH = os.environ.get("CLASH_CORE_PATH", "clash-meta") # 修改为你的实际文件名

# Clash.Meta API 端口
API_PORT = 9090

# --- 核心逻辑 ---

def is_valid_reality_short_id(short_id) -> bool:
    """
    验证 REALITY 协议的 short-id 是否有效。
    一个有效的 short_id 是1到8个十六进制字符。
    这里为了兼容性，放宽到1-16位。
    """
    if not isinstance(short_id, str) or not short_id:
        return False
    return bool(re.match(r"^[0-9a-fA-F]{1,16}(,[0-9a-fA-F]{1,16})*$", short_id))

def validate_proxy(proxy: dict, index: int) -> bool:
    """
    验证单个代理节点配置的有效性，特别是针对 REALITY 协议。
    """
    if not all(k in proxy for k in ["name", "server", "port", "type"]):
        print(f"⚠️ 跳过无效节点 (索引 {index})：缺少 name, server, port 或 type 字段 - {proxy.get('name', '未知节点')}")
        return False

    # 重点检查 VLESS REALITY 节点的配置
    if proxy.get("type") == "vless" and "reality-opts" in proxy:
        reality_opts = proxy.get("reality-opts", {})
        if not isinstance(reality_opts, dict):
            print(f"⚠️ 跳过无效 REALITY 节点 (索引 {index})：'reality-opts' 不是一个有效的字典 - {proxy.get('name')}")
            return False

        public_key = reality_opts.get("public-key")
        if not public_key or not isinstance(public_key, str) or len(public_key) < 40:
             print(f"⚠️ 跳过无效 REALITY 节点 (索引 {index})：缺少或 public-key 无效 - {proxy.get('name')}")
             return False

        short_ids = reality_opts.get("short-id") # Clash.Meta 使用 short-id
        if not short_ids:
            short_ids = reality_opts.get("shortId") # 兼容旧格式

        if not is_valid_reality_short_id(short_ids):
            print(f"❌ 过滤掉致命错误的 REALITY 节点 (索引 {index})：无效的 short-id: '{short_ids}' - {proxy.get('name')}")
            return False # 这是导致您问题的关键检查

    return True

async def fetch_and_parse_proxies(urls: list[str]) -> list:
    """
    从 URL 列表异步获取并解析 Clash 代理节点。
    """
    all_proxies = []
    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        tasks = [client.get(url) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for i, res in enumerate(results):
            url = urls[i]
            if isinstance(res, httpx.Response):
                try:
                    res.raise_for_status()
                    yaml_content = yaml.safe_load(res.text)
                    proxies = yaml_content.get("proxies", [])
                    if not proxies:
                        print(f"⚠️ 警告：在 {url} 中没有找到 'proxies' 列表。")
                        continue

                    valid_proxies_count = 0
                    for index, proxy in enumerate(proxies):
                        if validate_proxy(proxy, index):
                            all_proxies.append(proxy)
                            valid_proxies_count += 1

                    print(f"✅ 成功从 {url} 解析并验证了 {valid_proxies_count} / {len(proxies)} 个代理节点。")

                except httpx.HTTPStatusError as e:
                    print(f"❌ HTTP 错误：从 {url} 获取配置失败，状态码：{e.response.status_code}")
                except yaml.YAMLError as e:
                    print(f"❌ YAML 解析错误：文件 {url} 格式不正确 - {e}")
                except Exception as e:
                    print(f"❌ 处理 {url} 时发生未知错误: {e}")
            else:
                print(f"❌ 网络请求错误：无法访问 {url} - {res}")
    return all_proxies

async def test_clash_meta_latency(clash_path: str, config_path: str, api_port: int, retries: int = 3) -> list:
    """
    启动 Clash.Meta 核心，通过 API 测试所有节点的延迟。
    """
    # 确保端口未被占用
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if s.connect_ex(('127.0.0.1', api_port)) == 0:
            print(f"❌ 错误：端口 {api_port} 已被占用。请关闭占用该端口的程序或在脚本中更换 API_PORT。")
            return []

    for attempt in range(retries):
        print(f"\n🚀 尝试启动 Clash.Meta 核心 (第 {attempt + 1}/{retries})...")
        process = None
        try:
            # 启动 Clash.Meta 子进程
            process = await asyncio.create_subprocess_exec(
                clash_path,
                "-d", ".",   # -d 指定配置目录
                "-f", config_path, # -f 指定主配置文件
                "--ext-ctl", f"127.0.0.1:{api_port}", # 外部控制器地址
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            print(f"✅ Clash.Meta 进程已启动，PID: {process.pid}")

            # 等待 API 准备就绪
            api_base_url = f"http://127.0.0.1:{api_port}"
            proxies_url = f"{api_base_url}/proxies"
            max_wait = 75
            interval = 2
            connected = False
            for _ in range(max_wait // interval):
                if process.returncode is not None:
                    print(f"⚠️ Clash.Meta 进程已提前退出，退出码: {process.returncode}")
                    break
                try:
                    async with httpx.AsyncClient() as client:
                        await client.get(api_base_url, timeout=interval)
                    print(f"✅ 成功连接到 Clash.Meta API。")
                    connected = True
                    break
                except httpx.RequestError:
                    print(f"⏳ 等待 Clash.Meta API 响应...")
                    await asyncio.sleep(interval)

            if not connected:
                print(f"❌ 在 {max_wait} 秒内未能连接到 Clash.Meta API。")
                # 读取并打印标准输出和错误流以帮助诊断
                stdout, stderr = await process.communicate()
                print("--- Clash.Meta STDOUT ---")
                print(stdout.decode('utf-8', errors='ignore'))
                print("--- Clash.Meta STDERR ---")
                print(stderr.decode('utf-8', errors='ignore'))
                continue

            # 获取所有可测试的代理名称
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.get(proxies_url)
                proxies_data = resp.json()['proxies']
                testable_proxies = [
                    name for name, details in proxies_data.items()
                    if details['type'] not in ["Selector", "URLTest", "Direct", "Reject", "Fallback"]
                ]
                print(f"🔬 发现 {len(testable_proxies)} 个可测试的代理节点，开始延迟测试...")

                # 并发测试延迟
                tasks = []
                for name in testable_proxies:
                    test_url = f"{proxies_url}/{urllib.parse.quote(name)}/delay?timeout=5000&url=http://www.google.com/generate_204"
                    tasks.append(client.get(test_url))

                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                tested_nodes = []
                for i, res in enumerate(results):
                    name = testable_proxies[i]
                    if isinstance(res, httpx.Response) and res.status_code == 200:
                        try:
                            delay_info = res.json()
                            delay = delay_info.get("delay", -1)
                            if delay > 0:
                                print(f"  - ✅ {name}: {delay}ms")
                                tested_nodes.append({"name": name, "delay": delay})
                            else:
                                print(f"  - ❌ {name}: 超时或测试失败")
                        except json.JSONDecodeError:
                            print(f"  - ❌ {name}: 响应解析失败")
                    else:
                        print(f"  - ❌ {name}: 请求错误 ({res})")

                tested_nodes.sort(key=lambda x: x["delay"])
                return tested_nodes

        except FileNotFoundError:
            print(f"❌ 致命错误：找不到 Clash.Meta 核心文件 '{clash_path}'。请确保 CLASH_CORE_PATH 设置正确且文件存在。")
            return []
        except Exception as e:
            print(f"❌ 在测试过程中发生意外错误: {e}")
        finally:
            if process and process.returncode is None:
                print("🛑 正在停止 Clash.Meta 进程...")
                process.terminate()
                await process.wait()

    print(f"❌ 经过 {retries} 次尝试后，Clash.Meta 测试失败。")
    return []

def generate_final_config(proxies: list, output_path: str):
    """
    生成最终的 Clash 配置文件。
    """
    # 简单的去重逻辑
    unique_proxies_map = {}
    for proxy in proxies:
        # 使用服务器、端口和类型作为唯一标识符
        key = (proxy.get("server"), proxy.get("port"), proxy.get("type"))
        if key not in unique_proxies_map:
            unique_proxies_map[key] = proxy
    
    unique_proxies = list(unique_proxies_map.values())
    print(f"🔍 过滤重复节点后，剩余 {len(unique_proxies)} 个唯一节点。")

    proxy_names = [p["name"] for p in unique_proxies]
    
    # 基础配置模板
    config_template = {
        "port": 7890,
        "socks-port": 7891,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "external-controller": f"127.0.0.1:{API_PORT}",
        "dns": {
            "enable": True,
            "listen": "0.0.0.0:53",
            "enhanced-mode": "fake-ip",
            "nameserver": ["8.8.8.8", "1.1.1.1"],
        },
        "proxies": unique_proxies,
        "proxy-groups": [
            {
                "name": "PROXY",
                "type": "select",
                "proxies": ["自动选择", "手动选择"] + proxy_names
            },
            {
                "name": "手动选择",
                "type": "select",
                "proxies": proxy_names
            },
            {
                "name": "自动选择",
                "type": "url-test",
                "proxies": proxy_names,
                "url": "http://www.google.com/generate_204",
                "interval": 300
            }
        ],
        "rules": [
            "MATCH,PROXY"
        ]
    }
    
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            yaml.dump(config_template, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
        print(f"✅ 最终的 YAML 配置文件已成功写入：{output_path}")
        print(f"📄 总共输出 {len(unique_proxies)} 个代理节点。")
    except Exception as e:
        print(f"❌ 错误：写入最终配置文件失败：{e}")


async def main():
    """
    主执行函数
    """
    # 确保工作目录存在
    os.makedirs("data", exist_ok=True)
    output_config_path = "data/unified_clash_config.yaml"

    print("--- 第 1 步：获取和解析代理节点 ---")
    all_proxies = await fetch_and_parse_proxies(CLASH_SOURCE_URLS)
    
    if not all_proxies:
        print("🤷 没有获取到任何有效的代理节点，程序退出。")
        return

    print(f"\n--- 第 2 步：生成统一配置文件 ---")
    generate_final_config(all_proxies, output_config_path)

    print("\n--- 第 3 步：使用 Clash.Meta 测试节点延迟 ---")
    if not os.path.isfile(CLASH_CORE_PATH):
        print(f"⚠️ 警告：找不到 Clash Core '{CLASH_CORE_PATH}'，跳过延迟测试。")
        print("➡️ 您可以手动使用 Clash 客户端加载生成的配置文件: " + output_config_path)
        return

    tested_nodes = await test_clash_meta_latency(CLASH_CORE_PATH, output_config_path, API_PORT)

    if tested_nodes:
        print("\n--- ✅ 延迟测试完成 ---")
        print("延迟最低的节点如下 (ms):")
        for node in tested_nodes[:20]: # 最多显示前20个
            print(f"  - {node['delay']}ms: {node['name']}")
    else:
        print("\n--- 😔 没有节点通过延迟测试 ---")
        print("这可能是由于：")
        print("1. 所有节点均已失效或超时。")
        print("2. 您的网络环境无法访问测试网址 (http://www.google.com/generate_204)。")
        print("3. Clash.Meta 核心启动失败，请检查上面的日志输出。")

if __name__ == "__main__":
    asyncio.run(main())
