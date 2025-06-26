import httpx
import yaml
import asyncio
import base64
import json
import os
import urllib.parse
import subprocess
import time

# ... (CLASH_BASE_CONFIG_URLS, parse_node_link_to_clash_proxy, fetch_all_configs, generate_plaintext_node_link 保持不变) ...

# --- test_clash_meta_nodes 函数 (重点修改这里) ---
async def test_clash_meta_nodes(clash_core_path: str, config_path: str, api_port: int = 9090) -> list:
    """
    启动 Clash.Meta 核心，加载配置文件，并通过其 API 测试所有代理节点的延迟。
    返回一个包含测试结果（节点名和延迟）的列表。
    """
    clash_process = None
    tested_nodes_info = []
    
    # 定义一个异步函数来读取并打印Clash进程的输出
    async def read_clash_output(stream, name):
        # 使用 asyncio.StreamReader 的 readuntil 替代 readline
        # 因为 readline 在没有换行符时可能会阻塞。
        # 这里我们假设日志行通常以换行符结束。
        # readuntil 是为了处理可能不完整的行。
        while True:
            try:
                # read(4096) 是为了避免无限阻塞，每次读取一块数据
                # 然后通过 decode() 尝试将其转换为字符串并打印
                data = await asyncio.wait_for(stream.read(4096), timeout=0.1) # 短暂超时，避免长时间阻塞
                if not data:
                    break
                print(f"[{name}] {data.decode('utf-8', errors='ignore').strip()}")
            except asyncio.TimeoutError:
                # 即使超时也继续循环，直到进程结束
                pass
            except Exception as e:
                print(f"Error reading {name}: {e}")
                break

    try:
        print(f"\n🚀 正在启动 Clash.Meta 核心进行测试...")
        # 启动 Clash.Meta 进程，同时捕获其标准输出和标准错误
        clash_process = subprocess.Popen(
            [clash_core_path, "-f", config_path, "-d", "./data", "-ext-ctl", f"0.0.0.0:{api_port}", "-ext-ui", "ui"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        print(f"Clash.Meta 进程已启动，PID: {clash_process.pid}")

        # 创建异步任务来实时读取Clash的输出
        stdout_task = asyncio.create_task(read_clash_output(asyncio.StreamReader(clash_process.stdout), "Clash_STDOUT"))
        stderr_task = asyncio.create_task(read_clash_output(asyncio.StreamReader(clash_process.stderr), "Clash_STDERR"))

        # --- 优化等待逻辑 ---
        api_url_base = f"http://127.0.0.1:{api_port}"
        proxies_api_url = f"{api_url_base}/proxies"
        max_wait_time = 45 # 增加最大等待秒数到 45 秒
        wait_interval = 1 # 每次检查间隔秒数
        
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
                    if clash_process.poll() is not None:
                        print(f"⚠️ Clash.Meta 进程已提前退出，无法连接API。")
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
                if details.get("type") not in ["Fallback", "Selector", "URLTest", "LoadBalance"]:
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
        # 在 finally 块中确保停止 Clash.Meta 进程并等待其输出任务完成
        if clash_process and clash_process.poll() is None:
            print("🛑 正在停止 Clash.Meta 进程...")
            clash_process.terminate()
            try:
                clash_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                clash_process.kill()
        
        # 等待输出读取任务完成，避免IO阻塞
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

# ... (main 函数保持不变) ...

if __name__ == "__main__":
    asyncio.run(main())
