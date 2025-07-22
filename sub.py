```python
import os
import yaml
import time
import subprocess
import concurrent.futures
from urllib.parse import urlparse
import logging
from typing import List, Dict, Optional

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

DEBUG = True
TIMEOUT = 15
TEST_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://httpbin.org/get",
    "https://www.cloudflare.com/cdn-cgi/trace"
]
FAILED_NODES_FILE = 'failed_nodes.txt'

def log(message):
    if DEBUG:
        logger.info(message)

def load_failed_nodes() -> set:
    """加载失败的节点"""
    try:
        if os.path.exists(FAILED_NODES_FILE):
            with open(FAILED_NODES_FILE, 'r', encoding='utf-8') as f:
                return {line.strip().split(',', 1)[1] for line in f if ',' in line}
        return set()
    except Exception as e:
        logger.error(f"加载失败节点错误: {e}")
        return set()

def save_failed_nodes(failed_nodes: List[Dict]):
    """保存失败的节点"""
    try:
        with open(FAILED_NODES_FILE, 'w', encoding='utf-8') as f:
            for node in failed_nodes:
                f.write(f"{node['name']},{node['server']}:{node['port']}\n")
        logger.info(f"保存 {len(failed_nodes)} 个失败节点到 {FAILED_NODES_FILE}")
    except Exception as e:
        logger.error(f"保存失败节点错误: {e}")

def test_ss(node, retries: int = 2) -> Optional[float]:
    """测试Shadowsocks节点"""
    for attempt in range(retries):
        for url in TEST_URLS:
            try:
                start_time = time.time()
                cmd = [
                    'curl', '-sS',
                    '--connect-timeout', '10',
                    '--max-time', str(TIMEOUT),
                    '--socks5-hostname', f"{node['server']}:{node['port']}",
                    '--proxy-user', f"{node['cipher']}:{node['password']}",
                    '-o', '/dev/null',
                    '-w', '%{http_code} %{time_total}',
                    url
                ]
                result = subprocess.run(
                    cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=TIMEOUT
                )
                
                if result.returncode == 0 and '200' in result.stdout or '204' in result.stdout:
                    latency = float(result.stdout.split()[1]) * 1000
                    return latency
                log(f"SS测试失败 {node['name']} ({url}): {result.stderr[:100]}")
            except Exception as e:
                log(f"SS异常 {node['name']} ({url}): {str(e)}")
        time.sleep(1)  # 重试前等待
    return None

def test_tcp(node, retries: int = 2) -> Optional[float]:
    """通用TCP端口测试"""
    for attempt in range(retries):
        try:
            start_time = time.time()
            cmd = [
                'nc', '-zv', '-w', '10',
                node['server'], str(node['port'])
            ]
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=TIMEOUT
            )
            
            if result.returncode == 0:
                return (time.time() - start_time) * 1000
            log(f"TCP测试失败 {node['name']}: {result.stderr[:100]}")
        except Exception as e:
            log(f"TCP异常 {node['name']}: {str(e)}")
        time.sleep(1)
    return None

def test_node(node: Dict) -> Optional[Dict]:
    """节点测试分发"""
    protocol_testers = {
        'ss': test_ss,
        'vmess': test_tcp,
        'trojan': test_tcp,
        'http': test_tcp
    }
    
    if node['type'] not in protocol_testers:
        log(f"⚠️ 跳过不支持协议: {node['type']}")
        return None
        
    if not all(k in node for k in ['server', 'port', 'name']):
        log(f"⚠️ 节点字段缺失: {node.get('name')}")
        return None
        
    try:
        latency = protocol_testers[node['type']](node)
        if latency:
            log(f"✅ {node['name']} 有效 ({latency:.2f}ms)")
            return {'node': node, 'latency': latency}
        return None
    except Exception as e:
        log(f"全局异常: {str(e)}")
        return None

def main():
    start_time = time.time()
    failed_nodes = []
    failed_urls = load_failed_nodes()
    
    # 加载节点源
    sources = [
        "https://cdn.jsdelivr.net/gh/mfbpn/tg_mfbpn_subs@refs/heads/main/trials/2.flybar20.cc.yaml"
    ]
    
    all_nodes = []
    for url in sources:
        try:
            result = subprocess.run(
                ['curl', '-sSL', url],
                stdout=subprocess.PIPE,
                check=True
            )
            data = yaml.safe_load(result.stdout)
            valid_nodes = [n for n in data.get('proxies', []) if 'type' in n]
            all_nodes.extend(valid_nodes)
            log(f"📥 加载 {len(valid_nodes)} 节点 from {url}")
        except Exception as e:
            log(f"❌ 加载失败 {url}: {str(e)}")

    # 节点去重
    seen = set()
    unique_nodes = []
    for node in all_nodes:
        key = f"{node['type']}_{node['server']}_{node['port']}_{node.get('cipher', '')}_{node.get('password', '')}"
        if key not in seen and f"{node['server']}:{node['port']}" not in failed_urls:
            seen.add(key)
            unique_nodes.append(node)
    log(f"🔍 去重后节点数: {len(unique_nodes)}")

    # 并发测试
    valid_results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(test_node, n): n for n in unique_nodes}
        
        for future in concurrent.futures.as_completed(futures):
            node = futures[future]
            try:
                result = future.result()
                if result:
                    valid_results.append(result)
                else:
                    failed_nodes.append(node)
            except Exception as e:
                log(f"⚠️ 并发错误: {str(e)}")
                failed_nodes.append(node)

    # 保存失败节点
    save_failed_nodes(failed_nodes)

    # 生成结果文件
    if valid_results:
        sorted_nodes = sorted(valid_results, key=lambda x: x['latency'])[:50]
        
        with open('nodes.yml', 'w', encoding='utf-8') as f:
            yaml.safe_dump(
                {'proxies': [n['node'] for n in sorted_nodes]},
                f,
                default_flow_style=False,
                allow_unicode=True
            )
            
        with open('speed.txt', 'w', encoding='utf-8') as f:
            f.write("排名 | 节点名称 | 类型 | 服务器 | 延迟(ms)\n")
            f.write("-"*60 + "\n")
            for idx, item in enumerate(sorted_nodes, 1):
                node = item['node']
                f.write(f"{idx:2d}. {node['name']} | {node['type']} | {node['server']}:{node['port']} | {item['latency']:.2f}\n")
        
        log(f"🎉 生成 {len(sorted_nodes)} 个有效节点")
    else:
        log("❌ 未找到有效节点")
    
    log(f"总用时: {time.time() - start_time:.2f}秒")

if __name__ == '__main__':
    main()
```

### **优化后的改进**
1. **多目标测试**：为 SS 测试添加多个测试 URL，增加结果可靠性。
2. **重试机制**：每个节点最多重试 2 次，减少因网络波动导致的误判。
3. **失败节点缓存**：将失败节点保存到 `failed_nodes.txt`，下次运行时跳过。
4. **改进去重**：考虑 `cipher` 和 `password` 字段，避免遗漏不同配置的节点。
5. **增强输出**：在 `speed.txt` 中添加协议类型和服务器地址，便于分析。
6. **日志优化**：使用 `logging` 模块，提供更详细的错误信息。

### **如何验证改进后的可靠性**
1. **运行多次**：在不同时间运行脚本，比较结果的一致性。
2. **测试多种网络环境**：在不同网络（如家庭网络、移动数据）下运行，验证结果稳定性。
3. **手动验证**：使用代理客户端（如 Clash、V2Ray）测试输出节点，确认是否真正可用。
4. **检查失败节点**：查看 `failed_nodes.txt
