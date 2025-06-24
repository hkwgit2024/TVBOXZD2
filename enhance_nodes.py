import os
import requests
from requests.exceptions import RequestException
import time

def test_proxy(proxy_url, timeout=5):
    """
    测试代理节点连通性。
    此示例仅适用于HTTP/HTTPS代理。
    对于V2Ray, Trojan等协议，需要专门的客户端或库来测试。
    """
    proxies = {
        "http": proxy_url,
        "https": proxy_url,
    }
    test_url = "http://www.google.com" # 尝试连接一个公共网站
    try:
        # 使用stream=True和close()来避免资源泄露
        with requests.get(test_url, proxies=proxies, timeout=timeout, stream=True) as response:
            if response.status_code == 200:
                print(f"✅ 节点连通: {proxy_url}")
                return True
            else:
                print(f"❌ 节点不连通 (Status {response.status_code}): {proxy_url}")
                return False
    except RequestException as e:
        print(f"❌ 节点连通失败 ({e}): {proxy_url}")
        return False
    except Exception as e:
        print(f"❌ 测试节点时发生未知错误 ({e}): {proxy_url}")
        return False

def process_nodes_with_test(input_file_path, output_file_path):
    """
    读取节点文件，去重并测试连通性后保存到新的文件。
    """
    if not os.path.exists(input_file_path):
        print(f"错误：输入文件不存在 - {input_file_path}")
        return

    unique_nodes = set()
    try:
        with open(input_file_path, 'r', encoding='utf-8') as infile:
            for line in infile:
                node = line.strip()
                if node:
                    unique_nodes.add(node)
    except Exception as e:
        print(f"读取文件时发生错误 {input_file_path}: {e}")
        return

    connectable_nodes = []
    print(f"开始测试 {len(unique_nodes)} 个唯一节点...")

    # 对节点进行排序，以便测试顺序一致
    sorted_unique_nodes = sorted(list(unique_nodes))

    for i, node in enumerate(sorted_unique_nodes):
        print(f"[{i+1}/{len(sorted_unique_nodes)}] 正在测试: {node}...")
        # 假设 sub.txt 中的节点是像 "http://host:port" 或 "socks5://host:port" 这样的格式
        # 对于V2Ray/Trojan等订阅链接，需要先解析出具体的节点信息才能测试
        if node.startswith("http://") or node.startswith("https://") or node.startswith("socks5://"):
            if test_proxy(node):
                connectable_nodes.append(node)
        else:
            print(f"⚠️ 跳过未知协议或格式的节点 (非HTTP/HTTPS/SOCKS5): {node}")

        time.sleep(0.5) # 稍微暂停，避免请求过于频繁

    try:
        output_dir = os.path.dirname(output_file_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        with open(output_file_path, 'w', encoding='utf-8') as outfile:
            for node in sorted(connectable_nodes): # 再次排序，确保输出文件内容一致
                outfile.write(node + '\n')
        print(f"\n成功测试并保存连通节点到 {output_file_path}，共 {len(connectable_nodes)} 个连通节点。")
    except Exception as e:
        print(f"写入文件时发生错误 {output_file_path}: {e}")

if __name__ == "__main__":
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.abspath(os.path.join(script_dir, os.pardir))

    input_file = os.path.join(project_root, 'data', 'sub.txt')
    output_file = os.path.join(project_root, 'data', 'enhanced_nodes.txt')

    process_nodes_with_test(input_file, output_file)
