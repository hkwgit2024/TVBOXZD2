import os
import requests # 尽管不再测试HTTP，但保留requests以防将来扩展
from requests.exceptions import RequestException
import time
import base64
import urllib.parse
import socket
import ssl # 仅为潜在的未来安全连接保留

# 尝试导入 shadowsocks 库
try:
    from shadowsocks import ssr
    print("Shadowsocks (SSR) library imported successfully.")
except ImportError:
    print("Warning: 'shadowsocks' library not found. Shadowsocks (SS/SSR) nodes will be skipped.")
    print("Please install it using: pip install shadowsocks")
    ssr = None # 如果导入失败，则将其设置为None


def parse_ss_url(ss_url):
    """
    解析 Shadowsocks (SS) URL。
    格式通常为 ss://base64(method:password@server:port)
    或 ss://base64(method:password@server:port#tag)
    """
    try:
        # 移除 ss:// 前缀
        encoded_part = ss_url.replace("ss://", "")
        # 分离出 #tag 部分 (如果有)
        parts = encoded_part.split("#", 1)
        encoded_config = parts[0]
        tag = urllib.parse.unquote(parts[1]) if len(parts) > 1 else None

        # Base64 解码
        # 注意：Base64解码可能需要填充，或者可能遇到非标准Base64
        # 这里尝试进行URL安全解码，并处理可能的填充
        missing_padding = len(encoded_config) % 4
        if missing_padding:
            encoded_config += '='* (4 - missing_padding)

        decoded_config = base64.urlsafe_b64decode(encoded_config).decode('utf-8')

        # 解析 method:password@server:port
        at_split = decoded_config.split("@", 1)
        if len(at_split) < 2:
            raise ValueError("Invalid SS format: missing '@'")

        method_password_part = at_split[0]
        server_port_part = at_split[1]

        method, password = method_password_part.split(":", 1)
        server, port_str = server_port_part.split(":", 1)
        port = int(port_str)

        return {
            "method": method,
            "password": password,
            "server": server,
            "port": port,
            "tag": tag,
            "original_url": ss_url # 保存原始URL
        }
    except Exception as e:
        print(f"❌ 解析SS URL失败 ({e}): {ss_url}")
        return None

def test_shadowsocks_node(ss_config, timeout=5):
    """
    测试Shadowsocks节点连通性。
    需要 'shadowsocks' 库。
    此功能仅为示例，实际的SSR库可能需要更复杂的配置和运行方式。
    """
    if not ssr:
        print(f"❌ Shadowsocks库未安装，无法测试SS节点: {ss_config.get('original_url', 'N/A')}")
        return False

    server = ss_config.get("server")
    port = ss_config.get("port")

    if not server or not port:
        print(f"❌ SS配置信息不完整: {ss_config.get('original_url', 'N/A')}")
        return False

    try:
        # 尝试进行TCP连接到SS服务器，检查端口是否开放
        sock = socket.create_connection((server, port), timeout=timeout)
        sock.close()
        print(f"✅ SS节点TCP连通 (端口开放): {ss_config['original_url']}")
        # 实际测试SS的可用性需要更复杂的逻辑，例如通过它去访问一个外部网站。
        # 鉴于GitHub Actions环境的复杂性，这里只做初步的端口连通性检查。
        return True
    except socket.timeout:
        print(f"❌ SS节点连接超时: {ss_config['original_url']}")
        return False
    except socket.error as e:
        print(f"❌ SS节点连接错误 ({e}): {ss_config['original_url']}")
        return False
    except Exception as e:
        print(f"❌ 测试SS节点时发生未知错误 ({e}): {ss_config['original_url']}")
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

        if node.startswith("ss://"):
            ss_config = parse_ss_url(node)
            if ss_config and test_shadowsocks_node(ss_config):
                connectable_nodes.append(node)
        else:
            print(f"⚠️ 跳过未知协议或格式的节点 (仅支持SS协议): {node}")

        time.sleep(0.5) # 稍微暂停，避免请求过于频繁

    try:
        output_dir = os.path.dirname(output_file_path)
        if output_dir and not os.path.exists(output_dir):
            os.makedirs(output_dir)

        with open(output_file_path, 'w', encoding='utf-8') as outfile:
            for node in sorted(connectable_nodes): # 再次排序，确保输出文件内容一致
                outfile.write(node + '\n')
        print(f"\n成功测试并保存连通SS节点到 {output_file_path}，共 {len(connectable_nodes)} 个连通节点。")
    except Exception as e:
        print(f"写入文件时发生错误 {output_file_path}: {e}")

if __name__ == "__main__":
    # 脚本的当前工作目录就是仓库根目录，可以直接从此处引用 'data/'
    input_file = os.path.join('data', 'sub.txt')
    output_file = os.path.join('data', 'enhanced_nodes.txt')

    process_nodes_with_test(input_file, output_file)
