import requests
import base64
import yaml
import re
import os

def decode_base64(data):
    """尝试解码Base64字符串，处理URL安全Base64和普通Base64。"""
    try:
        # 尝试URL安全Base64解码
        decoded_bytes = base64.urlsafe_b64decode(data + '==')
        return decoded_bytes.decode('utf-8', errors='ignore')
    except:
        try:
            # 尝试普通Base64解码
            decoded_bytes = base64.b64decode(data + '==')
            return decoded_bytes.decode('utf-8', errors='ignore')
        except Exception as e:
            print(f"Base64 decoding failed: {e}")
            return None

def extract_nodes(content):
    """从不同格式的内容中提取节点信息。"""
    nodes = set()

    # 尝试YAML解析（适用于Clash配置）
    try:
        yaml_content = yaml.safe_load(content)
        if isinstance(yaml_content, dict) and 'proxies' in yaml_content:
            for proxy in yaml_content['proxies']:
                # 提取常见的代理类型和必要信息
                # 这里可以根据需要添加更多代理类型的解析逻辑
                if 'name' in proxy and 'type' in proxy:
                    nodes.add(str(proxy)) # 将整个代理字典转换为字符串以便去重
                elif 'server' in proxy and 'port' in proxy:
                     nodes.add(str(proxy))
        return nodes
    except yaml.YAMLError:
        pass # 不是YAML格式，继续尝试其他解析

    # 尝试Base64解码后的内容
    decoded_content = decode_base64(content)
    if decoded_content:
        # 再次尝试YAML解析 decoded_content
        try:
            yaml_content = yaml.safe_load(decoded_content)
            if isinstance(yaml_content, dict) and 'proxies' in yaml_content:
                for proxy in yaml_content['proxies']:
                    if 'name' in proxy and 'type' in proxy:
                        nodes.add(str(proxy))
                    elif 'server' in proxy and 'port' in proxy:
                        nodes.add(str(proxy))
            return nodes
        except yaml.YAMLError:
            pass # 不是YAML格式，继续尝试其他解析

        # 尝试提取各种协议的链接 (vless, trojan, ss, etc.)
        # 这是一个简化的示例，可能需要更复杂的正则表达式来匹配所有变体
        # 注意：这里仅是示例，实际生产环境可能需要更健壮的匹配规则
        patterns = [
            r"vmess://[a-zA-Z0-9+/=]+",
            r"ss://[a-zA-Z0-9+/=]+(?:@[0-9A-Za-z\.-]+(?::\d+)?)?(?:#.+)?",
            r"trojan://[^@]+@[0-9A-Za-z\.-]+(?::\d+)?(?:#.+)?",
            r"vless://[^@]+@[0-9A-Za-z\.-]+(?::\d+)?(?:#.+)?",
            r"hy2://[^@]+@[0-9A-Za-z\.-]+(?::\d+)?(?:#.+)?",
            r"warp://[^@]+@[0-9A-Za-z\.-]+(?::\d+)?(?:#.+)?",
            r"tuic://[^@]+@[0-9A-Za-z\.-]+(?::\d+)?(?:#.+)?",
        ]
        for pattern in patterns:
            found_nodes = re.findall(pattern, decoded_content)
            for node in found_nodes:
                nodes.add(node)
        
        # 尝试逐行处理解码后的内容，如果不是上述链接格式，则认为是明文节点
        for line in decoded_content.splitlines():
            line = line.strip()
            if line and not line.startswith('#'): # 忽略注释行
                # 简单过滤，认为太短的或者不包含常见协议名的不是节点
                if len(line) > 10 and any(proto in line for proto in ['vmess', 'ss', 'trojan', 'vless', 'hy2', 'warp', 'tuic', 'http', 'https']):
                    nodes.add(line)

    # 如果以上都未能提取，尝试将原始内容作为明文节点（逐行处理）
    else:
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith('#'): # 忽略注释行
                if len(line) > 10 and any(proto in line for proto in ['vmess', 'ss', 'trojan', 'vless', 'hy2', 'warp', 'tuic', 'http', 'https']):
                    nodes.add(line)

    return nodes

def main():
    sources_file = 'sources.list'
    output_dir = 'data'
    output_file = os.path.join(output_dir, 'sources.txt')

    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)

    all_nodes = set()

    if not os.path.exists(sources_file):
        print(f"Error: {sources_file} not found in the root directory.")
        return

    with open(sources_file, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]

    print(f"Found {len(urls)} URLs in {sources_file}")

    for url in urls:
        print(f"Processing URL: {url}")
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
            content = response.text

            # 尝试处理Base64编码的订阅链接，这些链接通常不会在响应头中明确指出Content-Type
            if len(content) > 100 and not any(c in content for c in [' ', '\n', '\r']) and not content.startswith(('http', 'https', 'vmess', 'ss', 'trojan', 'vless')):
                decoded_content = decode_base64(content)
                if decoded_content:
                    print(f"  Attempting to decode Base64 from {url}")
                    nodes = extract_nodes(decoded_content)
                else:
                    nodes = extract_nodes(content) # 如果解码失败，尝试原始内容
            else:
                nodes = extract_nodes(content) # 直接处理内容


            if nodes:
                all_nodes.update(nodes)
                print(f"  Extracted {len(nodes)} nodes from {url}")
            else:
                print(f"  No valid nodes extracted from {url}")

        except requests.exceptions.RequestException as e:
            print(f"  Error fetching {url}: {e}")
        except Exception as e:
            print(f"  An unexpected error occurred for {url}: {e}")

    # 写入去重后的节点到文件
    with open(output_file, 'w', encoding='utf-8') as f:
        for node in sorted(list(all_nodes)): # 排序以便于比较和查看
            f.write(node + '\n')

    print(f"\nSuccessfully extracted and saved {len(all_nodes)} unique nodes to {output_file}")

if __name__ == "__main__":
    main()
