import yaml

def clean_and_deduplicate_proxies(input_file, output_file):
    """
    清理并去重代理节点，只保留指定协议的必要参数。
    """
    # 定义各协议的必要参数
    required_params = {
        'vmess': ['type', 'server', 'port', 'uuid', 'alterId'],
        'ss': ['type', 'server', 'port', 'cipher', 'password'],
        'hy2': ['type', 'server', 'port', 'password'],
        'trojan': ['type', 'server', 'port', 'password'],
        'vless': ['type', 'server', 'port', 'uuid']
    }

    try:
        # 读取输入文件
        with open(input_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        proxies = data.get('proxies', [])
        cleaned_proxies = []
        seen_proxies = set()

        for proxy in proxies:
            proxy_type = proxy.get('type')
            
            # 检查协议是否在列表中
            if proxy_type not in required_params:
                continue
            
            # 检查所有必要参数是否存在
            is_valid = True
            for param in required_params[proxy_type]:
                if param not in proxy:
                    is_valid = False
                    break
            
            if not is_valid:
                continue

            # 创建一个只包含必要参数的新节点
            cleaned_proxy = {param: proxy[param] for param in required_params[proxy_type]}
            
            # 创建一个用于去重的唯一标识符
            # 使用元组来确保可哈希
            unique_key = tuple(sorted(cleaned_proxy.items()))
            
            if unique_key not in seen_proxies:
                seen_proxies.add(unique_key)
                cleaned_proxies.append(cleaned_proxy)

        # 写入新的YAML文件
        with open(output_file, 'w', encoding='utf-8') as f:
            # 写入顶级键 'proxies'，并设置别名
            yaml.safe_dump({'proxies': cleaned_proxies}, f, allow_unicode=True, default_flow_style=False)
            
        print(f"清理完成，共保留 {len(cleaned_proxies)} 个节点，已保存至 {output_file}")

    except FileNotFoundError:
        print(f"错误: 文件 {input_file} 未找到。")
    except yaml.YAMLError as e:
        print(f"解析YAML文件时发生错误: {e}")

if __name__ == '__main__':
    clean_and_deduplicate_proxies('link.yaml', 'link_cleaned.yaml')
