import yaml

def clean_and_deduplicate_proxies(input_file, output_file):
    """
    清理并去重代理节点，只保留指定协议的必要参数。
    """
    # 定义各协议的必要参数，确保去重和输出的精简
    required_params = {
        'vmess': ['type', 'server', 'port', 'uuid', 'alterId'],
        'ss': ['type', 'server', 'port', 'cipher', 'password'],
        'hy2': ['type', 'server', 'port', 'password'],
        'trojan': ['type', 'server', 'port', 'password'],
        'vless': ['type', 'server', 'port', 'uuid']
    }

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        proxies = data.get('proxies', [])
        cleaned_proxies = []
        seen_proxies = set()

        for proxy in proxies:
            proxy_type = proxy.get('type')
            
            # 检查协议和必要参数
            if proxy_type not in required_params:
                continue
            is_valid = all(param in proxy for param in required_params[proxy_type])
            if not is_valid:
                continue

            # 创建一个只包含必要参数的新节点用于去重和输出
            cleaned_proxy_data = {param: proxy[param] for param in required_params[proxy_type]}
            unique_key = tuple(sorted(cleaned_proxy_data.items()))
            
            if unique_key not in seen_proxies:
                seen_proxies.add(unique_key)
                cleaned_proxies.append(cleaned_proxy_data)

        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.safe_dump({'proxies': cleaned_proxies}, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
            
        print(f"清理完成，共保留 {len(cleaned_proxies)} 个节点，已保存至 {output_file}")

    except FileNotFoundError:
        print(f"错误: 文件 {input_file} 未找到。")
    except yaml.YAMLError as e:
        print(f"解析YAML文件时发生错误: {e}")

if __name__ == '__main__':
    clean_and_deduplicate_proxies('link.yaml', 'link_cleaned.yaml')
