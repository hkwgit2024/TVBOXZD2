import yaml

def clean_and_deduplicate_proxies(input_file, output_file):
    """
    清理并去重代理节点，并输出详细的统计报告。
    """
    # 定义各协议的必要参数
    required_params = {
        'vmess': ['type', 'server', 'port', 'uuid'],
        'ss': ['type', 'server', 'port', 'cipher', 'password'],
        'hy2': ['type', 'server', 'port', 'password'],
        'trojan': ['type', 'server', 'port', 'password'],
        'vless': ['type', 'server', 'port', 'uuid']
    }

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        proxies = data.get('proxies', [])
        total_nodes_before = len(proxies)
        
        cleaned_proxies = []
        seen_proxies = set()
        discarded_stats = {
            'unsupported_protocol': 0,
            'missing_params': 0,
            'duplicates': 0
        }

        for proxy in proxies:
            proxy_type = proxy.get('type')
            
            # 检查协议是否支持
            if proxy_type not in required_params:
                discarded_stats['unsupported_protocol'] += 1
                continue
            
            # 检查必要参数
            is_valid = all(param in proxy for param in required_params[proxy_type])
            if not is_valid:
                discarded_stats['missing_params'] += 1
                continue

            # 创建一个只包含必要参数的精简节点用于去重和输出
            cleaned_proxy_data = {param: proxy[param] for param in required_params[proxy_type]}
            unique_key = tuple(sorted(cleaned_proxy_data.items()))
            
            if unique_key in seen_proxies:
                discarded_stats['duplicates'] += 1
            else:
                seen_proxies.add(unique_key)
                cleaned_proxies.append(cleaned_proxy_data)

        total_nodes_after = len(cleaned_proxies)
        total_discarded = total_nodes_before - total_nodes_after

        # 写入新的YAML文件
        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.safe_dump({'proxies': cleaned_proxies}, f, allow_unicode=True, sort_keys=False, default_flow_style=False)
            
        # 打印详细报告
        print("🎉 节点清理报告")
        print("--------------------")
        print(f"📦 清理前节点总数: {total_nodes_before} 个")
        print("🗑️ 丢弃节点详情:")
        print(f"  - 协议不支持: {discarded_stats['unsupported_protocol']} 个")
        print(f"  - 缺少必要参数: {discarded_stats['missing_params']} 个")
        print(f"  - 重复节点: {discarded_stats['duplicates']} 个")
        print(f"  - 丢弃总数: {total_discarded} 个")
        print(f"✅ 清理后节点总数: {total_nodes_after} 个")
        print("--------------------")
        print(f"文件已保存至: {output_file}")

    except FileNotFoundError:
        print(f"错误: 文件 {input_file} 未找到。")
    except yaml.YAMLError as e:
        print(f"解析YAML文件时发生错误: {e}")

if __name__ == '__main__':
    clean_and_deduplicate_proxies('link.yaml', 'link_cleaned.yaml')
