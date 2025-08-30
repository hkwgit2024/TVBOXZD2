import yaml
import sys

def clean_and_deduplicate_proxies(input_file, output_file):
    """
    清理并去重代理节点，采用协议、服务器和端口作为去重键，并提供实时进度。
    """
    # 整合协议定义，同时接受 'hy2' 和 'hysteria2'
    required_params = {
        'vmess': ['type', 'server', 'port', 'uuid', 'alterId'],
        'ss': ['type', 'server', 'port', 'cipher', 'password'],
        'hy2': ['type', 'server', 'port', 'password', 'auth'],
        'hysteria2': ['type', 'server', 'port', 'password', 'auth'],
        'trojan': ['type', 'server', 'port', 'password'],
        'vless': ['type', 'server', 'port', 'uuid']
    }

    try:
        with open(input_file, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)

        proxies = data.get('proxies', [])
        total_nodes_before = len(proxies)

        if not proxies:
            print("proxies列表为空，无需处理。")
            return

        cleaned_proxies = []
        seen_keys = set()
        discarded_stats = {
            'unsupported_protocol': 0,
            'missing_params': 0,
            'duplicates': 0
        }
        
        # 实时进度计数器
        progress_counter = 0

        for proxy in proxies:
            progress_counter += 1
            if progress_counter % 1000 == 0:
                print(f"处理进度：已处理 {progress_counter} 个节点...")

            proxy_type = proxy.get('type')
            
            # 兼容处理 hy2 和 hysteria2
            if proxy_type not in required_params:
                discarded_stats['unsupported_protocol'] += 1
                continue
            
            # 检查必要参数，这里采用协议+服务器+端口
            server = proxy.get('server')
            port = proxy.get('port')
            if not server or not port:
                discarded_stats['missing_params'] += 1
                continue
            
            # 创建唯一的去重键：协议、服务器和端口
            # 这样既能快速去重，又能保留同一IP不同端口的节点
            unique_key = (proxy_type, str(server), str(port))
            
            # 去重
            if unique_key in seen_keys:
                discarded_stats['duplicates'] += 1
            else:
                seen_keys.add(unique_key)
                # 保留所有必要参数
                cleaned_proxy_data = {}
                params = required_params[proxy_type]
                for param in params:
                    if param in proxy:
                        cleaned_proxy_data[param] = proxy[param]
                
                # 特别处理 Hysteria2 的 password/auth 兼容性
                if proxy_type in ['hy2', 'hysteria2']:
                    if 'password' not in cleaned_proxy_data and 'auth' in proxy:
                        cleaned_proxy_data['password'] = proxy['auth']

                cleaned_proxies.append(cleaned_proxy_data)

        total_nodes_after = len(cleaned_proxies)
        total_discarded = total_nodes_before - total_nodes_after

        with open(output_file, 'w', encoding='utf-8') as f:
            yaml.safe_dump({'proxies': cleaned_proxies}, f, allow_unicode=True, sort_keys=False, default_flow_style=False)

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
        print(f"错误: YAML解析失败: {e}")

if __name__ == '__main__':
    clean_and_deduplicate_proxies('link.yaml', 'link_cleaned.yaml')
