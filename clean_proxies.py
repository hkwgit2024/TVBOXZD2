import yaml
import sys

def clean_and_deduplicate_proxies(input_file, output_file):
    """
    清理并去重代理节点，确保每个节点都有唯一的名称，并进行严格的参数检查。
    """
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

        progress_counter = 0

        for proxy in proxies:
            progress_counter += 1
            if progress_counter % 1000 == 0:
                print(f"处理进度：已处理 {progress_counter} 个节点...")

            proxy_type = proxy.get('type')
            server = proxy.get('server')
            port = proxy.get('port')
            
            # 检查必要参数和协议
            if proxy_type not in required_params or not server or not port:
                if proxy_type not in required_params:
                    discarded_stats['unsupported_protocol'] += 1
                else:
                    discarded_stats['missing_params'] += 1
                continue
            
            # 创建唯一的去重键：协议、服务器和端口
            unique_key = (proxy_type, str(server), str(port))
            
            if unique_key in seen_keys:
                discarded_stats['duplicates'] += 1
            else:
                seen_keys.add(unique_key)
                
                # 提取必要参数
                cleaned_proxy_data = {}
                params = required_params[proxy_type]
                
                # 严格检查所有必要参数是否都存在
                is_valid = all(param in proxy for param in params if param != 'auth')
                if not is_valid:
                    discarded_stats['missing_params'] += 1
                    continue
                
                for param in params:
                    if param in proxy:
                        cleaned_proxy_data[param] = proxy[param]
                
                # 特别处理 Hysteria2 的 password/auth 兼容性
                if proxy_type in ['hy2', 'hysteria2']:
                    if 'password' not in cleaned_proxy_data and 'auth' in proxy:
                        cleaned_proxy_data['password'] = proxy['auth']

                # 增加名称参数
                if 'name' in proxy and proxy['name']:
                    cleaned_proxy_data['name'] = proxy['name']
                else:
                    cleaned_proxy_data['name'] = f"[{proxy_type.upper()}] {server}:{port}"
                
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
