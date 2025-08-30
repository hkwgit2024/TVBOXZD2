import yaml
import socket
import sys

def get_ip_from_hostname(hostname):
    """通过域名获取IP地址"""
    try:
        # 使用getaddrinfo来处理IPv4和IPv6，并获取第一个IP
        info = socket.getaddrinfo(hostname, None, 0, socket.SOCK_STREAM)
        return info[0][4][0]
    except (socket.gaierror, IndexError):
        return None

def clean_and_deduplicate_proxies(input_file, output_file):
    """
    清理并去重代理节点，采用最严格的去重规则：协议、服务器IP地址完全一致则视为重复。
    """
    # 整合协议定义，新增对 'hysteria2' 的 'auth' 参数支持
    required_params = {
        'vmess': ['type', 'server', 'port', 'uuid', 'alterId'],
        'ss': ['type', 'server', 'port', 'cipher', 'password'],
        'hy2': ['type', 'server', 'port', 'password'],
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

        for proxy in proxies:
            proxy_type = proxy.get('type')
            server = proxy.get('server')
            
            # 检查协议支持和服务器参数
            if proxy_type not in required_params or not server:
                discarded_stats['unsupported_protocol'] += 1
                continue
            
            # 将域名解析成IP地址用于去重
            resolved_ip = get_ip_from_hostname(server)
            if not resolved_ip:
                # 如果解析失败，则该节点被视为无效
                discarded_stats['missing_params'] += 1
                continue
            
            # 创建唯一的去重键：协议和服务器IP
            unique_key = (proxy_type, resolved_ip)
            
            # 去重
            if unique_key in seen_keys:
                discarded_stats['duplicates'] += 1
            else:
                seen_keys.add(unique_key)
                # 保留所有必要参数
                cleaned_proxy_data = {param: proxy[param] for param in required_params[proxy_type] if param in proxy}
                
                # 兼容Hysteria2的auth参数
                if proxy_type in ['hy2', 'hysteria2']:
                    if 'auth' in proxy:
                        cleaned_proxy_data['auth'] = proxy['auth']
                    elif 'password' in proxy:
                        cleaned_proxy_data['password'] = proxy['password']

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
