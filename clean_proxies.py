import sys
import yaml

def clean_links(proxies):
    if not proxies or not isinstance(proxies, list):
        print("❌ 代理节点列表为空或格式不正确。")
        return []

    cleaned_proxies = []
    seen_keys = set()
    discarded_stats = {
        'unsupported_protocol': 0,
        'missing_params': 0,
        'duplicate_nodes': 0
    }

    # 定义每种代理类型所需的参数
    required_params = {
        'ss': ['server', 'port', 'cipher', 'password'],
        'ssr': ['server', 'port', 'password', 'protocol', 'obfs'],
        'vmess': ['server', 'port', 'uuid'],
        'vless': ['server', 'port', 'uuid'],
        'trojan': ['server', 'port', 'password'],
    }

    total_proxies = len(proxies)
    processed_count = 0

    print(f"📦 清理前节点总数: {total_proxies} 个")
    
    for proxy in proxies:
        processed_count += 1
        if processed_count % 1000 == 0:
            print(f"处理进度：已处理 {processed_count} 个节点...")

        proxy_type = proxy.get('type')
        server = proxy.get('server')
        port = proxy.get('port')

        # 1. 检查协议是否支持
        if proxy_type not in required_params:
            discarded_stats['unsupported_protocol'] += 1
            continue

        # 2. 检查基本参数是否缺失
        if not all(proxy.get(param) for param in ['server', 'port']):
            discarded_stats['missing_params'] += 1
            continue

        # 3. 检查特定协议的必要参数是否缺失
        is_valid = True
        params_to_check = required_params.get(proxy_type, [])
        for param in params_to_check:
            if param not in proxy:
                is_valid = False
                break
        
        if not is_valid:
            discarded_stats['missing_params'] += 1
            continue

        # 4. 生成唯一键并检查重复
        # 将参数转换为字符串，确保哈希值一致性
        unique_key_parts = []
        for key in sorted(proxy.keys()):
            # 过滤掉不用于去重的键，例如name
            if key in ['name', 'region', '_index']:
                continue
            unique_key_parts.append(f"{key}:{proxy[key]}")
        
        unique_key = '|'.join(unique_key_parts)

        if unique_key in seen_keys:
            discarded_stats['duplicate_nodes'] += 1
            continue

        seen_keys.add(unique_key)

        # 5. 准备要保留的节点数据
        cleaned_proxy = {
            'type': proxy_type,
            'server': server,
            'port': port
        }

        # 动态添加其他必要参数
        for param in params_to_check:
            if param not in ['server', 'port']:
                cleaned_proxy[param] = proxy[param]

        cleaned_proxies.append(cleaned_proxy)

    print(f"处理进度：已处理 {total_proxies} 个节点...")

    # 打印清理报告
    print("\n🎉 节点清理报告")
    print("--------------------")
    print(f"📦 清理前节点总数: {total_proxies} 个")
    print("🗑️ 丢弃节点详情:")
    print(f"  - 协议不支持: {discarded_stats['unsupported_protocol']} 个")
    print(f"  - 缺少必要参数: {discarded_stats['missing_params']} 个")
    print(f"  - 重复节点: {discarded_stats['duplicate_nodes']} 个")
    print(f"  - 丢弃总数: {sum(discarded_stats.values())} 个")
    print(f"✅ 清理后节点总数: {len(cleaned_proxies)} 个")
    print("--------------------")

    return cleaned_proxies

def main():
    try:
        with open('link.yaml', 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
    except FileNotFoundError:
        print("❌ 错误：找不到文件 'link.yaml'。请确保文件存在。")
        sys.exit(1)
    except yaml.YAMLError as e:
        print(f"❌ 错误：解析 YAML 文件时出错：{e}")
        sys.exit(1)

    proxies = data.get('proxies', [])
    cleaned_proxies = clean_links(proxies)

    if cleaned_proxies:
        try:
            with open('link_cleaned.yaml', 'w', encoding='utf-8') as f:
                yaml.dump({'proxies': cleaned_proxies}, f, allow_unicode=True, sort_keys=False)
            print("文件已保存至: link_cleaned.yaml")
        except IOError as e:
            print(f"❌ 错误：无法写入文件 'link_cleaned.yaml'：{e}")
    else:
        print("⚠️ 没有可用的有效节点。未生成 'link_cleaned.yaml' 文件。")

if __name__ == '__main__':
    main()
