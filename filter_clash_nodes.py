import yaml
import sys
import os

try:
    input_file = 'clash_config.yaml'
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.", file=sys.stderr)
        sys.exit(1)

    with open(input_file, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

    filtered_proxies = []
    if 'proxies' in config and isinstance(config['proxies'], list):
        for proxy in config['proxies']:
            if isinstance(proxy, dict) and 'server' in proxy: # 检查 'server' 字段
                server_address = proxy['server']
                
                # 定义国家/地区的关键词列表，匹配服务器地址中的标识符
                # 例如：sg001 -> SG, jp001 -> JP, us001 -> US, hk001 -> HK
                # 假设您的服务器地址命名规则是 sgXXX, jpXXX, usXXX, hkXXX
                keywords_to_match = ['sg', 'jp', 'us', 'hk']
                
                # 检查服务器地址是否包含任何一个关键词
                if any(keyword.lower() in server_address.lower() for keyword in keywords_to_match):
                    filtered_proxies.append(proxy)
            else:
                print(f"Warning: Skipping malformed proxy entry or entry without 'server' key: {proxy}", file=sys.stderr)
    else:
        print("Warning: No 'proxies' key found or it's not a list in the input config.", file=sys.stderr)

    output_config = {'proxies': filtered_proxies}
    
    output_file = 'filtered_nodes.yaml'
    with open(output_file, 'w', encoding='utf-8') as f:
        yaml.dump(output_config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        
    print(f"Successfully filtered {len(filtered_proxies)} nodes to '{output_file}'")

except yaml.YAMLError as e:
    print(f"Error parsing YAML: {e}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"An unexpected error occurred: {e}", file=sys.stderr)
    sys.exit(1)
