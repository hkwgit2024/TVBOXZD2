import yaml
import sys
import os

try:
    # 检查输入文件是否存在
    input_file = 'clash_config.yaml'
    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.", file=sys.stderr)
        sys.exit(1)

    with open(input_file, 'r', encoding='utf-8') as f:
        config = yaml.safe_load(f)

    filtered_proxies = []
    # 确保 'proxies' 键存在且是列表
    if 'proxies' in config and isinstance(config['proxies'], list):
        for proxy in config['proxies']:
            # 确保代理是一个字典，并且有 'name' 键
            if isinstance(proxy, dict) and 'name' in proxy:
                name = proxy['name']
                # 过滤条件：匹配 US, Japan, Singapore, HK (不区分大小写)
                if any(country.lower() in name.lower() for country in ['US', 'Japan', 'Singapore', 'HK']):
                    filtered_proxies.append(proxy)
            else:
                print(f"Warning: Skipping malformed proxy entry: {proxy}", file=sys.stderr)
    else:
        print("Warning: No 'proxies' key found or it's not a list in the input config.", file=sys.stderr)


    # 将过滤后的代理列表包装在 'proxies' 键下，以符合 Clash 配置文件格式
    output_config = {'proxies': filtered_proxies}
    
    output_file = 'filtered_nodes.yaml'
    with open(output_file, 'w', encoding='utf-8') as f:
        # 使用 default_flow_style=False 保持块状风格，便于阅读
        # allow_unicode=True 确保正确处理非ASCII字符
        # sort_keys=False 保持原始顺序，不按字母排序
        yaml.dump(output_config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        
    print(f"Successfully filtered {len(filtered_proxies)} nodes to '{output_file}'")

except yaml.YAMLError as e:
    print(f"Error parsing YAML: {e}", file=sys.stderr)
    sys.exit(1)
except Exception as e:
    print(f"An unexpected error occurred: {e}", file=sys.stderr)
    sys.exit(1)
