# generate_clash_config.py
import json
import yaml
import sys
import os

def generate_clash_config(log_file_path, original_config_path, output_config_path):
    """
    从 speedtest-clash 的日志中提取排序后的代理节点数据，
    并将其合并到原始的 Clash 配置文件中，然后输出到新文件。

    Args:
        log_file_path (str): speedtest-clash 输出的日志文件路径。
        original_config_path (str): 原始 Clash 配置文件的路径 (包含非代理部分)。
        output_config_path (str): 生成的 Clash 配置文件的输出路径。
    """
    sorted_proxies_json_str = ""

    # 检查日志文件是否存在
    if not os.path.exists(log_file_path):
        print(f"Error: Log file '{log_file_path}' does not exist. Please ensure the path is correct and the file has been generated.", file=sys.stderr)
        sys.exit(1)

    # 1. 从日志文件中提取排序后的代理 JSON 字符串
    print(f"Parsing '{log_file_path}' for sorted proxies JSON...")
    with open(log_file_path, 'r', encoding='utf-8') as f:
        for line in f:
            # 寻找包含日志时间戳和 "message":"json: [" 的行
            if '{"time":' in line and '"message":"json: [' in line:
                try:
                    log_entry = json.loads(line)
                    message_content = log_entry.get('message', '')
                    if message_content.startswith('json: ['):
                        # 提取 "json: " 后面的内容，即纯粹的 JSON 数组字符串
                        sorted_proxies_json_str = message_content[len('json: '):]
                        print("Successfully extracted proxy JSON string.")
                        break # Found, no need to read further
                except json.JSONDecodeError:
                    # If not a valid JSON log entry, skip
                    continue
    
    if not sorted_proxies_json_str:
        print(f"Error: Could not extract sorted proxies JSON from '{log_file_path}'.", file=sys.stderr)
        print("Please check log content to ensure 'speedtest-clash' outputs lines in 'json: [...]' format.", file=sys.stderr)
        sys.exit(1)

    # 2. 将提取到的 JSON 字符串转换为 Python 列表
    try:
        proxies_data = json.loads(sorted_proxies_json_str)
        print("Proxy JSON string successfully parsed into Python object.")
    except json.JSONDecodeError as e:
        print(f"Error: Extracted string is not valid JSON: {e}", file=sys.stderr)
        print(f"Problematic string (first 200 chars): {sorted_proxies_json_str[:200]}...", file=sys.stderr)
        sys.exit(1)

    # 检查原始配置文件是否存在
    if not os.path.exists(original_config_path):
        print(f"Error: Original config file '{original_config_path}' does not exist. Please ensure the path is correct.", file=sys.stderr)
        sys.exit(1)

    # 3. 加载原始 Clash 配置
    print(f"Loading original Clash config from '{original_config_path}'...")
    try:
        with open(original_config_path, 'r', encoding='utf-8') as f:
            original_config = yaml.safe_load(f)
        print("Original Clash config loaded successfully.")
    except Exception as e:
        print(f"Error: Could not load original config '{original_config_path}': {e}", file=sys.stderr)
        sys.exit(1)

    # Ensure original_config is a dictionary
    if not isinstance(original_config, dict):
        print(f"Error: Original config '{original_config_path}' is not a valid YAML dictionary. Exiting.", file=sys.stderr)
        sys.exit(1)

    # 4. 将排序后的代理列表替换原始配置中的 'proxies' 部分
    print("Replacing 'proxies' section in the config...")
    original_config['proxies'] = proxies_data

    # 5. 将修改后的配置写入输出文件
    print(f"Writing final config to '{output_config_path}'...")
    try:
        with open(output_config_path, 'w', encoding='utf-8') as f:
            # default_flow_style=False ensures block style for proxies (one per line)
            # sort_keys=False to preserve original key order in other sections
            yaml.dump(original_config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
        print(f"Clash config '{output_config_path}' successfully generated!")
    except Exception as e:
        print(f"Error: Could not write output config to '{output_config_path}': {e}", file=sys.stderr)
        sys.exit(1)

    # Print the generated file content (for debugging in workflow logs)
    print(f"\n--- Content of '{output_config_path}' ---")
    with open(output_config_path, 'r', encoding='utf-8') as f:
        print(f.read())
    print("------------------------------------------")

if __name__ == "__main__":
    # Script expects 3 command-line arguments: log file, original config, output config
    if len(sys.argv) != 4:
        print("Usage: python generate_clash_config.py <speedtest_log_file> <original_clash_config.yaml> <output_clash.yaml>", file=sys.stderr)
        sys.exit(1)

    log_file = sys.argv[1]
    original_config = sys.argv[2]
    output_config = sys.argv[3]

    # Check for PyYAML library
    try:
        import yaml
    except ImportError:
        print("Error: PyYAML library not found. Please install it using 'pip install PyYAML'.", file=sys.stderr)
        sys.exit(1)
    
    generate_clash_config(log_file, original_config, output_config)
