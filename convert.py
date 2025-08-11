import yaml
import sys

def load_yaml(path):
    with open(path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def main():
    if len(sys.argv) != 3:
        print("用法: python convert.py <测速结果.yaml> <原始config.yaml>")
        return

    result_file = sys.argv[1]
    original_file = sys.argv[2]

    results = load_yaml(result_file)
    original = load_yaml(original_file)

    name_set = {node['name'] for node in results if 'name' in node}
    filtered = [node for node in original.get('proxies', []) if node.get('name') in name_set]

    output = {
        'proxies': filtered,
        'proxy-groups': [
            {
                'name': '自动选择',
                'type': 'url-test',
                'proxies': [n['name'] for n in filtered],
                'url': 'http://www.gstatic.com/generate_204',
                'interval': 300
            }
        ],
        'rules': [
            'MATCH,自动选择'
        ]
    }

    with open('clash-use.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(output, f, allow_unicode=True, sort_keys=False)

    print("✅ 已生成 clash-use.yaml，可直接导入 Clash 客户端")

if __name__ == '__main__':
    main()
