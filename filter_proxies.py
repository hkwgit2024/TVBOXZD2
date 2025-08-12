import yaml
import requests

def get_country_code(ip):
    """
    通过公共API获取IP地址的国家代码。
    """
    try:
        # 使用 ip-api.com 的免费公共API
        response = requests.get(f'http://ip-api.com/json/{ip}', timeout=2)
        response.raise_for_status()
        data = response.json()
        if data['status'] == 'success':
            return data['countryCode']
    except Exception:
        return None
    return None

def main():
    """
    主函数，用于下载、筛选和保存Clash配置。
    """
    # 你想保留的国家或地区代码
    include_codes = {'JP', 'KR', 'HK', 'TW', 'SG', 'MY', 'PH', 'VN', 'TH', 'LA', 'MM', 'RU', 'MN'}
    
    # 原始Clash配置文件的订阅地址
    config_url = 'https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/clash_config.yaml'
    
    try:
        # 下载原始配置文件
        response = requests.get(config_url)
        response.raise_for_status()
        config = yaml.safe_load(response.text)
    except requests.exceptions.RequestException as e:
        print(f"下载配置文件失败: {e}")
        return
    except yaml.YAMLError as e:
        print(f"解析YAML文件失败: {e}")
        return
    
    if 'proxies' not in config:
        print('没有找到 proxies 列表。')
        return

    filtered_proxies = []
    for proxy in config['proxies']:
        ip_address = proxy.get('server')
        if ip_address:
            country_code = get_country_code(ip_address)
            if country_code and country_code in include_codes:
                filtered_proxies.append(proxy)
    
    config['proxies'] = filtered_proxies
    
    # 将筛选后的配置保存到新文件
    with open('filtered_by_ip.yaml', 'w') as f:
        yaml.dump(config, f, allow_unicode=True)
    
    print(f"已成功筛选出 {len(filtered_proxies)} 个节点，并保存到 filtered_by_ip.yaml。")

if __name__ == '__main__':
    main()
