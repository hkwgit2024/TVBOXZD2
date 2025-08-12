import yaml
import requests
import socket
import time

def get_country_code(host):
    """
    通过公共API获取IP地址的国家代码，支持域名解析。
    """
    print(f"正在处理: {host}")
    
    # 尝试解析域名为IP
    try:
        ip_address = socket.gethostbyname(host)
        print(f"  - 解析到 IP: {ip_address}")
    except socket.gaierror:
        print(f"  - 无法解析域名: {host}")
        return None
    
    # 查询IP的地理位置
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=2)
        response.raise_for_status()
        data = response.json()
        if data['status'] == 'success':
            country_code = data['countryCode']
            print(f"  - IP {ip_address} 的国家代码是: {country_code}")
            return country_code
    except requests.exceptions.RequestException as e:
        print(f"  - 查询IP地址 {ip_address} 失败: {e}")
        return None
    except Exception as e:
        print(f"  - 发生未知错误: {e}")
        return None
    finally:
        # 在每次API调用后增加1秒的延迟，以避免触发频率限制
        time.sleep(1)
    
    return None

def main():
    """
    主函数，用于下载、筛选和保存Clash配置。
    """
    include_codes = {'JP', 'KR', 'HK', 'TW', 'SG', 'MY', 'PH', 'VN', 'TH', 'LA', 'MM', 'RU', 'MN'}
    config_url = 'https://raw.githubusercontent.com/qjlxg/vt/refs/heads/main/clash_config.yaml'
    
    print("开始下载配置文件...")
    try:
        response = requests.get(config_url)
        response.raise_for_status()
        config = yaml.safe_load(response.text)
        print("配置文件下载并解析成功。")
    except requests.exceptions.RequestException as e:
        print(f"下载配置文件失败: {e}")
        return
    except yaml.YAMLError as e:
        print(f"解析YAML文件失败: {e}")
        return
    
    if 'proxies' not in config:
        print('配置中没有找到 proxies 列表。')
        return

    filtered_proxies = []
    print(f"配置文件中共有 {len(config['proxies'])} 个代理。")
    for proxy in config['proxies']:
        host = proxy.get('server')
        if host:
            country_code = get_country_code(host)
            if country_code and country_code in include_codes:
                filtered_proxies.append(proxy)
    
    config['proxies'] = filtered_proxies
    
    with open('filtered_by_ip.yaml', 'w') as f:
        yaml.dump(config, f, allow_unicode=True)
    
    print(f"已成功筛选出 {len(filtered_proxies)} 个节点，并保存到 filtered_by_ip.yaml。")

if __name__ == '__main__':
    main()
