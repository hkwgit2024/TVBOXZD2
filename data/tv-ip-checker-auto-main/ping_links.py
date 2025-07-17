import requests

# 读取链接文件
with open('links.txt', 'r') as file:
    links = file.readlines()

# 存储可用的链接
reachable_links = []

# 测试每个链接
for link in links:
    link = link.strip()
    try:
        response = requests.head(link, allow_redirects=True)
        if response.status_code == 200:
            reachable_links.append(link)
            print(f"可用链接: {link}")
        else:
            print(f"不可用链接: {link} (状态码: {response.status_code})")
    except requests.RequestException:
        print(f"不可用链接: {link} (请求异常)")

# 将可用的链接写入新文件
with open('reachable_links.txt', 'w') as file:
    for link in reachable_links:
        file.write(link + '\n')

print("可用的链接已保存到 reachable_links.txt 文件中。")
