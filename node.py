import os
import requests
import base64

# 从环境变量获取
GITHUB_API_URL = "https://api.github.com"
OWNER = os.environ.get("GITHUB_OWNER")
REPO = os.environ.get("GITHUB_REPO")
TOKEN = os.environ.get("GITHUB_TOKEN")

HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Accept": "application/vnd.github+json"
}

def get_yaml_files():
    """
    获取仓库中所有yaml文件的路径
    """
    yaml_files = []
    page = 1
    per_page = 100

    while True:
        url = f"{GITHUB_API_URL}/repos/{OWNER}/{REPO}/contents?per_page={per_page}&page={page}"
        response = requests.get(url, headers=HEADERS)
        if response.status_code != 200:
            print(f"请求失败: {response.status_code}")
            break

        contents = response.json()

        if not contents:
            break

        for item in contents:
            if item['type'] == 'file' and item['name'].lower().endswith('.yaml'):
                yaml_files.append(item['path'])

        # 判断是否有下一页
        if 'Link' in response.headers:
            links = response.headers['Link']
            if 'rel="next"' in links:
                page += 1
            else:
                break
        else:
            break

    return yaml_files

def download_file(file_path):
    """
    下载单个文件内容
    """
    url = f"{GITHUB_API_URL}/repos/{OWNER}/{REPO}/contents/{file_path}"
    response = requests.get(url, headers=HEADERS)
    if response.status_code != 200:
        print(f"无法下载 {file_path}: {response.status_code}")
        return ""

    content_json = response.json()
    encoded_content = content_json.get('content', '')
    decoded_bytes = base64.b64decode(encoded_content)
    return decoded_bytes.decode('utf-8')

def main():
    os.makedirs('data', exist_ok=True)
    yaml_files = get_yaml_files()
    print(f"找到 {len(yaml_files)} 个YAML文件。")
    all_content = []

    for file_path in yaml_files:
        print(f"下载 {file_path}")
        content = download_file(file_path)
        all_content.append(content)

    with open('data/ji.txt', 'w', encoding='utf-8') as f:
        f.write("\n---\n".join(all_content))
    print("所有Yaml内容已保存到 data/ji.txt")

if __name__ == "__main__":
    main()
