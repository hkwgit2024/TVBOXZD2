import os

def convert_to_m3u():
    input_file = 'output/final_playlist.txt'
    output_file = 'output/final_playlist.m3u'
    if not os.path.exists(input_file):
        print(f"错误：{input_file} 不存在")
        return
    with open(input_file, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip()]
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('#EXTM3U\n')
        for url in urls:
            f.write(f'#EXTINF:-1,{url}\n{url}\n')
    print(f"M3U 文件生成：{output_file}，包含 {len(urls)} 个 URL")

if __name__ == "__main__":
    convert_to_m3u()
