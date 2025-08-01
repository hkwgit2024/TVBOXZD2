import os
import glob

def merge_results():
    output_dir = 'output'
    final_playlist = 'output/final_playlist.txt'
    valid_urls = set()
    categorized_urls = {}

    # 合并 mpeg_shard_X.txt
    for mpeg_file in glob.glob(f'{output_dir}/mpeg_shard_*.txt'):
        with open(mpeg_file, 'r', encoding='utf-8') as f:
            valid_urls.update(line.strip() for line in f if line.strip())

    # 合并分类文件
    for category_file in glob.glob(f'{output_dir}/*_shard_*.txt'):
        category = os.path.basename(category_file).split('_shard_')[0]
        if category not in categorized_urls:
            categorized_urls[category] = set()
        with open(category_file, 'r', encoding='utf-8') as f:
            categorized_urls[category].update(line.strip() for line in f if line.strip())
        valid_urls.update(categorized_urls[category])

    # 保存合并的 final_playlist.txt
    with open(final_playlist, 'w', encoding='utf-8') as f:
        for url in sorted(valid_urls):
            f.write(url + '\n')
    print(f"合并完成，生成 {final_playlist}，包含 {len(valid_urls)} 个有效 URL")

    # 保存分类 M3U 文件
    for category, urls in categorized_urls.items():
        category_m3u = f'{output_dir}/{category}.m3u'
        with open(category_m3u, 'w', encoding='utf-8') as f:
            f.write('#EXTM3U\n')
            for url in sorted(urls):
                f.write(f'#EXTINF:-1,{category} - {url}\n{url}\n')
        print(f"生成分类 M3U 文件：{category_m3u}，包含 {len(urls)} 个 URL")

if __name__ == "__main__":
    merge_results()
