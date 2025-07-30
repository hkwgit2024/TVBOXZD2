def main():
    logging.warning("开始测试 IPTV 处理脚本")
    url_states = load_url_states_local()
    
    # 测试数据
    test_channels = [
        ("CCTV1", "http://example.com/cctv1.m3u8"),
        ("湖南卫视", "http://example.com/hunan.m3u8"),
        ("购物频道", "http://example.com/shopping.m3u8")
    ]
    
    # 测试过滤
    filtered_channels = filter_and_modify_channels(test_channels)
    logging.warning(f"过滤后频道: {filtered_channels}")
    
    # 测试分类
    categorized, uncategorized = categorize_channels(filtered_channels)
    logging.warning(f"分类结果: {categorized}")
    logging.warning(f"未分类: {uncategorized}")
    
    # 保存分类结果
    process_and_save_channels_by_category(filtered_channels, url_states, {})
    
    # 合并文件
    merge_local_channel_files(CONFIG['output']['paths']['channels_dir'], IPTV_LIST_PATH, url_states)
    
    save_url_states_local(url_states)
    logging.warning("测试完成")

if __name__ == "__main__":
    main()
