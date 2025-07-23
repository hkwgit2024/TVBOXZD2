import unittest
from unittest.mock import patch, mock_open, MagicMock
import os
import subprocess
import json
import requests
import sys
import time # 导入 time 模块

# 添加当前脚本目录到模块搜索路径
sys.path.append(os.path.dirname(__file__))
# 确保从 main_script 导入 check_content_variation，因为它在一些测试中被 mock 了
from main_script import is_link_playable, main, load_config, is_valid_url, quick_check_url, get_stream_info, read_input_file, write_output_file, load_failed_links, is_excluded_url, check_content_variation

class TestIPTVChecker(unittest.TestCase):
    
    def test_load_config_default(self):
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', mock_open(read_data=json.dumps({
                "ffmpeg_path": "ffmpeg",
                "timeout": 3,
                "read_duration": 1,
                "max_retries": 2,
                "max_workers": 300,
                "min_resolution_width": 1280,
                "min_bitrate": 1000000,
                "max_response_time": 1.5,
                "quick_check_timeout": 0.5,
                "default_headers": {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                    "Referer": "https://www.example.com"
                },
                "exclude_domains": ["epg.pw", "ali-m-l.cztv.com"],
                "input_file": "list.txt",
                "output_file": "ff/ff.txt",
                "failed_links_file": "ff/failed_links.txt",
                "log_file": "ff/iptv_checker.log",
                "checkpoint_file": "ff/checkpoint.json"
            }))) as mocked_file:
                config = load_config()
                self.assertEqual(config['timeout'], 3)
                self.assertEqual(config['read_duration'], 1)
                self.assertEqual(config['min_resolution_width'], 1280)
                self.assertEqual(config['min_bitrate'], 1000000)
                self.assertEqual(config['max_response_time'], 1.5)
                self.assertEqual(config['quick_check_timeout'], 0.5)
                self.assertEqual(config['input_file'], "list.txt")
                self.assertEqual(config['output_file'], "ff/ff.txt")
                self.assertEqual(config['failed_links_file'], "ff/failed_links.txt")
                self.assertEqual(config['log_file'], "ff/iptv_checker.log")
                self.assertEqual(config['checkpoint_file'], "ff/checkpoint.json")
                mocked_file.assert_called_with(os.path.join('ff', 'config.json'), 'r')

    def test_is_excluded_url(self):
        self.assertTrue(is_excluded_url("https://epg.pw/stream.m3u8"))
        self.assertTrue(is_excluded_url("http://ali-m-l.cztv.com/stream.m3u8"))
        self.assertFalse(is_excluded_url("http://devstreaming-cdn.apple.com/stream.m3u8"))

    @patch('requests.head')
    def test_quick_check_url(self, mock_head):
        mock_head.return_value = unittest.mock.Mock(status_code=200)
        result, reason = quick_check_url("http://devstreaming-cdn.apple.com/videos/streaming/examples/bipbop_adv_example_hevc/master.m3u8")
        self.assertTrue(result)
        self.assertIsNone(reason)
        
        mock_head.return_value = unittest.mock.Mock(status_code=404)
        result, reason = quick_check_url("http://invalid.com/stream.m3u8")
        self.assertFalse(result)
        self.assertEqual(reason, "HTTP Error 404")
        
        mock_head.side_effect = requests.RequestException("Connection error")
        result, reason = quick_check_url("http://invalid.com/stream.m3u8")
        self.assertFalse(result)
        self.assertTrue(reason.startswith("Connection failed"))

    def test_load_failed_links(self):
        config = {
            "failed_links_file": "ff/failed_links.txt"
        }
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', mock_open(read_data="Test Channel,http://invalid.com/stream.m3u8,Invalid URL\n")):
                with patch('main_script.CONFIG', config):
                    failed_urls = load_failed_links()
                    self.assertEqual(failed_urls, {"http://invalid.com/stream.m3u8"})

    @patch('main_script.is_valid_url', return_value=True)
    @patch('main_script.is_excluded_url', return_value=False)
    @patch('main_script.quick_check_url', return_value=(True, None))
    @patch('subprocess.run')
    def test_get_stream_info(self, mock_run, mock_quick_check, mock_excluded_url, mock_valid_url):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps({
                "streams": [{"codec_type": "video", "width": 1920, "height": 1080, "bit_rate": "2000000"}]
            }),
            stderr=""
        )
        streams, error = get_stream_info("http://devstreaming-cdn.apple.com/videos/streaming/examples/bipbop_adv_example_hevc/master.m3u8")
        self.assertEqual(len(streams), 1)
        self.assertEqual(streams[0]['width'], 1920)
        self.assertEqual(error, None)

        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="Connection refused"
        )
        streams, error = get_stream_info("http://invalid.com/stream.m3u8")
        self.assertEqual(streams, [])
        self.assertTrue(error.startswith("FFmpeg error"))

    @patch('main_script.is_valid_url', return_value=True)
    @patch('main_script.is_excluded_url', return_value=False)
    @patch('main_script.quick_check_url', return_value=(True, None))
    @patch('main_script.get_stream_info')
    @patch('main_script.check_content_variation') # 确保这里也 mock 了 check_content_variation
    @patch('subprocess.run')
    @patch('time.time') # 模拟时间
    def test_is_link_playable_success(self, mock_time, mock_run, mock_content_variation, mock_stream_info, mock_quick_check, mock_excluded_url, mock_valid_url):
        # 模拟 time.time 的返回值，以计算响应时间
        mock_time.side_effect = [0, 0.5] # 开始时间为0，结束时间为0.5，模拟0.5秒的响应时间

        mock_stream_info.return_value = ([{"codec_type": "video", "width": 1920, "height": 1080, "bit_rate": "2000000"}], None)
        mock_content_variation.return_value = (True, None) # 模拟内容无变化
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0, # 模拟 FFmpeg 成功运行
            stdout="",
            stderr=""
        )
        
        url = "http://devstreaming-cdn.apple.com/videos/streaming/examples/bipbop_adv_example_hevc/master.m3u8"
        channel_name = "Test Channel"
        is_playable, response_time, width, bitrate, reason = is_link_playable(url, channel_name)
        
        self.assertTrue(is_playable)
        self.assertGreater(response_time, 0)
        self.assertEqual(width, 1920)
        self.assertEqual(bitrate, 2000000)
        self.assertEqual(reason, "Success")

    @patch('main_script.is_valid_url', return_value=True)
    @patch('main_script.is_excluded_url', return_value=False)
    @patch('main_script.quick_check_url', return_value=(True, None))
    @patch('main_script.get_stream_info')
    def test_is_link_playable_low_resolution(self, mock_stream_info, mock_quick_check, mock_excluded_url, mock_valid_url):
        mock_stream_info.return_value = ([{"codec_type": "video", "width": 640, "height": 480, "bit_rate": "2000000"}], None)
        url = "http://valid.com/low.m3u8"
        channel_name = "Test Channel"
        is_playable, response_time, width, bitrate, reason = is_link_playable(url, channel_name)
        
        self.assertFalse(is_playable)
        self.assertEqual(width, 640)
        self.assertEqual(bitrate, 2000000)
        self.assertTrue(reason.startswith("Low resolution"))

    @patch('main_script.is_valid_url', return_value=True)
    @patch('main_script.is_excluded_url', return_value=False)
    @patch('main_script.quick_check_url', return_value=(True, None))
    @patch('main_script.get_stream_info')
    @patch('main_script.check_content_variation') # 确保这里也 mock 了 check_content_variation
    @patch('subprocess.run')
    @patch('time.time') # 模拟时间
    def test_is_link_playable_slow_response(self, mock_time, mock_run, mock_content_variation, mock_stream_info, mock_quick_check, mock_excluded_url, mock_valid_url):
        # 模拟 time.time 的返回值，以计算响应时间
        mock_time.side_effect = [0, 2.5] # 开始时间为0，结束时间为2.5，模拟2.5秒的响应时间

        mock_stream_info.return_value = ([{"codec_type": "video", "width": 1920, "height": 1080, "bit_rate": "2000000"}], None)
        mock_content_variation.return_value = (True, None) # 模拟内容无变化
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0, # 模拟 FFmpeg 成功运行 (但由于时间长，仍判断为慢响应)
            stdout="",
            stderr=""
        )
        
        url = "http://valid.com/stream.m3u8"
        channel_name = "Test Channel"
        is_playable, response_time, width, bitrate, reason = is_link_playable(url, channel_name)
        
        self.assertFalse(is_playable) # 期望是 False，因为响应时间过长
        self.assertGreaterEqual(response_time, 2) # 应该大约是 2.5
        self.assertTrue(reason.startswith("Slow response"))

    @patch('main_script.is_valid_url', return_value=True)
    @patch('main_script.is_excluded_url', return_value=False)
    @patch('main_script.quick_check_url', return_value=(True, None))
    @patch('main_script.get_stream_info')
    @patch('main_script.check_content_variation') # 确保这里也 mock 了 check_content_variation
    @patch('subprocess.run')
    @patch('time.time') # 模拟时间
    def test_is_link_playable_unstable(self, mock_time, mock_run, mock_content_variation, mock_stream_info, mock_quick_check, mock_excluded_url, mock_valid_url):
        # 模拟 time.time 的返回值，以计算响应时间
        mock_time.side_effect = [0, 0.5] # 模拟快速响应，但 FFmpeg 失败

        mock_stream_info.return_value = ([{"codec_type": "video", "width": 1920, "height": 1080, "bit_rate": "2000000"}], None)
        mock_content_variation.return_value = (True, "FFmpeg error in content check: 403 Forbidden") # 模拟内容检查失败
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=1, # 模拟 FFmpeg 失败
            stdout="",
            stderr="403 Forbidden"
        )
        
        url = "http://valid.com/unstable.m3u8"
        channel_name = "Test Channel"
        is_playable, response_time, width, bitrate, reason = is_link_playable(url, channel_name)
        
        self.assertFalse(is_playable)
        self.assertGreater(response_time, 0) # 应该大约是 0.5
        self.assertTrue(reason.startswith("Unstable connection"))

    @patch('main_script.is_valid_url', return_value=True)
    @patch('main_script.is_excluded_url', return_value=True)
    def test_is_link_playable_excluded(self, mock_excluded_url, mock_valid_url):
        url = "https://epg.pw/stream.m3u8"
        channel_name = "Test Channel"
        is_playable, response_time, width, bitrate, reason = is_link_playable(url, channel_name)
        
        self.assertFalse(is_playable)
        self.assertEqual(response_time, 0.0)
        self.assertIsNone(width)
        self.assertIsNone(bitrate)
        self.assertEqual(reason, "Excluded domain")

    def test_read_input_file_success(self):
        config = {"input_file": "list.txt", "failed_links_file": "ff/failed_links.txt", "checkpoint_file": "ff/checkpoint.json"}
        with patch('builtins.open', mock_open(read_data="Test Channel,http://devstreaming-cdn.apple.com/videos/streaming/examples/bipbop_adv_example_hevc/master.m3u8\n")):
            with patch('main_script.load_failed_links', return_value=set()):
                with patch('main_script.load_checkpoint', return_value={'processed_urls': [], 'valid_links': [], 'failed_links': []}):
                    with patch('main_script.CONFIG', config):
                        links_to_check, checkpoint = read_input_file()
                        self.assertEqual(len(links_to_check), 1)
                        self.assertEqual(links_to_check[0][0], "Test Channel")
                        self.assertEqual(links_to_check[0][1], "http://devstreaming-cdn.apple.com/videos/streaming/examples/bipbop_adv_example_hevc/master.m3u8")

    def test_read_input_file_skip_failed(self):
        config = {"input_file": "list.txt", "failed_links_file": "ff/failed_links.txt", "checkpoint_file": "ff/checkpoint.json"}
        with patch('builtins.open', mock_open(read_data="Test Channel,http://devstreaming-cdn.apple.com/videos/streaming/examples/bipbop_adv_example_hevc/master.m3u8\n")):
            with patch('main_script.load_failed_links', return_value={"http://devstreaming-cdn.apple.com/videos/streaming/examples/bipbop_adv_example_hevc/master.m3u8"}):
                with patch('main_script.load_checkpoint', return_value={'processed_urls': [], 'valid_links': [], 'failed_links': []}):
                    with patch('main_script.CONFIG', config):
                        links_to_check, checkpoint = read_input_file()
                        self.assertEqual(len(links_to_check), 0)

    def test_read_input_file_skip_excluded(self):
        config = {"input_file": "list.txt", "failed_links_file": "ff/failed_links.txt", "checkpoint_file": "ff/checkpoint.json"}
        with patch('builtins.open', mock_open(read_data="Test Channel,https://epg.pw/stream.m3u8\n")):
            with patch('main_script.load_failed_links', return_value=set()):
                with patch('main_script.load_checkpoint', return_value={'processed_urls': [], 'valid_links': [], 'failed_links': []}):
                    with patch('main_script.CONFIG', config):
                        links_to_check, checkpoint = read_input_file()
                        self.assertEqual(len(links_to_check), 0)

    def test_write_output_file(self):
        config = {
            "output_file": "ff/ff.txt",
            "failed_links_file": "ff/failed_links.txt",
            "checkpoint_file": "ff/checkpoint.json"
        }
        # 使用 mock_builtin_open 变量捕获 mock 对象
        with patch('builtins.open', new_callable=mock_open) as mock_builtin_open:
            with patch('main_script.load_checkpoint', return_value={'processed_urls': [], 'valid_links': [], 'failed_links': []}):
                with patch('main_script.CONFIG', config):
                    valid_links = [(1.0, "Test Channel,http://devstreaming-cdn.apple.com/videos/streaming/examples/bipbop_adv_example_hevc/master.m3u8")]
                    failed_links = [("Test Channel", "http://invalid.com/stream.m3u8", "Invalid URL")]
                    checkpoint = {'processed_urls': [], 'valid_links': [], 'failed_links': []}
                    success_count = write_output_file(valid_links, failed_links, checkpoint)
                    self.assertEqual(success_count, 1)
                    # 现在对捕获的 mock_builtin_open 对象进行断言
                    mock_builtin_open.assert_any_call(config['output_file'], 'w', encoding='utf-8')
                    mock_builtin_open.assert_any_call(config['failed_links_file'], 'a', encoding='utf-8')

    @patch('os.path.exists')
    @patch('main_script.load_config')
    @patch('main_script.read_input_file')
    @patch('main_script.write_output_file')
    @patch('main_script.load_checkpoint') # 确保 mock load_checkpoint
    @patch('main_script.save_checkpoint') # 确保 mock save_checkpoint
    def test_main_success(self, mock_save_checkpoint, mock_load_checkpoint, mock_write, mock_read, mock_config, mock_exists):
        mock_config.return_value = {
            "ffmpeg_path": "ffmpeg",
            "timeout": 3,
            "read_duration": 1,
            "max_retries": 2,
            "max_workers": 300,
            "min_resolution_width": 1280,
            "min_bitrate": 1000000,
            "max_response_time": 1.5,
            "quick_check_timeout": 0.5,
            "default_headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                "Referer": "https://www.example.com"
            },
            "exclude_domains": ["epg.pw", "ali-m-l.cztv.com"],
            "input_file": "list.txt",
            "output_file": "ff/ff.txt",
            "failed_links_file": "ff/failed_links.txt",
            "log_file": "ff/iptv_checker.log",
            "checkpoint_file": "ff/checkpoint.json"
        }
        mock_exists.return_value = True
        
        # 模拟 checkpoint 的初始值和 read_input_file 的返回值
        initial_checkpoint = {'processed_urls': [], 'valid_links': [], 'failed_links': []}
        mock_load_checkpoint.return_value = initial_checkpoint
        mock_read.return_value = ([("Test Channel", "http://devstreaming-cdn.apple.com/videos/streaming/examples/bipbop_adv_example_hevc/master.m3u8")], initial_checkpoint)
        
        mock_write.return_value = 1
        
        # 确保 is_link_playable 在这里也被正确 Mock，以返回成功结果
        with patch('main_script.is_link_playable', return_value=(True, 1.0, 1920, 2000000, "Success")):
            main()
            mock_write.assert_called_once() # 确认 write_output_file 被调用
            mock_save_checkpoint.assert_called_once() # 确认 save_checkpoint 被调用

    @patch('os.path.exists')
    @patch('main_script.load_config')
    def test_main_file_not_found(self, mock_config, mock_exists):
        mock_config.return_value = {
            "input_file": "list.txt",
            "output_file": "ff/ff.txt",
            "failed_links_file": "ff/failed_links.txt",
            "log_file": "ff/iptv_checker.log",
            "checkpoint_file": "ff/checkpoint.json"
        }
        mock_exists.return_value = False
        with patch('logging.Logger.error') as mock_logger:
            main()
            mock_logger.assert_called_with("Input file list.txt not found.")

if __name__ == '__main__':
    unittest.main()
