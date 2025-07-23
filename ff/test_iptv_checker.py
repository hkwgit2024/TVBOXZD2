import unittest
from unittest.mock import patch, mock_open
import os
import subprocess
import json
import requests
from main_script import is_link_playable, main, load_config, is_valid_url, quick_check_url, get_stream_info, read_input_file, write_output_file, load_failed_links

class TestIPTVChecker(unittest.TestCase):
    
    def test_load_config_default(self):
        with patch('os.path.exists', return_value=False):
            with patch('builtins.open', mock_open()) as mocked_file:
                config = load_config()
                self.assertEqual(config['timeout'], 3)
                self.assertEqual(config['read_duration'], 1)
                self.assertEqual(config['min_resolution_width'], 1280)
                self.assertEqual(config['min_bitrate'], 1000000)
                self.assertEqual(config['max_response_time'], 1.5)
                self.assertEqual(config['quick_check_timeout'], 2)
                self.assertIn("default_headers", config)
                mocked_file.assert_called_with(os.path.join('ff', 'config.json'), 'w')

    @patch('requests.head')
    def test_quick_check_url(self, mock_head):
        mock_head.return_value = unittest.mock.Mock(status_code=200)
        result, reason = quick_check_url("http://valid.com/stream.m3u8")
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
        with patch('os.path.exists', return_value=True):
            with patch('builtins.open', mock_open(read_data="Test Channel,http://invalid.com/stream.m3u8,Invalid URL\n")):
                failed_urls = load_failed_links()
                self.assertEqual(failed_urls, {"http://invalid.com/stream.m3u8"})

    @patch('main_script.is_valid_url', return_value=True)
    @patch('main_script.quick_check_url', return_value=(True, None))
    @patch('subprocess.run')
    def test_get_stream_info(self, mock_run, mock_quick_check, mock_valid_url):
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=json.dumps({
                "streams": [{"codec_type": "video", "width": 1920, "height": 1080, "bit_rate": "2000000"}]
            }),
            stderr=""
        )
        streams, error = get_stream_info("http://valid.com/stream.m3u8")
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
    @patch('main_script.quick_check_url', return_value=(True, None))
    @patch('main_script.get_stream_info')
    @patch('subprocess.run')
    def test_is_link_playable_success(self, mock_run, mock_stream_info, mock_quick_check, mock_valid_url):
        mock_stream_info.return_value = ([{"codec_type": "video", "width": 1920, "height": 1080, "bit_rate": "2000000"}], None)
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="",
            stderr=""
        )
        
        url = "http://valid.com/stream.m3u8"
        channel_name = "Test Channel"
        is_playable, response_time, width, bitrate, reason = is_link_playable(url, channel_name)
        
        self.assertTrue(is_playable)
        self.assertGreater(response_time, 0)
        self.assertEqual(width, 1920)
        self.assertEqual(bitrate, 2000000)
        self.assertEqual(reason, "Success")

    @patch('main_script.is_valid_url', return_value=True)
    @patch('main_script.quick_check_url', return_value=(True, None))
    @patch('main_script.get_stream_info')
    def test_is_link_playable_low_resolution(self, mock_stream_info, mock_quick_check, mock_valid_url):
        mock_stream_info.return_value = ([{"codec_type": "video", "width": 640, "height": 480, "bit_rate": "2000000"}], None)
        url = "http://valid.com/low.m3u8"
        channel_name = "Test Channel"
        is_playable, response_time, width, bitrate, reason = is_link_playable(url, channel_name)
        
        self.assertFalse(is_playable)
        self.assertEqual(width, 640)
        self.assertEqual(bitrate, 2000000)
        self.assertTrue(reason.startswith("Low resolution"))

    @patch('main_script.is_valid_url', return_value=True)
    @patch('main_script.quick_check_url', return_value=(True, None))
    @patch('main_script.get_stream_info')
    @patch('subprocess.run')
    def test_is_link_playable_slow_response(self, mock_run, mock_stream_info, mock_quick_check, mock_valid_url):
        mock_stream_info.return_value = ([{"codec_type": "video", "width": 1920, "height": 1080, "bit_rate": "2000000"}], None)
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="",
            stderr=""
        )
        with patch('time.time', side_effect=[0, 2]):  # 模拟2秒响应
            url = "http://valid.com/stream.m3u8"
            channel_name = "Test Channel"
            is_playable, response_time, width, bitrate, reason = is_link_playable(url, channel_name)
            
            self.assertFalse(is_playable)
            self.assertGreaterEqual(response_time, 2)
            self.assertTrue(reason.startswith("Slow response"))

    @patch('main_script.is_valid_url', return_value=True)
    @patch('main_script.quick_check_url', return_value=(True, None))
    @patch('main_script.get_stream_info')
    @patch('subprocess.run')
    def test_is_link_playable_unstable(self, mock_run, mock_stream_info, mock_quick_check, mock_valid_url):
        mock_stream_info.return_value = ([{"codec_type": "video", "width": 1920, "height": 1080, "bit_rate": "2000000"}], None)
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=1,
            stdout="",
            stderr="403 Forbidden"
        )
        
        url = "http://valid.com/unstable.m3u8"
        channel_name = "Test Channel"
        is_playable, response_time, width, bitrate, reason = is_link_playable(url, channel_name)
        
        self.assertFalse(is_playable)
        self.assertGreater(response_time, 0)
        self.assertTrue(reason.startswith("Unstable connection"))

    @patch('builtins.open', new_callable=mock_open, read_data="Test Channel,http://valid.com/stream.m3u8\n")
    def test_read_input_file_success(self, mock_file):
        with patch('main_script.load_failed_links', return_value=set()):
            links_to_check = read_input_file('list.txt')
            self.assertEqual(len(links_to_check), 1)
            self.assertEqual(links_to_check[0][0], "Test Channel")
            self.assertEqual(links_to_check[0][1], "http://valid.com/stream.m3u8")

    @patch('builtins.open', new_callable=mock_open, read_data="Test Channel,http://valid.com/stream.m3u8\n")
    def test_read_input_file_skip_failed(self, mock_file):
        with patch('main_script.load_failed_links', return_value={"http://valid.com/stream.m3u8"}):
            links_to_check = read_input_file('list.txt')
            self.assertEqual(len(links_to_check), 0)

    def test_write_output_file(self):
        valid_links = [(1.0, "Test Channel,http://valid.com/stream.m3u8")]
        failed_links = [("Test Channel,http://invalid.com/stream.m3u8", "Invalid URL")]
        stats = {'checked': 1, 'success': 0, 'invalid': 0, 'low_quality': 0, 'slow': 0, 'unstable': 0}
        with patch('builtins.open', mock_open()) as mocked_file:
            success_count = write_output_file('ff.txt', valid_links, failed_links)
            self.assertEqual(success_count, 1)
            self.assertEqual(stats['success'], 0)  # stats not modified here
            mocked_file.assert_any_call(os.path.join('ff', 'ff.txt'), 'w', encoding='utf-8')
            mocked_file.assert_any_call(os.path.join('ff', 'failed_links.txt'), 'a', encoding='utf-8')

    @patch('os.path.exists')
    @patch('main_script.load_config')
    @patch('main_script.read_input_file')
    @patch('main_script.write_output_file')
    def test_main_success(self, mock_write, mock_read, mock_config, mock_exists):
        mock_config.return_value = {
            "ffmpeg_path": "ffmpeg",
            "timeout": 3,
            "read_duration": 1,
            "max_retries": 2,
            "max_workers": 4,
            "min_resolution_width": 1280,
            "min_bitrate": 1000000,
            "max_response_time": 1.5,
            "quick_check_timeout": 2,
            "default_headers": {
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36",
                "Referer": "https://www.example.com"
            }
        }
        mock_exists.return_value = True
        mock_read.return_value = [("Test Channel", "http://valid.com/stream.m3u8")]
        mock_write.return_value = 1
        
        with patch('main_script.is_link_playable', return_value=(True, 1.0, 1920, 2000000, "Success")):
            main()
            mock_write.assert_called()

    @patch('os.path.exists')
    def test_main_file_not_found(self, mock_exists):
        mock_exists.return_value = False
        with patch('logging.Logger.error') as mock_logger:
            main()
            mock_logger.assert_called_with("Input file list.txt not found in ff directory.")

if __name__ == '__main__':
    unittest.main()
