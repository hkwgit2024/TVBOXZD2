import unittest
from unittest.mock import patch, mock_open, MagicMock
import os
import subprocess
import json
import requests
import sys
import time # Import time module to mock it

# Add current script directory to module search path
sys.path.append(os.path.dirname(__file__))
# Ensure to import check_content_variation if it's part of main_script
from main_script import is_link_playable, main, load_config, is_valid_url, quick_check_url, get_stream_info, read_input_file, write_output_file, load_failed_links, is_excluded_url, check_content_variation, save_checkpoint, CONFIG # Import save_checkpoint and CONFIG

class TestIPTVChecker(unittest.TestCase):
    # Setup initial CONFIG value as it's often imported and used directly
    # This is a good practice to ensure the CONFIG is in a known state for tests
    def setUp(self):
        # Reset CONFIG to a default state before each test that might rely on it
        # This is crucial for tests that directly interact with main_script.CONFIG
        # without explicitly patching it in their own scope.
        # For simplicity, we'll mimic the default config here.
        CONFIG.clear() # Clear existing config
        CONFIG.update({
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
        })

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
        # We need to ensure main_script.CONFIG is correctly set up for load_failed_links
        # This can be done by patching main_script.CONFIG within the test's scope
        with patch('main_script.CONFIG', { "failed_links_file": "ff/failed_links.txt" }):
            with patch('os.path.exists', return_value=True):
                with patch('builtins.open', mock_open(read_data="Test Channel,http://invalid.com/stream.m3u8,Invalid URL\n")):
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
    @patch('main_script.check_content_variation') # Mock check_content_variation
    @patch('subprocess.run')
    @patch('time.time') # Mock time.time
    def test_is_link_playable_success(self, mock_time, mock_run, mock_content_variation, mock_stream_info, mock_quick_check, mock_excluded_url, mock_valid_url):
        # Configure time.time to return values that result in a response_time > 0 but < max_response_time
        mock_time.side_effect = [0, 0.1, 0.2] # start_time, check_time, end_time (for calculate_response_time)
        
        mock_stream_info.return_value = ([{"codec_type": "video", "width": 1920, "height": 1080, "bit_rate": "2000000"}], None)
        mock_content_variation.return_value = (True, None) # Content variation check passes
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
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
    @patch('main_script.check_content_variation') # Mock check_content_variation
    @patch('subprocess.run')
    @patch('time.time') # Mock time.time
    def test_is_link_playable_slow_response(self, mock_time, mock_run, mock_content_variation, mock_stream_info, mock_quick_check, mock_excluded_url, mock_valid_url):
        # Configure time.time to return values that result in a response_time >= max_response_time (1.5)
        mock_time.side_effect = [0, 2.0, 2.1] # start_time, check_time, end_time
        
        mock_stream_info.return_value = ([{"codec_type": "video", "width": 1920, "height": 1080, "bit_rate": "2000000"}], None)
        mock_content_variation.return_value = (True, None) # Content variation check passes
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="",
            stderr=""
        )
        
        url = "http://valid.com/stream.m3u8"
        channel_name = "Test Channel"
        is_playable, response_time, width, bitrate, reason = is_link_playable(url, channel_name)
        
        self.assertFalse(is_playable)
        # response_time will be calculated as (2.1 - 0) = 2.1, which is >= 2
        self.assertGreaterEqual(response_time, 1.5) # Check against CONFIG['max_response_time']
        self.assertTrue(reason.startswith("Slow response"))

    @patch('main_script.is_valid_url', return_value=True)
    @patch('main_script.is_excluded_url', return_value=False)
    @patch('main_script.quick_check_url', return_value=(True, None))
    @patch('main_script.get_stream_info')
    @patch('main_script.check_content_variation') # Mock check_content_variation
    @patch('subprocess.run')
    @patch('time.time') # Mock time.time
    def test_is_link_playable_unstable(self, mock_time, mock_run, mock_content_variation, mock_stream_info, mock_quick_check, mock_excluded_url, mock_valid_url):
        # Configure time.time to return values that result in a valid response_time
        mock_time.side_effect = [0, 0.1, 0.2] # start_time, check_time, end_time
        
        mock_stream_info.return_value = ([{"codec_type": "video", "width": 1920, "height": 1080, "bit_rate": "2000000"}], None)
        # Simulate check_content_variation failing due to FFmpeg error
        mock_content_variation.return_value = (False, "FFmpeg error in content check: 403 Forbidden") 
        mock_run.return_value = subprocess.CompletedProcess(
            args=[],
            returncode=1, # Simulate FFmpeg returning an error code
            stdout="",
            stderr="403 Forbidden" # This stderr is picked up by get_stream_info or check_content_variation
        )
        
        url = "http://valid.com/unstable.m3u8"
        channel_name = "Test Channel"
        is_playable, response_time, width, bitrate, reason = is_link_playable(url, channel_name)
        
        self.assertFalse(is_playable)
        self.assertGreater(response_time, 0) # Response time should still be calculated
        self.assertEqual(width, 1920) # Stream info might still be retrieved before content check fails
        self.assertEqual(bitrate, 2000000)
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
        # Use patch on main_script.CONFIG for tests that directly reference it
        with patch('main_script.CONFIG', {
            "input_file": "list.txt", 
            "failed_links_file": "ff/failed_links.txt", 
            "checkpoint_file": "ff/checkpoint.json"
        }):
            with patch('builtins.open', mock_open(read_data="Test Channel,http://devstreaming-cdn.apple.com/videos/streaming/examples/bipbop_adv_example_hevc/master.m3u8\n")):
                with patch('main_script.load_failed_links', return_value=set()):
                    with patch('main_script.load_checkpoint', return_value={'processed_urls': [], 'valid_links': [], 'failed_links': []}):
                        links_to_check, checkpoint = read_input_file()
                        self.assertEqual(len(links_to_check), 1)
                        self.assertEqual(links_to_check[0][0], "Test Channel")
                        self.assertEqual(links_to_check[0][1], "http://devstreaming-cdn.apple.com/videos/streaming/examples/bipbop_adv_example_hevc/master.m3u8")

    def test_read_input_file_skip_failed(self):
        with patch('main_script.CONFIG', {
            "input_file": "list.txt", 
            "failed_links_file": "ff/failed_links.txt", 
            "checkpoint_file": "ff/checkpoint.json"
        }):
            with patch('builtins.open', mock_open(read_data="Test Channel,http://devstreaming-cdn.apple.com/videos/streaming/examples/bipbop_adv_example_hevc/master.m3u8\n")):
                with patch('main_script.load_failed_links', return_value={"http://devstreaming-cdn.apple.com/videos/streaming/examples/bipbop_adv_example_hevc/master.m3u8"}):
                    with patch('main_script.load_checkpoint', return_value={'processed_urls': [], 'valid_links': [], 'failed_links': []}):
                        links_to_check, checkpoint = read_input_file()
                        self.assertEqual(len(links_to_check), 0)

    def test_read_input_file_skip_excluded(self):
        with patch('main_script.CONFIG', {
            "input_file": "list.txt", 
            "failed_links_file": "ff/failed_links.txt", 
            "checkpoint_file": "ff/checkpoint.json"
        }):
            with patch('builtins.open', mock_open(read_data="Test Channel,https://epg.pw/stream.m3u8\n")):
                with patch('main_script.load_failed_links', return_value=set()):
                    with patch('main_script.load_checkpoint', return_value={'processed_urls': [], 'valid_links': [], 'failed_links': []}):
                        links_to_check, checkpoint = read_input_file()
                        self.assertEqual(len(links_to_check), 0)

    def test_write_output_file(self):
        config = {
            "output_file": "ff/ff.txt",
            "failed_links_file": "ff/failed_links.txt",
            "checkpoint_file": "ff/checkpoint.json"
        }
        # Correctly capture the mock_open object
        with patch('builtins.open', new_callable=mock_open) as mock_builtin_open:
            with patch('main_script.load_checkpoint', return_value={'processed_urls': [], 'valid_links': [], 'failed_links': []}):
                # Patch main_script.CONFIG so write_output_file uses the test's config
                with patch('main_script.CONFIG', config):
                    valid_links = [(1.0, "Test Channel,http://devstreaming-cdn.apple.com/videos/streaming/examples/bipbop_adv_example_hevc/master.m3u8")]
                    failed_links = [("Test Channel", "http://invalid.com/stream.m3u8", "Invalid URL")]
                    checkpoint = {'processed_urls': [], 'valid_links': [], 'failed_links': []}
                    success_count = write_output_file(valid_links, failed_links, checkpoint)
                    self.assertEqual(success_count, 1)
                    # Assert calls on the captured mock_builtin_open
                    mock_builtin_open.assert_any_call(config['output_file'], 'w', encoding='utf-8')
                    mock_builtin_open.assert_any_call(config['failed_links_file'], 'a', encoding='utf-8')
                    # If save_checkpoint is called with open(), you might need to assert for checkpoint_file too
                    # mock_builtin_open.assert_any_call(config['checkpoint_file'], 'w', encoding='utf-8')

    @patch('os.path.exists')
    @patch('main_script.load_config')
    @patch('main_script.read_input_file')
    @patch('main_script.write_output_file')
    @patch('main_script.load_checkpoint') # Patch load_checkpoint
    @patch('main_script.save_checkpoint') # Patch save_checkpoint
    @patch('main_script.CONFIG') # Patch CONFIG in main_script for main() function
    def test_main_success(self, mock_main_config, mock_save_checkpoint, mock_load_checkpoint, mock_write, mock_read, mock_config, mock_exists):
        # Set return value for load_config
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
        # The mocked main_script.CONFIG itself needs to be updated with the config values.
        # This is because other functions called by main() (like is_link_playable) might directly access main_script.CONFIG.
        mock_main_config.update(mock_config.return_value)

        mock_exists.return_value = True
        
        initial_checkpoint = {'processed_urls': [], 'valid_links': [], 'failed_links': []}
        mock_load_checkpoint.return_value = initial_checkpoint # Make load_checkpoint return an empty checkpoint
        mock_read.return_value = ([("Test Channel", "http://devstreaming-cdn.apple.com/videos/streaming/examples/bipbop_adv_example_hevc/master.m3u8")], initial_checkpoint)
        
        mock_write.return_value = 1
        
        # Ensure is_link_playable is correctly mocked to return success
        with patch('main_script.is_link_playable', return_value=(True, 1.0, 1920, 2000000, "Success")):
            main()
            mock_write.assert_called_once() # Verify write_output_file was called
            mock_save_checkpoint.assert_called_once() # Verify save_checkpoint was called

    @patch('os.path.exists')
    @patch('main_script.load_config')
    @patch('main_script.CONFIG') # Patch main_script.CONFIG for consistency
    def test_main_file_not_found(self, mock_main_config, mock_config, mock_exists):
        mock_config.return_value = {
            "input_file": "list.txt",
            "output_file": "ff/ff.txt",
            "failed_links_file": "ff/failed_links.txt",
            "log_file": "ff/iptv_checker.log",
            "checkpoint_file": "ff/checkpoint.json"
        }
        mock_main_config.update(mock_config.return_value) # Update the mocked CONFIG
        mock_exists.return_value = False
        with patch('logging.Logger.error') as mock_logger:
            main()
            mock_logger.assert_called_with("Input file list.txt not found.")

if __name__ == '__main__':
    unittest.main()
