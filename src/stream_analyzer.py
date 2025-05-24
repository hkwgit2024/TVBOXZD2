# src/stream_analyzer.py

import subprocess
import time
import re
import logging
from urllib.parse import urlparse
import sys

# Ensure ffprobe is available in PATH
# This check is also in main_quality_checker.py, but good to have here for direct module usage
def check_ffmpeg_availability():
    try:
        subprocess.run(['ffprobe', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2)
        subprocess.run(['ffmpeg', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False

# Load config values (ensure they are available)
# These will be loaded from config.quality_config when imported by main_quality_checker.py
# For standalone testing, you might need to mock or define them
try:
    from config.quality_config import STREAM_CHECK_TIMEOUT_SECONDS, STREAM_CHECK_DURATION_SECONDS
except ImportError:
    logging.warning("Could not import STREAM_CHECK_TIMEOUT_SECONDS/DURATION from config.quality_config. Using default values.")
    STREAM_CHECK_TIMEOUT_SECONDS = 15
    STREAM_CHECK_DURATION_SECONDS = 5


def check_stream_quality(url, channel_name):
    """
    Performs a deep quality check on a given stream URL using ffprobe and ffmpeg.
    Returns a dictionary with quality metrics.
    """
    results = {
        'channel_name': channel_name,
        'channel_url': url,
        'metrics': {
            'is_playable': False,
            'initial_buffer_ms': float('inf'),
            'resolution': '0x0', # Default to 0x0 for easier sorting (lower resolution)
            'bitrate_kbps': 0.0,
            'dropped_frames_percentage': float('inf'), # High value means bad
            'avg_speed_multiplier': 0.0,
            'error_message': ''
        }
    }
    
    start_time = time.time()
    
    try:
        # --- Stage 1: Initial probe for playability and metadata (Resolution, Bitrate) ---
        probe_command = [
            'ffprobe', '-v', 'error',
            '-rw_timeout', str(STREAM_CHECK_TIMEOUT_SECONDS * 1000000), # Timeout in microseconds
            '-analyzeduration', str(STREAM_CHECK_DURATION_SECONDS * 1000000), # Analyze duration in microseconds
            '-probesize', str(STREAM_CHECK_DURATION_SECONDS * 1000000), # Probesize in bytes
            '-select_streams', 'v:0', # Select first video stream
            '-show_entries', 'stream=width,height,bit_rate,avg_frame_rate',
            '-of', 'default=noprint_wrappers=1:nokey=1',
            url
        ]
        
        probe_process = subprocess.run(
            probe_command, 
            capture_output=True, 
            text=True, 
            timeout=STREAM_CHECK_TIMEOUT_SECONDS,
            errors='ignore' # Handle potential decoding errors in output
        )
        
        if probe_process.returncode == 0:
            results['metrics']['is_playable'] = True
            lines = probe_process.stdout.strip().split('\n')
            
            try:
                # Expecting width, height, bit_rate, avg_frame_rate on separate lines
                if len(lines) >= 3:
                    width = int(lines[0])
                    height = int(lines[1])
                    bit_rate = int(lines[2])
                    
                    results['metrics']['resolution'] = f"{width}x{height}"
                    results['metrics']['bitrate_kbps'] = round(bit_rate / 1000, 2)
                    results['metrics']['initial_buffer_ms'] = (time.time() - start_time) * 1000
                else:
                    results['metrics']['error_message'] += " (ffprobe metadata incomplete)"
                    logging.debug(f"ffprobe for {url} returned incomplete metadata: {lines}")
            except ValueError:
                results['metrics']['error_message'] += " (ffprobe output parse error)"
                logging.debug(f"Failed to parse ffprobe output for {url}: {lines}")
        else:
            results['metrics']['error_message'] = f"FFprobe failed to connect or parse stream ({probe_process.returncode}): {probe_process.stderr.strip()}"
            logging.debug(f"FFprobe failed for {url}: {probe_process.stderr.strip()}")
            return results # No need to proceed to ffmpeg if ffprobe already failed

        # --- Stage 2: (Optional) Actual Decoding & Monitoring for Dropped Frames/Speed ---
        # This part is more resource-intensive and can be enabled/disabled as needed.
        # It requires FFmpeg to be installed.
        
        # skip_decoding_check = True # Set to False to enable decoding check
        # if not skip_decoding_check and check_ffmpeg_availability(): # Check for ffmpeg again
        #     monitor_command = [
        #         'ffmpeg', '-i', url,
        #         '-t', str(STREAM_CHECK_DURATION_SECONDS), # Process for this duration
        #         '-f', 'null', '-', # Output to null device
        #         '-vstats', # Enable video statistics
        #         '-progress', 'pipe:1' # Print progress info to stdout
        #     ]
            
        #     monitor_process = subprocess.Popen(
        #         monitor_command, 
        #         stdout=subprocess.PIPE, 
        #         stderr=subprocess.PIPE, 
        #         text=True, 
        #         bufsize=1, # Line-buffered output
        #         errors='ignore'
        #     )
            
        #     total_frames = 0
        #     dropped_frames = 0
        #     total_speed = 0.0
        #     speed_count = 0

        #     try:
        #         for line in monitor_process.stdout:
        #             if line.startswith('frame='):
        #                 try:
        #                     frame_match = re.search(r'frame=\s*(\d+)', line)
        #                     if frame_match:
        #                         total_frames = int(frame_match.group(1))
        #                 except Exception: pass
        #             elif line.startswith('drop='):
        #                 try:
        #                     drop_match = re.search(r'drop=(\d+)', line)
        #                     if drop_match:
        #                         dropped_frames = int(drop_match.group(1))
        #                 except Exception: pass
        #             elif line.startswith('speed='):
        #                 try:
        #                     speed_match = re.search(r'speed=\s*(\d+\.?\d*)x', line)
        #                     if speed_match:
        #                         current_speed = float(speed_match.group(1))
        #                         total_speed += current_speed
        #                         speed_count += 1
        #                 except Exception: pass
        #         
        #         monitor_process.wait(timeout=STREAM_CHECK_TIMEOUT_SECONDS + 5) # Wait for process to finish
        #     except subprocess.TimeoutExpired:
        #         monitor_process.kill()
        #         results['metrics']['error_message'] += " (Decoding monitor timeout)"
        #         logging.warning(f"Decoding monitor for {url} timed out.")
        #     
        #     if total_frames > 0:
        #         results['metrics']['dropped_frames_percentage'] = (dropped_frames / total_frames) * 100
        #     if speed_count > 0:
        #         results['metrics']['avg_speed_multiplier'] = total_speed / speed_count
        #     else:
        #         results['metrics']['error_message'] += " (No speed/frame data from monitor)"
        # else:
        #     if not check_ffmpeg_availability():
        #         results['metrics']['error_message'] += " (FFmpeg not available for full quality check)"
        #     else:
        #         results['metrics']['error_message'] += " (Decoding check skipped)"

    except subprocess.CalledProcessError as e:
        results['metrics']['error_message'] = f"FFmpeg/FFprobe command failed with code {e.returncode}: {e.stderr.strip()}"
        logging.debug(f"Command failed for {url}: {e.cmd}\nStdout: {e.stdout}\nStderr: {e.stderr}")
    except subprocess.TimeoutExpired:
        results['metrics']['error_message'] = "Stream check timed out."
        logging.debug(f"Stream check for {url} timed out.")
    except FileNotFoundError:
        results['metrics']['error_message'] = "FFmpeg or FFprobe not found. Ensure FFmpeg is installed and in PATH."
        logging.error(f"FFmpeg/FFprobe not found during check for {url}.")
    except Exception as e:
        results['metrics']['error_message'] = f"An unexpected error occurred during check: {e}"
        logging.error(f"Unexpected error for {url}: {e}", exc_info=True)

    return results
