import os
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime

# Import modules from src
from src.stream_analyzer import check_stream_quality
from src.utils import read_txt_to_array, write_array_to_txt
from config.quality_config import (
    SOURCE_IPTV_FILE, OUTPUT_FILTERED_IPTV_FILE, LOG_FILE,
    MAX_QUALITY_CHECK_WORKERS, STREAM_CHECK_TIMEOUT_SECONDS,
    STREAM_CHECK_DURATION_SECONDS, CHANNELS_PER_NAME_LIMIT
)

# --- Configure logging ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler()
    ]
)

def main():
    logging.info("--- Starting IPTV Stream Quality Checker ---")
    logging.info(f"Source IPTV list: {SOURCE_IPTV_FILE}")
    logging.info(f"Output filtered IPTV list: {OUTPUT_FILTERED_IPTV_FILE}")
    logging.info(f"Max concurrent quality checks: {MAX_QUALITY_CHECK_WORKERS}")

    # Check for FFmpeg/ffprobe availability
    try:
        subprocess.run(['ffprobe', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2)
        subprocess.run(['ffmpeg', '-h'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=2)
        logging.info("FFmpeg and FFprobe found in PATH.")
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        logging.error("FFmpeg/FFprobe not found or not working correctly. Please ensure FFmpeg is installed and accessible in your system's PATH.")
        logging.error("Exiting. Cannot perform stream quality checks without FFmpeg.")
        return

    if not os.path.exists(SOURCE_IPTV_FILE):
        logging.error(f"Source IPTV file '{SOURCE_IPTV_FILE}' not found. Please ensure your main script has generated it.")
        return

    lines_to_check = read_txt_to_array(SOURCE_IPTV_FILE)
    if not lines_to_check:
        logging.info(f"No channels found in '{SOURCE_IPTV_FILE}' to check. Exiting.")
        return

    logging.info(f"Starting deep quality check for {len(lines_to_check)} channels...")

    quality_results = []
    
    # Use a ThreadPoolExecutor for concurrent stream analysis
    with ThreadPoolExecutor(max_workers=MAX_QUALITY_CHECK_WORKERS) as executor:
        futures = {
            executor.submit(
                check_stream_quality, 
                url_line.split(',', 1)[1].strip(), # Extract URL
                url_line.split(',', 1)[0].strip()  # Extract Channel Name
            ): url_line for url_line in lines_to_check if ',' in url_line and '://' in url_line
        }
        
        processed_count = 0
        total_channels = len(futures) # Only count valid lines submitted

        for future in as_completed(futures):
            processed_count += 1
            original_line = futures[future]
            try:
                channel_data = future.result()
                if channel_data and channel_data['metrics']['is_playable']:
                    quality_results.append(channel_data)
                    logging.info(f"PASS ({processed_count}/{total_channels}): {channel_data['channel_name']}, Res: {channel_data['metrics']['resolution']}, Buffer: {channel_data['metrics']['initial_buffer_ms']:.0f}ms")
                else:
                    status_msg = "FAIL"
                    error_msg = channel_data['metrics']['error_message'] if channel_data else "Unknown error"
                    logging.warning(f"{status_msg} ({processed_count}/{total_channels}): {original_line} - Reason: {error_msg}")
            except Exception as exc:
                logging.error(f"Error processing channel '{original_line}': {exc}")
            
            if processed_count % 50 == 0 or processed_count == total_channels:
                logging.info(f"--- Progress: {processed_count}/{total_channels} channels checked ---")

    logging.info("\n--- Quality check phase completed. ---")
    logging.info(f"Found {len(quality_results)} playable channels.")

    # Group channels by name and apply quality-based sorting/filtering
    quality_ranked_channels_map = {}
    for item in quality_results:
        name = item['channel_name']
        if name not in quality_ranked_channels_map:
            quality_ranked_channels_map[name] = []
        quality_ranked_channels_map[name].append(item)

    selected_channels_for_output = []
    for name, channel_data_list in quality_ranked_channels_map.items():
        # Sort by: Playable (True first) -> Resolution (Height, descending) -> Dropped Frames (Ascending) -> Initial Buffer (Ascending)
        channel_data_list.sort(key=lambda x: (
            not x['metrics']['is_playable'],
            -(int(x['metrics']['resolution'].split('x')[1]) if 'x' in x['metrics']['resolution'] and x['metrics']['resolution'].split('x')[1].isdigit() else 0),
            x['metrics']['dropped_frames_percentage'],
            x['metrics']['initial_buffer_ms']
        ))
        
        # Select the top N channels based on quality for this channel name
        unique_urls_added = set()
        for data in channel_data_list:
            if len(selected_channels_for_output) >= CHANNELS_PER_NAME_LIMIT:
                break # Limit total channels per name for output

            # Ensure URL is unique for this channel name in the final list
            if data['channel_url'] not in unique_urls_added:
                selected_channels_for_output.append(f"{data['channel_name']},{data['channel_url']}")
                unique_urls_added.add(data['channel_url'])

    # Add an update timestamp
    now = datetime.now()
    update_time_header = [
        f"更新时间,#genre#\n",
        f"{now.strftime('%Y-%m-%d')},url\n",
        f"{now.strftime('%H:%M:%S')},url\n"
    ]
    
    # Sort final selected channels alphabetically by channel name
    selected_channels_for_output_sorted = sorted(selected_channels_for_output, key=lambda x: x.split(',')[0].strip())

    # Write the final high-quality IPTV list
    final_output_content = update_time_header + [line + '\n' for line in selected_channels_for_output_sorted]
    
    write_array_to_txt(OUTPUT_FILTERED_IPTV_FILE, final_output_content, append=False)
    logging.info(f"\nFinal high-quality IPTV list with {len(selected_channels_for_output)} channels saved to: {OUTPUT_FILTERED_IPTV_FILE}")
    logging.info("--- IPTV Stream Quality Checker Finished ---")

if __name__ == "__main__":
    import subprocess # Import here for the initial check in main()
    main()
