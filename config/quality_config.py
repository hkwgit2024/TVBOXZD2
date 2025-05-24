# config/quality_config.py

# Source file from your main IPTV script (e.g., iptv.txt, iptv_speed.txt, or iptv_list.txt)
SOURCE_IPTV_FILE = "../iptv_list.txt" # Adjust this path relative to main_quality_checker.py

# Output file for the filtered high-quality IPTV list
OUTPUT_FILTERED_IPTV_FILE = "../iptv_high_quality.txt"

# Log file for the quality checker
LOG_FILE = "quality_checker.log"

# --- FFmpeg/ffprobe related configurations ---
# Maximum concurrent FFmpeg/ffprobe processes.
# Adjust this based on your system's CPU/RAM/Network. Lower numbers are safer.
MAX_QUALITY_CHECK_WORKERS = 5 # Example: Allow 5 concurrent checks

# Overall timeout for each stream check in seconds.
# If FFmpeg/ffprobe doesn't respond within this time, the check fails.
STREAM_CHECK_TIMEOUT_SECONDS = 15

# Duration in seconds for FFmpeg/ffprobe to analyze/decode the stream.
# A longer duration gives more reliable quality metrics but takes longer.
STREAM_CHECK_DURATION_SECONDS = 5

# --- Filtering and Sorting ---
# Maximum number of URLs to keep per channel name in the final output.
# URLs are sorted by quality (resolution, dropped frames, buffer time).
CHANNELS_PER_NAME_LIMIT = 5

# Add more specific filters here if needed, e.g., resolution thresholds
# MIN_RESOLUTION_HEIGHT = 720 # Example: Only keep channels >= 720p
