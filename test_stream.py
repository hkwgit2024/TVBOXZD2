import os
import subprocess
import re
import datetime

def test_stream(url, output_dir="output"):
    """
    Tests a single video stream using ffprobe and saves the output.
    """
    # Sanitize URL to create a valid filename
    filename = re.sub(r'[^a-zA-Z0-9.-]', '_', url).replace('__', '_')
    if len(filename) > 200: # Limit filename length
        filename = filename[:200] + "_hash" + str(hash(url) % 10000)

    output_path = os.path.join(output_dir, f"{filename}.json")
    error_path = os.path.join(output_dir, f"{filename}_error.log")

    try:
        command = [
            "ffprobe",
            "-v", "quiet",
            "-print_format", "json",
            "-show_format",
            "-show_streams",
            url
        ]
        
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(result.stdout)
        print(f"Successfully tested {url}. Output saved to {output_path}")

    except subprocess.CalledProcessError as e:
        with open(error_path, "w", encoding="utf-8") as f:
            f.write(f"Error testing {url}:\n")
            f.write(f"Command: {' '.join(e.cmd)}\n")
            f.write(f"Return Code: {e.returncode}\n")
            f.write(f"STDOUT:\n{e.stdout}\n")
            f.write(f"STDERR:\n{e.stderr}\n")
        print(f"Error testing {url}. Error log saved to {error_path}")
    except Exception as e:
        with open(error_path, "w", encoding="utf-8") as f:
            f.write(f"An unexpected error occurred for {url}:\n")
            f.write(str(e))
        print(f"An unexpected error occurred for {url}. Error log saved to {error_path}")

def parse_iptv_list(file_content):
    """
    Parses the IPTV list content and extracts channel names and URLs.
    """
    channels = []
    lines = file_content.splitlines()
    for line in lines:
        line = line.strip()
        if not line or line.startswith(('#', '更新时间')):
            continue
        
        parts = line.split(',', 1) # Split only on the first comma
        if len(parts) == 2:
            channel_name = parts[0].strip()
            url = parts[1].strip()
            # Basic URL validation
            if url.startswith(('http://', 'https://', 'rtp://', 'udp://')):
                channels.append((channel_name, url))
    return channels

def main():
    script_dir = os.path.dirname(__file__)
    iptv_list_path = os.path.join(script_dir, "iptv_list.txt")
    output_dir = os.path.join(script_dir, "output")

    os.makedirs(output_dir, exist_ok=True)

    try:
        with open(iptv_list_path, "r", encoding="utf-8") as f:
            iptv_content = f.read()
    except FileNotFoundError:
        print(f"Error: {iptv_list_path} not found. Please make sure the iptv_list.txt file is in the same directory as the script.")
        return

    channels = parse_iptv_list(iptv_content)

    if not channels:
        print("No valid video sources found in iptv_list.txt.")
        return

    print(f"Found {len(channels)} channels to test.")
    for i, (name, url) in enumerate(channels):
        print(f"Testing channel {i+1}/{len(channels)}: {name} - {url}")
        test_stream(url, output_dir)
    print("Testing complete.")

if __name__ == "__main__":
    main()
