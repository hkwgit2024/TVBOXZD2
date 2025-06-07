import os
import requests
import logging
import json
from datetime import datetime
import re
from urllib.parse import urlparse, urljoin
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor
import shutil
import time

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Environment variables
GITHUB_TOKEN = os.getenv('BOT')
REPO_URL = os.getenv('REPO_URL')

# Output directory and files
OUTPUT_DIR = 'data'
OUTPUT_FILE = os.path.join(OUTPUT_DIR, 'valid_urls.txt') # Changed to .txt
SUCCESS_FILE = os.path.join(OUTPUT_DIR, 'successful_urls.json')
FAILED_FILE = os.path.join(OUTPUT_DIR, 'failed_urls.json')
ERROR_LOG = os.path.join(OUTPUT_DIR, 'error_log.txt')

# Non-stream extensions to avoid
NON_STREAM_EXTENSIONS = {'.txt', '.html', '.htm', '.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.xml', '.json', '.pdf'}

def ensure_output_dir():
    """Ensures the output directory exists."""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
        logger.info(f"Created output directory: {OUTPUT_DIR}")

def load_cache(file_path):
    """Loads cache from a JSON file."""
    if os.path.exists(file_path):
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            logger.warning(f"Invalid JSON in {file_path}, starting fresh.")
    return {}

def save_cache(data, file_path):
    """Saves cache to a JSON file."""
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

def backup_output_file():
    """Backs up the existing output file (now .txt)."""
    if os.path.exists(OUTPUT_FILE):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = os.path.join(OUTPUT_DIR, f'valid_urls_backup_{timestamp}.txt') # Changed to .txt
        shutil.copy(OUTPUT_FILE, backup_path)
        logger.info(f"Backed up {OUTPUT_FILE} to {backup_path}")

def create_session():
    """Creates a requests session with retry mechanism."""
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504]) # Increased retries and backoff
    session.mount('http://', HTTPAdapter(max_retries=retries))
    session.mount('https://', HTTPAdapter(max_retries=retries))
    return session

def validate_token():
    """Validates if the GitHub token is effective."""
    if not GITHUB_TOKEN:
        logger.error("BOT environment variable is not set. Please set a valid GitHub token with 'repo' scope.")
        return False
    try:
        headers = {'Authorization': f'token {GITHUB_TOKEN}'}
        session = create_session()
        response = session.get('https://api.github.com/user', headers=headers, timeout=5) # Increased timeout
        if response.status_code == 200:
            logger.info(f"GitHub token is valid for user: {response.json().get('login')}")
            return True
        else:
            logger.error(f"Invalid GitHub token (status {response.status_code}): {response.text}")
            return False
    except requests.RequestException as e:
        logger.error(f"Failed to validate GitHub token: {str(e)}")
        return False

def fetch_urls_from_repo():
    """Fetches urls.txt from the private repository."""
    if not validate_token():
        logger.error("Cannot proceed without a valid token. Exiting.")
        return []
    if not REPO_URL:
        logger.error("REPO_URL environment variable is not set. Please set the correct URL for urls.txt.")
        return []
    
    parsed_url = urlparse(REPO_URL)
    if parsed_url.netloc == 'github.com':
        path_parts = parsed_url.path.split('/raw/')
        if len(path_parts) != 2:
            logger.error(f"Invalid REPO_URL format: {REPO_URL}. Expected format: https://github.com/owner/repo/raw/branch/path/to/urls.txt")
            return []
        raw_url = f"https://raw.githubusercontent.com{path_parts[0]}/{path_parts[1]}"
    else:
        raw_url = REPO_URL
    
    headers = {'Authorization': f'token {GITHUB_TOKEN}'}
    try:
        logger.info(f"Fetching urls.txt from {raw_url}")
        session = create_session()
        response = session.get(raw_url, headers=headers, timeout=15) # Increased timeout
        response.raise_for_status()
        urls = [line.strip() for line in response.text.splitlines() if line.strip()]
        if not urls:
            logger.warning(f"urls.txt is empty at {raw_url}. Check the file content.")
        else:
            logger.info(f"Fetched {len(urls)} URLs from urls.txt")
        return urls
    except requests.RequestException as e:
        logger.error(f"Failed to fetch urls.txt from {raw_url}: {str(e)}")
        with open(ERROR_LOG, 'a', encoding='utf-8') as f:
            f.write(f"Failed to fetch {raw_url}: {str(e)}\n")
        return []

def parse_m3u_content(content, base_url=None, playlist_name=None):
    """Parses M3U content, extracting channel name, URL, and group-title or EXTGRP."""
    lines = content.splitlines()
    channels = []
    current_extinf = None
    current_stream_inf = None
    current_extgrp = None
    stream_count = 0
    m3u_name = None
    is_vod = '#EXT-X-PLAYLIST-TYPE:VOD' in content
    max_channels_per_playlist = 100 # Limit channels per playlist to avoid excessive processing

    for line in lines:
        if stream_count >= max_channels_per_playlist:
            logger.info(f"Reached max channels ({max_channels_per_playlist}) for a playlist, stopping parsing.")
            break
        line = line.strip()
        if not line:
            continue
        if line.startswith('#EXTM3U'):
            name_match = re.search(r'name="([^"]*)"', line)
            m3u_name = name_match.group(1) if name_match else playlist_name
            continue
        elif line.startswith('#EXTINF'):
            current_extinf = line
            current_stream_inf = None
        elif line.startswith('#EXT-X-STREAM-INF'):
            current_stream_inf = line
            current_extinf = None
        elif line.startswith('#EXTGRP'):
            current_extgrp = line.replace('#EXTGRP:', '').strip()
        elif line.startswith('频道,#genre#'): # Custom format support
            try:
                parts = line.split(',', 1)
                if len(parts) == 2:
                    channel_name = parts[0].replace('频道', '').strip()
                    url = parts[1].strip()
                    channels.append((channel_name, url, '自定义'))
                    stream_count += 1
                else:
                    logger.warning(f"Invalid custom format line: {line}")
            except ValueError:
                logger.warning(f"Error parsing custom format: {line}")
            continue
        elif any(line.endswith(ext) for ext in ['.m3u8', '.ve', '.ts']) or line.startswith(('http://', 'https://', 'udp://')):
            if any(line.endswith(ext) for ext in NON_STREAM_EXTENSIONS):
                logger.debug(f"Skipping non-stream URL: {line}")
                continue

            channel_name = f"Stream_{stream_count}"
            group_title = current_extgrp or m3u_name # Default to M3U name if no other group

            if current_extinf:
                # Extract channel name from EXTINF
                name_parts = current_extinf.split(',')
                if len(name_parts) > 1:
                    channel_name = name_parts[-1].strip()
                
                # Extract group-title from EXTINF
                group_match = re.search(r'group-title="([^"]*)"', current_extinf)
                if group_match:
                    group_title = group_match.group(1)
            elif current_stream_inf:
                # Extract program ID or other info for naming from EXT-X-STREAM-INF
                program_id_match = re.search(r'PROGRAM-ID=(\d+)', current_stream_inf)
                channel_name = f"Stream_{stream_count}_{program_id_match.group(1)}" if program_id_match else f"Stream_{stream_count}"
                
                # Extract group-title from EXT-X-STREAM-INF
                group_match = re.search(r'group-title="([^"]*)"', current_stream_inf)
                if group_match:
                    group_title = group_match.group(1)

            if is_vod and '[VOD]' not in channel_name:
                channel_name += ' [VOD]'
            
            stream_url = urljoin(base_url, line) if base_url and not line.startswith(('http://', 'https://', 'udp://')) else line
            channels.append((channel_name, stream_url, group_title))
            stream_count += 1
            
            # Reset for next entry
            current_extinf = None
            current_stream_inf = None
            current_extgrp = None
        else:
            # Clear state if line doesn't match an EXTINF/EXT-X-STREAM-INF or a URL
            current_extinf = None
            current_stream_inf = None
            current_extgrp = None
            
    return channels, m3u_name

def fetch_m3u_playlist(url, success_cache, failed_cache):
    """Fetches and parses an M3U playlist."""
    if url in failed_cache and (time.time() - failed_cache[url].get('timestamp', 0) < 3600): # Cooldown for failed URLs (1 hour)
        logger.info(f"Skipping recently failed URL: {url}")
        return []
    
    # Simple check for update, not a full ETag/Last-Modified for playlist content as it's complex
    # The ETag/Last-Modified check is more effective for the urls.txt itself.
    # For sub-playlists, we'll refetch to ensure fresh content unless it's a known success.
    if url in success_cache and (time.time() - success_cache[url].get('timestamp', 0) < 3600): # Cooldown for successful URLs (1 hour)
         logger.info(f"Using cached successful data for {url}")
         return success_cache[url].get('channels', []) # Return cached channels if recent

    try:
        logger.info(f"Fetching playlist: {url}")
        session = create_session()
        headers = {'Authorization': f'token {GITHUB_TOKEN}'} if url.startswith(('https://github.com', 'https://raw.githubusercontent.com')) else {}
        response = session.get(url, headers=headers, timeout=15) # Increased timeout
        response.raise_for_status()

        base_url = url.rsplit('/', 1)[0] + '/' if '/' in url else url # Handle cases where base URL is just domain
        channels, m3u_name = parse_m3u_content(response.text, base_url, url.split('/')[-1])
        
        key_match = re.search(r'#EXT-X-KEY:METHOD=AES-128,URI="([^"]*)"', response.text)
        if key_match:
            logger.info(f"Found encryption key for playlist {url}: {key_match.group(1)}. Marking channels as [Unverified].")
            for i, (name, stream_url, group_title) in enumerate(channels):
                if '[Unverified]' not in name: # Avoid adding multiple times
                    channels[i] = (name + ' [Unverified]', stream_url, group_title)
        
        success_cache[url] = {
            'channels': channels, # Cache channels for future use
            'etag': response.headers.get('ETag', ''),
            'last_modified': response.headers.get('Last-Modified', ''),
            'timestamp': time.time()
        }
        logger.info(f"Fetched {len(channels)} channels from {url}")
        return channels
    except requests.RequestException as e:
        logger.error(f"Failed to fetch playlist {url}: {str(e)}")
        failed_cache[url] = {'reason': str(e), 'timestamp': time.time()}
        with open(ERROR_LOG, 'a', encoding='utf-8') as f:
            f.write(f"Failed to fetch {url}: {str(e)}\n")
        return []

def validate_stream_url(url, failed_cache):
    """Validates if a stream URL is accessible."""
    if any(url.lower().endswith(ext) for ext in NON_STREAM_EXTENSIONS):
        logger.debug(f"Skipping non-stream URL: {url}")
        failed_cache[url] = {'reason': 'Non-stream extension', 'timestamp': time.time()}
        return False
    if url.startswith('udp://') or 'udp/' in url.lower() or url.lower().endswith('.ts'):
        logger.debug(f"Skipping validation for UDP or .ts URL: {url}")
        return True # Assume valid for these types as HEAD requests won't work reliably
    
    # Check if URL was recently failed
    if url in failed_cache and (time.time() - failed_cache[url].get('timestamp', 0) < 3600): # Cooldown for 1 hour
        logger.debug(f"Skipping recently failed stream URL: {url}")
        return False

    try:
        session = create_session()
        response = session.head(url, timeout=5, allow_redirects=True) # Increased timeout for HEAD
        if response.status_code == 200:
            return True
        logger.warning(f"Invalid stream URL (status {response.status_code}): {url}")
        failed_cache[url] = {'reason': f'Status {response.status_code}', 'timestamp': time.time()}
        with open(ERROR_LOG, 'a', encoding='utf-8') as f:
            f.write(f"Invalid URL (status {response.status_code}): {url}\n")
        return False
    except requests.RequestException as e:
        logger.warning(f"Failed to validate stream URL {url}: {str(e)}")
        failed_cache[url] = {'reason': str(e), 'timestamp': time.time()}
        with open(ERROR_LOG, 'a', encoding='utf-8') as f:
            f.write(f"Failed to validate {url}: {str(e)}\n")
        return False

def classify_channel(channel_name, group_title=None, url=None):
    """Intelligently classifies channels, supporting non-Chinese translations and excluding music/sports."""
    # Prioritize group_title for classification, with translations
    if group_title:
        group_title_lower = group_title.lower()
        translations = {
            'общие': '综合', 'новостные': '新闻', 'фильмы': '电影', 'детские': '少儿',
            'документальные': '纪录', 'образовательные': '科教', 'развлекательные': '娱乐',
            'познавательные': '教育',
            'general': '综合', 'news': '新闻', 'movies': '电影', 'kids': '少儿',
            'documentary': '纪录', 'education': '科教', 'entertainment': '娱乐',
            'learning': '教育',
            'général': '综合', 'actualités': '新闻', 'films': '电影', 'enfants': '少儿',
            'documentaire': '纪录', 'éducation': '科教', 'divertissement': '娱乐',
            'noticias': '新闻', 'películas': '电影', 'niños': '少儿',
            'أخبار': '新闻', 'أفلام': '电影', 'أطفال': '少儿', # Arabic
            '映画': '电影', 'ニュース': '新闻', # Japanese
            'cinema': '电影', # General for cinema
        }
        
        # Exclude music and sports from group_title
        if any(keyword in group_title_lower for keyword in ['music', 'музыка', 'musique', 'música', 'sport', 'спорт', 'deportes']):
            return '其他频道'
        
        # Try to match translated group titles first
        for key, value in translations.items():
            if key in group_title_lower:
                return value
        
        # Fallback to direct group_title if no translation matches
        return group_title if group_title else '其他频道'
            
    # Fallback to channel_name and URL if no group_title
    channel_name_lower = channel_name.lower()
    url_lower = url.lower() if url else ''

    # Exclude music and sports keywords from channel_name/URL
    if any(keyword in channel_name_lower for keyword in ['music', 'mtv', 'praise_him', '30a music', 'melody', 'sport', 'espn', 'nba', 'football', 'tennis', 'racing', 'golf', 'fútbol']) or \
       any(keyword in url_lower for keyword in ['music', 'sport', 'race', 'golf']):
        return '其他频道'

    categories = {
        '综合': ['综合', 'cctv-1', 'cctv-2', 'general', 'первый канал', 'россия', 'нтв', 'твц', 'рен тв', 'ucomist', 'hd', '综合'],
        '新闻': ['news', 'cnn', 'bbc', 'cctv-13', 'abcnews', 'известия', 'россия 24', 'рбк', 'euronews', 'настоящее время', 'news'],
        '电影': ['movie', 'cinema', 'film', 'cctv-6', 'cinemax', 'hbo', 'фильмы', 'movies', 'films', 'películas', '映画'],
        '少儿': ['kids', 'children', 'cctv-14', '3abn kids', 'cartoon', 'disney', 'детские', 'enfants', 'niños', 'أطفال'],
        '科教': ['science', 'education', 'cctv-10', 'discovery', 'national geographic', 'образовательные', 'éducation', 'educación'],
        '戏曲': ['opera', 'cctv-11', 'theater', '戏曲'],
        '社会与法': ['law', 'cctv-12', 'court', 'justice', '社会与法'],
        '国防军事': ['military', 'cctv-7', 'army', 'defense', '国防军事'],
        '纪录': ['documentary', 'cctv-9', 'docu', 'history', 'документальные', 'documentaire'],
        '国外频道': ['persian', 'french', 'international', 'abtvusa', 'rtvi', 'соловиёвlive', '3abn french', 'al jazeera', 'foreign', 'international'],
        '地方频道': ['sacramento', 'local', 'cablecast', 'access sacramento', 'city', '地方'],
        '流媒体': ['stream', 'kwikmotion', '30a-tv', 'uplynk', 'jsrdn', 'darcizzle', 'beachy', 'sidewalks', 'streaming'],
        '娱乐': ['entertainment', 'развлекательные', 'fun', 'comedy', 'variety', 'divertissement'],
        '教育': ['education', 'познавательные', 'learning', 'study', 'course'],
        '其他频道': [] # Default if nothing matches
    }
    
    for category, keywords in categories.items():
        if any(keyword in channel_name_lower for keyword in keywords) or any(keyword in url_lower for keyword in keywords):
            return category
            
    return '其他频道'

def fetch_playlist_wrapper(args):
    """Wrapper function for ThreadPoolExecutor."""
    url, success_cache, failed_cache = args
    return fetch_m3u_playlist(url, success_cache, failed_cache)

def main():
    ensure_output_dir()
    backup_output_file() # Backup the .txt file
    urls_to_process = fetch_urls_from_repo()
    if not urls_to_process:
        logger.error("No URLs fetched. Exiting.")
        return
    
    success_cache = load_cache(SUCCESS_FILE)
    failed_cache = load_cache(FAILED_FILE)
    all_channels = []
    
    # Limit the number of M3U playlists to fetch to avoid excessive processing time
    # This also helps manage GitHub API rate limits if many URLs point to GitHub.
    max_playlists_to_fetch = 2 # Adjusted based on potential long runtime, can be increased if needed

    # Filter out URLs that were recently successful or failed
    filtered_urls = []
    for url in urls_to_process:
        if url in success_cache and (time.time() - success_cache[url].get('timestamp', 0) < 3600): # 1 hour cooldown
            all_channels.extend(success_cache[url]['channels'])
            logger.info(f"Using cached channels for {url}")
            continue
        if url in failed_cache and (time.time() - failed_cache[url].get('timestamp', 0) < 3600): # 1 hour cooldown
            logger.info(f"Skipping recently failed URL: {url}")
            continue
        filtered_urls.append(url)

    # Process remaining URLs with a ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=20) as executor: # Reduced max_workers for potentially better resource usage and to avoid overwhelming servers
        # Only process up to max_playlists_to_fetch new/unprocessed URLs
        results = executor.map(fetch_playlist_wrapper, [(url, success_cache, failed_cache) for url in filtered_urls[:max_playlists_to_fetch]])
        for channels in results:
            all_channels.extend(channels)
    
    if all_channels:
        unique_channels = []
        seen_channels = set()
        for name, url, group_title in all_channels:
            key = (name.lower(), url)
            if key not in seen_channels:
                seen_channels.add(key)
                unique_channels.append((name, url, group_title))
        
        classified = {}
        valid_count = 0
        
        # Validate individual stream URLs in parallel
        stream_validation_tasks = []
        for name, url, group_title in unique_channels:
            stream_validation_tasks.append((name, url, group_title, failed_cache))

        # Use a new ThreadPoolExecutor for stream URL validation
        with ThreadPoolExecutor(max_workers=40) as executor: # Can use more workers for URL validation as it's typically faster HEAD requests
            validation_results = executor.map(lambda p: (p[0], p[1], p[2], validate_stream_url(p[1], p[3])), stream_validation_tasks)
            
            for name, url, group_title, is_valid in validation_results:
                if is_valid:
                    category = classify_channel(name, group_title, url)
                    if category not in classified:
                        classified[category] = []
                    classified[category].append((name, url))
                    valid_count += 1
                    logger.debug(f"Valid URL: {name}, {url}, Category: {category}") # Use debug for high volume logging
                else:
                    logger.warning(f"Invalid URL: {name}, {url}")
        
        if valid_count > 0:
            with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
                f.write('#EXTM3U\n') # Still write EXTM3U for compatibility with M3U players if they load .txt
                f.write('更新时间,#genre#\n')
                f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')},http://example.com/placeholder.m3u8\n") # Combined date and time, added placeholder URL
                f.write('# Note: [VOD] indicates Video on Demand streams, which may require specific clients (e.g., VLC, Kodi).\n')
                f.write('# Note: [Unverified] indicates streams with potentially inaccessible encryption keys.\n')
                
                # Sort categories for consistent output
                for category in sorted(classified.keys()):
                    if classified[category]:
                        f.write(f"\n{category},#genre#\n") # Add a newline for better readability between categories
                        for name, url in classified[category]:
                            f.write(f"{name},{url}\n")
            
            logger.info(f"Saved {valid_count} valid URLs to {OUTPUT_FILE}")
            logger.info(f"Categories found: {', '.join(sorted(classified.keys()))}")
        else:
            logger.error("No valid channels found, retaining previous output file.")
        
        save_cache(success_cache, SUCCESS_FILE)
        save_cache(failed_cache, FAILED_FILE)
    else:
        logger.error("No channels processed or found, retaining previous output file.")

if __name__ == "__main__":
    start_time = time.time()
    main()
    end_time = time.time()
    logger.info(f"Script finished in {end_time - start_time:.2f} seconds.")
