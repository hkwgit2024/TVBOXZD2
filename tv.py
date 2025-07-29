import asyncio
import aiohttp
import aiofiles
import re
import logging
import yaml
import dns.resolver
import os
import psutil
import subprocess
from datetime import datetime
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from urllib.parse import urlparse
from tqdm import tqdm
import sys
import time
import traceback

# Configure logging with maximum verbosity for debugging and tracking every step
logging.basicConfig(
    level=logging.DEBUG,  # Use DEBUG level to capture all possible logs
    format='%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
    handlers=[
        logging.FileHandler('iptv_crawler.log', encoding='utf-8', mode='a'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

class IPTVScraper:
    def __init__(self, config_file='config/config.yaml'):
        """
        Initialize the IPTVScraper with configuration settings and setup necessary directories.
        
        Args:
            config_file (str): Path to the YAML configuration file containing URLs and settings.
        """
        logger.debug("Initializing IPTVScraper with config file: %s", config_file)
        self.config_file = config_file
        self.config = self.load_config()
        self.urls = self.config.get('urls', [])
        self.output_dir = self.config.get('output_dir', 'output')
        self.temp_dir = self.config.get('temp_dir', 'temp_channels')
        self.regional_dir = self.config.get('regional_dir', '地方频道')
        self.max_concurrent_requests = self.config.get('max_concurrent_requests', 10)
        self.channels = []  # Store all extracted channels
        self.valid_channels = []  # Store validated channels
        self.semaphore = asyncio.Semaphore(self.max_concurrent_requests)
        self.start_time = datetime.now()
        
        # Log system information for debugging
        logger.debug("System information: Python %s, Platform: %s", sys.version, sys.platform)
        logger.debug("Initial CPU usage: %s%%", psutil.cpu_percent())
        logger.debug("Initial memory usage: %s MB", psutil.virtual_memory().used / 1024 / 1024)

        # Create necessary directories with error handling
        for directory in [self.output_dir, self.temp_dir, self.regional_dir]:
            try:
                os.makedirs(directory, exist_ok=True)
                logger.debug("Created or verified directory: %s", directory)
            except Exception as e:
                logger.error("Failed to create directory %s: %s", directory, str(e))
                raise

    def load_config(self):
        """
        Load the configuration from the specified YAML file.
        
        Returns:
            dict: Configuration dictionary with URLs and settings.
        """
        logger.debug("Attempting to load configuration from %s", self.config_file)
        try:
            with open(self.config_file, 'r', encoding='utf-8') as file:
                config = yaml.safe_load(file)
                if not config:
                    logger.error("Configuration file %s is empty or invalid", self.config_file)
                    return {}
                logger.info("Successfully loaded configuration with %d URLs", len(config.get('urls', [])))
                return config
        except FileNotFoundError:
            logger.error("Configuration file %s not found", self.config_file)
            return {}
        except yaml.YAMLError as e:
            logger.error("Failed to parse YAML file %s: %s", self.config_file, str(e))
            return {}
        except Exception as e:
            logger.error("Unexpected error loading config file %s: %s", self.config_file, str(e))
            return {}

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
        retry=retry_if_exception_type(Exception),
        before_sleep=lambda retry_state: logger.debug(
            "Retrying fetch_url (attempt %d/%d) for URL: %s",
            retry_state.attempt_number, 3, retry_state.args[1]
        )
    )
    async def fetch_url(self, session, url):
        """
        Fetch content from a URL with retries and semaphore control for concurrency limiting.
        
        Args:
            session (aiohttp.ClientSession): HTTP session for making requests.
            url (str): URL to fetch content from.
            
        Returns:
            str: Content of the URL if successful, None otherwise.
        """
        logger.debug("Fetching URL: %s", url)
        try:
            async with self.semaphore:
                async with session.get(url, timeout=10) as response:
                    logger.debug("Received response for %s: Status %d", url, response.status)
                    if response.status == 200:
                        content = await response.text()
                        logger.info("Successfully fetched %d bytes from %s", len(content), url)
                        return content
                    else:
                        logger.warning("Non-200 status code %d for URL: %s", response.status, url)
                        return None
        except aiohttp.ClientError as e:
            logger.error("Client error fetching URL %s: %s", url, str(e))
            raise
        except asyncio.TimeoutError:
            logger.error("Timeout fetching URL: %s", url)
            raise
        except Exception as e:
            logger.error("Unexpected error fetching URL %s: %s", url, str(e))
            raise

    async def resolve_url(self, url):
        """
        Resolve the domain of a URL using DNS to ensure it's accessible.
        
        Args:
            url (str): URL to resolve.
            
        Returns:
            bool: True if domain resolves successfully, False otherwise.
        """
        logger.debug("Resolving URL: %s", url)
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        if not domain:
            logger.error("Invalid URL format, no domain found: %s", url)
            return False
        
        try:
            answers = dns.resolver.resolve(domain, 'A')
            logger.debug("DNS resolution successful for %s: %s", domain, [str(a) for a in answers])
            return True
        except dns.resolver.NXDOMAIN:
            logger.warning("DNS resolution failed: Domain %s does not exist", domain)
            return False
        except dns.resolver.Timeout:
            logger.warning("DNS resolution timeout for domain: %s", domain)
            return False
        except Exception as e:
            logger.error("Unexpected error resolving domain %s: %s", domain, str(e))
            return False

    async def check_channel_validity(self, channel):
        """
        Validate a channel URL using ffmpeg to check if the stream is accessible.
        
        Args:
            channel (dict): Channel dictionary containing 'url' and 'name' keys.
            
        Returns:
            bool: True if the channel is valid, False otherwise.
        """
        url = channel.get('url')
        name = channel.get('name', 'Unknown')
        logger.debug("Validating channel: %s (%s)", name, url)
        
        if not url:
            logger.warning("Channel has no URL: %s", name)
            return False

        if not await self.resolve_url(url):
            logger.warning("Skipping validation for %s due to DNS resolution failure", url)
            return False

        try:
            process = await asyncio.create_subprocess_exec(
                'ffmpeg', '-i', url, '-t', '5', '-f', 'null', '-',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=15)
            if process.returncode == 0:
                logger.info("Channel %s (%s) is valid", name, url)
                return True
            else:
                logger.warning("Channel %s (%s) validation failed: %s", name, url, stderr.decode())
                return False
        except asyncio.TimeoutError:
            logger.warning("Validation timeout for channel %s (%s)", name, url)
            return False
        except FileNotFoundError:
            logger.error("FFmpeg not found on system. Please ensure FFmpeg is installed.")
            return False
        except Exception as e:
            logger.error("Unexpected error validating channel %s (%s): %s", name, url, str(e))
            return False

    async def extract_channels(self, session, url, index, total_urls):
        """
        Extract channels from the content of a URL (e.g., M3U playlist).
        
        Args:
            session (aiohttp.ClientSession): HTTP session for fetching URLs.
            url (str): URL to process.
            index (int): Current URL index for progress tracking.
            total_urls (int): Total number of URLs being processed.
        """
        logger.debug("Processing URL %d/%d: %s", index + 1, total_urls, url)
        
        if not await self.resolve_url(url):
            logger.warning("Skipping URL %s due to DNS resolution failure", url)
            return

        try:
            content = await self.fetch_url(session, url)
            if not content:
                logger.warning("No content retrieved from URL: %s", url)
                return

            lines = content.splitlines()
            current_channel = {}
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                if line.startswith('#EXTINF'):
                    match = re.search(r'tvg-name="([^"]+)"', line)
                    if match:
                        current_channel['name'] = match.group(1)
                        logger.debug("Found channel name: %s", current_channel['name'])
                    else:
                        logger.debug("No tvg-name found in EXTINF line: %s", line)
                elif line.startswith('http'):
                    current_channel['url'] = line
                    if 'name' in current_channel:
                        self.channels.append(current_channel.copy())
                        logger.debug("Added channel: %s (%s)", current_channel['name'], current_channel['url'])
                        current_channel = {}
                    else:
                        logger.debug("Found URL without name: %s", line)
            logger.warning("Processed %d/%d URLs for channel extraction", index + 1, total_urls)
        except Exception as e:
            logger.error("Error processing content from %s: %s", url, str(e))
            logger.debug("Traceback: %s", traceback.format_exc())

    async def process_channels(self):
        """
        Process all URLs to extract and validate channels.
        """
        logger.info("Starting channel extraction from %d URLs", len(self.urls))
        async with aiohttp.ClientSession() as session:
            tasks = []
            for i, url in enumerate(self.urls):
                tasks.append(self.extract_channels(session, url, i, len(self.urls)))
            await asyncio.gather(*tasks, return_exceptions=True)

        logger.warning("Finished channel extraction. Total channels extracted before filtering: %d", len(self.channels))

        # Filter and deduplicate channels
        seen_urls = set()
        unique_channels = []
        for channel in self.channels:
            url = channel.get('url')
            name = channel.get('name', 'Unknown')
            if url and url not in seen_urls:
                seen_urls.add(url)
                unique_channels.append(channel)
                logger.debug("Kept unique channel: %s (%s)", name, url)
            else:
                logger.debug("Discarded duplicate or invalid channel: %s (%s)", name, url)

        self.channels = unique_channels
        logger.warning("Total channels after filtering and deduplication: %d", len(self.channels))

        # Validate channels with progress bar
        logger.warning("Starting multithreaded channel validity and speed detection for %d channels...", len(self.channels))
        valid_channels = []
        for channel in tqdm(self.channels, desc="Validating channels", unit="channel"):
            if await self.check_channel_validity(channel):
                valid_channels.append(channel)

        self.valid_channels = valid_channels
        logger.warning("Total valid channels after validation: %d", len(self.valid_channels))

    def categorize_channels(self):
        """
        Categorize channels into CCTV, regional, and uncategorized groups based on channel names.
        
        Returns:
            dict: Dictionary with categorized channels.
        """
        logger.debug("Categorizing %d valid channels", len(self.valid_channels))
        categorized = {
            'CCTV': [],
            '地方': [],
            'uncategorized': []
        }
        regional_keywords = [
            '北京', '上海', '广东', '浙江', '江苏', '山东', '四川', '湖南', '湖北', '河南',
            '重庆', '安徽', '福建', '甘肃', '广西', '贵州', '海南', '河北', '黑龙江', '江西',
            '吉林', '辽宁', '内蒙古', '宁夏', '青海', '山西', '陕西', '天津', '新疆', '云南'
        ]

        for channel in self.valid_channels:
            name = channel.get('name', '').lower()
            logger.debug("Categorizing channel: %s", name)
            if 'cctv' in name:
                categorized['CCTV'].append(channel)
                logger.debug("Assigned to CCTV: %s", name)
            elif any(keyword.lower() in name for keyword in regional_keywords):
                categorized['地方'].append(channel)
                logger.debug("Assigned to 地方: %s", name)
            else:
                categorized['uncategorized'].append(channel)
                logger.debug("Assigned to uncategorized: %s", name)

        logger.debug("Categorization results: CCTV=%d, 地方=%d, uncategorized=%d",
                     len(categorized['CCTV']), len(categorized['地方']), len(categorized['uncategorized']))
        return categorized

    async def save_channels(self):
        """
        Save categorized channels to respective files and create a merged channel list.
        """
        logger.debug("Starting channel saving process")
        categorized = self.categorize_channels()
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        logger.debug("Generated timestamp for output files: %s", timestamp)

        # Save categorized channels to individual files
        for category, channels in categorized.items():
            logger.warning("Processing category: %s with %d channels", category, len(channels))
            output_file = os.path.join(self.output_dir, f"{category}_iptv.txt")
            try:
                async with aiofiles.open(output_file, 'w', encoding='utf-8') as file:
                    await file.write(f"更新时间,{timestamp},#genre#\n")
                    for channel in channels:
                        name = channel.get('name', 'Unknown')
                        url = channel.get('url', '')
                        await file.write(f"{name},{url}\n")
                        logger.debug("Wrote channel to %s: %s (%s)", output_file, name, url)
                logger.info("Successfully saved %d channels to %s", len(channels), output_file)
            except Exception as e:
                logger.error("Failed to save channels to %s: %s", output_file, str(e))

        # Save uncategorized channels separately
        uncategorized_file = os.path.join(self.output_dir, 'uncategorized_iptv.txt')
        logger.warning("Processing uncategorized channels: %d channels", len(categorized['uncategorized']))
        try:
            async with aiofiles.open(uncategorized_file, 'w', encoding='utf-8') as file:
                await file.write(f"更新时间,{timestamp},#genre#\n")
                for channel in categorized['uncategorized']:
                    name = channel.get('name', 'Unknown')
                    url = channel.get('url', '')
                    await file.write(f"{name},{url}\n")
                    logger.debug("Wrote uncategorized channel: %s (%s)", name, url)
            logger.info("Uncategorized channels saved to: %s", uncategorized_file)
        except Exception as e:
            logger.error("Failed to save uncategorized channels to %s: %s", uncategorized_file, str(e))

        # Merge all channels into a single iptv_list.txt
        all_channels = []
        for category, channels in categorized.items():
            all_channels.extend(channels)
            logger.debug("Merged %d channels from category %s", len(channels), category)

        # Deduplicate merged channels
        seen_urls = set()
        unique_channels = []
        for channel in all_channels:
            url = channel.get('url')
            name = channel.get('name', 'Unknown')
            if url and url not in seen_urls:
                seen_urls.add(url)
                unique_channels.append(channel)
                logger.debug("Kept unique channel for iptv_list.txt: %s (%s)", name, url)
            else:
                logger.debug("Discarded duplicate channel: %s (%s)", name, url)

        output_file = os.path.join(self.output_dir, 'iptv_list.txt')
        logger.warning("Total unique channels to check and filter for iptv_list.txt: %d", len(unique_channels))
        try:
            async with aiofiles.open(output_file, 'w', encoding='utf-8') as file:
                await file.write(f"更新时间,{timestamp},#genre#\n")
                for channel in unique_channels:
                    name = channel.get('name', 'Unknown')
                    url = channel.get('url', '')
                    await file.write(f"{name},{url}\n")
                    logger.debug("Wrote channel to iptv_list.txt: %s (%s)", name, url)
            logger.warning("All regional channel list files merged, deduplicated, and cleaned. Output saved to: %s", output_file)
        except Exception as e:
            logger.error("Failed to save merged channels to %s: %s", output_file, str(e))

    async def main(self):
        """
        Main execution method to run the entire scraping process.
        """
        logger.info("Starting IPTV scraper execution")
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024
        initial_cpu = psutil.cpu_percent()
        logger.info("Initial system resources - Memory: %.2f MB, CPU: %.2f%%", initial_memory, initial_cpu)

        try:
            await self.process_channels()
            await self.save_channels()
        except Exception as e:
            logger.error("Critical error in main execution: %s", str(e))
            logger.debug("Traceback: %s", traceback.format_exc())
        finally:
            final_memory = process.memory_info().rss / 1024 / 1024
            final_cpu = psutil.cpu_percent()
            execution_time = (datetime.now() - self.start_time).total_seconds()
            logger.info("Final system resources - Memory: %.2f MB, CPU: %.2f%%", final_memory, final_cpu)
            logger.info("Total execution time: %.2f seconds", execution_time)
            logger.warning("IPTV processing script finished")

if __name__ == "__main__":
    logger.debug("Script started")
    try:
        scraper = IPTVScraper()
        asyncio.run(scraper.main())
    except KeyboardInterrupt:
        logger.warning("Script terminated by user interruption")
        sys.exit(1)
    except Exception as e:
        logger.error("Fatal error in script execution: %s", str(e))
        logger.debug("Traceback: %s", traceback.format_exc())
        sys.exit(1)
    finally:
        logger.debug("Script execution completed")
