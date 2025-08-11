#整合
import json
import os
import sys
import logging
from typing import List, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

def merge_tvbox_configs(source_dir: str, output_file: str) -> None:
    """
    Traverses a directory of JSON files, merges TVbox configurations, and saves them to a new file.
    """
    sites = []
    lives = []
    spider = []
    
    file_list = [f for f in os.listdir(source_dir) if f.endswith('.json')]
    
    if not file_list:
        logger.warning(f"No JSON files found in directory '{source_dir}'.")
        return

    logger.info(f"Starting to process {len(file_list)} JSON files...")
    
    for file_name in file_list:
        file_path = os.path.join(source_dir, file_name)
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # Extract sites configuration
                if 'sites' in data and isinstance(data['sites'], list):
                    # Filter out invalid sites without 'api' or 'url' keys
                    valid_sites = [
                        site for site in data['sites'] 
                        if isinstance(site, dict) and ('api' in site or 'url' in site)
                    ]
                    sites.extend(valid_sites)
                
                # Extract lives configuration
                if 'lives' in data and isinstance(data['lives'], list):
                    lives.extend(data['lives'])
                    
                # Extract spider configuration, only keeping the first one found
                if not spider and 'spider' in data and isinstance(data['spider'], str):
                    spider.append(data['spider'])
                    
                logger.info(f"Successfully processed file: {file_name}")
        except json.JSONDecodeError:
            logger.error(f"Invalid JSON format in file '{file_name}', skipping.")
        except Exception as e:
            logger.error(f"An error occurred while processing file '{file_name}': {e}")

    # Build the merged configuration
    merged_data = {
        "sites": sites,
        "lives": lives,
        "spider": spider[0] if spider else ""
    }
    
    # Save the merged JSON file
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(merged_data, f, ensure_ascii=False, indent=2)
        logger.info(f"All configurations successfully merged and saved to '{output_file}'.")
    except Exception as e:
        logger.error(f"An error occurred while saving the merged file: {e}")

if __name__ == "__main__":
    SOURCE_DIRECTORY = "box"
    OUTPUT_FILE = "merged_tvbox_config.json"
    merge_tvbox_configs(SOURCE_DIRECTORY, OUTPUT_FILE)
