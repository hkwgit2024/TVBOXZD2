import os
import logging
from zhconv import convert

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

# --- Constants ---
INPUT_FILE = 'iptv_list.txt'
OUTPUT_FILE = 'tv_list.txt'
GENRE_DELIMITER = '#genre#'
OTHER_CATEGORY_NAME = '其他'

# Define classification keywords
# Keywords should be lowercased for case-insensitive matching
CATEGORIES = {
    '卫视': ['卫视'],
    '新闻': ['新闻'],
    '娱乐': ['娱乐', '炫动'],
    '广东频道': ['广东'],
    '重庆频道': ['重庆'],
    '河北频道': ['河北'],
    '央视频道': ['CCTV', '中央'], # Added '中央' as it's common for CCTV channels
    '国外频道': ['CNN', 'CNA', 'CNBC'],
    # Add more categories as needed, ensuring keywords are lowercased
}

# Pre-process keywords for faster and case-insensitive matching
LOWERCASE_CATEGORIES = {
    cat: [kw.lower() for kw in keywords]
    for cat, keywords in CATEGORIES.items()
}

# --- Functions ---

def parse_iptv_list(filepath: str) -> dict[str, str]:
    """
    Reads the IPTV list file, parses channel names and URLs,
    handles duplicate names, and converts names to simplified Chinese.

    Args:
        filepath: The path to the input IPTV list file.

    Returns:
        A dictionary where keys are unique channel names (with _N for duplicates)
        and values are their corresponding URLs.
    """
    channels = {}
    name_count = {}

    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or GENRE_DELIMITER in line:
                    continue  # Skip empty lines and genre headers

                try:
                    name_raw, url = line.split(',', 1)
                    # Convert to simplified Chinese and strip leading/trailing spaces
                    name_clean = convert(name_raw, 'zh-cn').strip()

                    if not name_clean: # Skip if name is empty after conversion
                        logging.warning(f"Line {line_num}: Skipped - Empty channel name for URL '{url}'")
                        continue

                    # Handle duplicate names by appending _N
                    original_name = name_clean
                    if name_clean in name_count:
                        name_count[name_clean] += 1
                        unique_name = f"{name_clean}_{name_count[name_clean]}"
                    else:
                        name_count[name_clean] = 1
                        unique_name = name_clean
                    
                    channels[unique_name] = url

                except ValueError:
                    logging.warning(f"Line {line_num}: Skipped - Malformed line (expected 'name,url'): '{line}'")
                except Exception as e:
                    logging.error(f"Line {line_num}: Error processing line '{line}': {e}")

    except FileNotFoundError:
        logging.error(f"Error: Input file '{filepath}' not found.")
        return {} # Return empty dict on error
    except Exception as e:
        logging.error(f"An unexpected error occurred while reading '{filepath}': {e}")
        return {}

    return channels

def classify_channels(channels_dict: dict[str, str]) -> dict[str, list[str]]:
    """
    Classifies channels based on defined categories.

    Args:
        channels_dict: A dictionary of unique channel names and URLs.

    Returns:
        A dictionary where keys are category names and values are lists of
        "name,url" strings for channels belonging to that category.
        Includes an '其他' (Other) category for unclassified channels.
    """
    classified_channels = {cat: [] for cat in CATEGORIES} # Initialize with all defined categories
    other_channels = []

    for name, url in channels_dict.items():
        categorized = False
        name_lower = name.lower() # Convert name to lowercase once for all comparisons

        for cat, keywords_lower in LOWERCASE_CATEGORIES.items():
            if any(keyword in name_lower for keyword in keywords_lower):
                classified_channels[cat].append(f"{name},{url}")
                categorized = True
                break  # Channel classified, move to the next channel

        if not categorized:
            other_channels.append(f"{name},{url}")
    
    # Add '其他' category to the result if it has channels
    if other_channels:
        classified_channels[OTHER_CATEGORY_NAME] = other_channels
    
    return classified_channels

def write_classified_list(output_filepath: str, classified_data: dict[str, list[str]]):
    """
    Writes the classified channels to the output file with category headers.

    Args:
        output_filepath: The path to the output file.
        classified_data: A dictionary of classified channels.
    """
    try:
        with open(output_filepath, 'w', encoding='utf-8') as f:
            # Write categories in the order they were defined in CATEGORIES, then '其他'
            for cat_name in CATEGORIES.keys():
                if cat_name in classified_data and classified_data[cat_name]:
                    f.write(f"{cat_name},{GENRE_DELIMITER}\n")
                    for channel_str in classified_data[cat_name]:
                        f.write(f"{channel_str}\n")
            
            # Write the '其他' category last if it exists
            if OTHER_CATEGORY_NAME in classified_data and classified_data[OTHER_CATEGORY_NAME]:
                f.write(f"{OTHER_CATEGORY_NAME},{GENRE_DELIMITER}\n")
                for channel_str in classified_data[OTHER_CATEGORY_NAME]:
                    f.write(f"{channel_str}\n")

        logging.info(f"Classification complete. Results saved to '{output_filepath}'")
    except Exception as e:
        logging.error(f"Error writing to output file '{output_filepath}': {e}")

# --- Main Execution ---
if __name__ == "__main__":
    logging.info(f"Starting IPTV list classification from '{INPUT_FILE}'...")

    # 1. Parse the input file
    parsed_channels = parse_iptv_list(INPUT_FILE)
    if not parsed_channels:
        logging.warning("No channels found or an error occurred during parsing. Exiting.")
    else:
        # 2. Classify the channels
        classified_results = classify_channels(parsed_channels)
        
        # 3. Write the classified results to the output file
        write_classified_list(OUTPUT_FILE, classified_results)
