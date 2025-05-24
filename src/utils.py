# src/utils.py

import os
import logging

def read_txt_to_array(file_name):
    """Reads content from a TXT file, one element per line."""
    try:
        with open(file_name, 'r', encoding='utf-8') as file:
            lines = file.readlines()
            # Filter out empty lines and strip whitespace
            lines = [line.strip() for line in lines if line.strip()]
            return lines
    except FileNotFoundError:
        logging.error(f"File '{file_name}' not found.")
        return []
    except Exception as e:
        logging.error(f"Error reading file '{file_name}': {e}")
        return []

def write_array_to_txt(file_name, data_array, append=False):
    """Writes array content to a TXT file, one element per line.
    If append is True, appends to the file; otherwise, overwrites.
    """
    mode = 'a' if append else 'w'
    try:
        with open(file_name, mode, encoding='utf-8') as file:
            # If append is True, ensure we don't write duplicate update headers
            if not append or not data_array or not data_array[0].startswith("更新时间"):
                for item in data_array:
                    # If item already ends with \n, avoid double newline
                    file.write(item if item.endswith('\n') else item + '\n')
            else: # If append and it's an update header, assume it's part of the full list
                for item in data_array:
                    file.write(item if item.endswith('\n') else item + '\n')

        logging.info(f"Data successfully written to '{file_name}' ({'appended' if append else 'overwritten'}).")
    except Exception as e:
        logging.error(f"Error writing to file '{file_name}': {e}")
