import yaml
import os

# Path to config.yaml
CONFIG_FILE = "config.yaml"

def clean_proxies():
    try:
        # Read the config.yaml file
        with open(CONFIG_FILE, 'r', encoding='utf-8') as file:
            config = yaml.safe_load(file)

        # Check if config and proxies exist
        if config and 'proxies' in config:
            # Clear the proxies list
            config['proxies'] = []
            print("Proxies cleared successfully.")
        else:
            print("No proxies found in config.yaml or file is empty.")

        # Write back the cleaned config.yaml
        with open(CONFIG_FILE, 'w', encoding='utf-8') as file:
            yaml.safe_dump(config, file, allow_unicode=True)
            print(f"Updated {CONFIG_FILE} saved.")

    except FileNotFoundError:
        print(f"Error: {CONFIG_FILE} not found.")
        exit(1)
    except yaml.YAMLError as e:
        print(f"Error parsing YAML: {e}")
        exit(1)
    except Exception as e:
        print(f"Unexpected error: {e}")
        exit(1)

if __name__ == "__main__":
    clean_proxies()
