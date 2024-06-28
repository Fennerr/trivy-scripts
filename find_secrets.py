import os
import json

def find_secrets_in_json(root_dir):
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                with open(file_path, 'r') as json_file:
                    try:
                        data = json.load(json_file)
                        if 'Results' in data:
                            for result in data['Results']:
                                if result.get('Class') == 'secret':
                                    print(f"File: {file_path}")
                                    for secret in result.get('Secrets', []):
                                        print(f"Match: {secret.get('Match')}")
                    except json.JSONDecodeError:
                        print(f"Error decoding JSON in file: {file_path}")

# Replace 'your_directory_path' with the path to the directory you want to search
find_secrets_in_json('./output')
