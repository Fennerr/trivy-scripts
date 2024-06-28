import os
import json
import csv

## Where output json files are stored

output_dir = './output'

## Utils

def find_json_files(root_dir):
    for root, dirs, files in os.walk(root_dir):
        for file in files:
            if file.endswith('.json'):
                file_path = os.path.join(root, file)
                yield file_path

def load_json(file_path):
    with open(file_path, 'r') as json_file:
        try:
            data = json.load(json_file)
            return data
        except json.JSONDecodeError:
            print(f"Error decoding JSON in file: {file_path}")

### Secrets functions

def find_secrets():
    def find_secrets_in_json_file(file_path):
        data = load_json(file_path)
        if 'Results' in data:
            for result in data['Results']:
                if result.get('Class') == 'secret':
                    print(f"File: {file_path}")
                    for secret in result.get('Secrets', []):
                        print(f"Match: {secret.get('Match')}")
                        
    for file_path in find_json_files(output_dir):
        find_secrets_in_json_file(file_path)


## Dashboard function

def create_dashboard(out_file_name, print_latex=True):
    data_file = open(out_file_name, 'w') 
    csv_writer = csv.writer(data_file)

    header = ['Image', 'Finding Target', 'Critical Found', 'Critical Fixed', 'High Found', 'High Fixed', 'Medium Found', 'Medium Fixed', 'Low Found', 'Low Fixed', 'Unknown Found', 'Unknown Fixed']

    csv_writer.writerow(header) 

    latex_entries = [] # To hold tuples of string, so that we can sort by critical vulns count
    latex_sort_key = 'Critical Found'

    for file_path in find_json_files(output_dir):
        data = load_json(file_path)
        image_name = data.get('ArtifactName')
        artifact_type = data.get('ArtifactType') # ie container_image

        if not 'Results' in data.keys():
            result_target = "No results"
            row_cells = [image_name, result_target]
            csv_writer.writerow(row_cells) 

        for result in data.get('Results'):
            result_target = result.get("Target")
            result_class = result.get("Class")
            
            # Handle OS findings (it will be the image name and then the OS name in brackets at the end)
            if '(' in result_target and ')' in result_target:
                result_target = result_target.split('(')[1][:-1]

            # Handle secrets (they dont have vulns)
            if result_class == "secret":
                continue


            row_cells = [image_name, result_target]

            vuln_count = {
                'Critical Found': 0, 
                'Critical Fixed': 0, 
                'High Found': 0, 
                'High Fixed': 0, 
                'Medium Found': 0, 
                'Medium Fixed': 0, 
                'Low Found': 0, 
                'Low Fixed': 0,
                'Unknown Found': 0,
                'Unknown Fixed': 0
            }

            for vuln in result.get('Vulnerabilities'):
                if vuln['Severity'] == 'CRITICAL':
                    vuln_count['Critical Found'] += 1
                    if 'FixedVersion' in vuln.keys():
                        vuln_count['Critical Fixed'] += 1
                elif vuln['Severity'] == 'HIGH':
                    vuln_count['High Found'] += 1
                    if 'FixedVersion' in vuln.keys():
                        vuln_count['High Fixed'] += 1
                elif vuln['Severity'] == 'MEDIUM':
                    vuln_count['Medium Found'] += 1
                    if 'FixedVersion' in vuln.keys():
                        vuln_count['Medium Fixed'] += 1
                elif vuln['Severity'] == 'LOW':
                    vuln_count['Low Found'] += 1
                    if 'FixedVersion' in vuln.keys():
                        vuln_count['Low Fixed'] += 1
                elif vuln['Severity'] == 'UNKNOWN':
                    vuln_count['Unknown Found'] += 1
                    if 'FixedVersion' in vuln.keys():
                        vuln_count['Unknown Fixed'] += 1
                else:
                    print("Could not find matching severity rating")
                    print(json.dumps(vuln, indent=4))
            
            for val in vuln_count.values():
                row_cells.append(str(val))
            csv_writer.writerow(row_cells) 

            if print_latex:
                if ".amazonaws.com/" in image_name:
                    image_name = '/'.join(image_name.split('/')[1:])
                if ':' in image_name:
                    image_name = image_name.split(':')[0]
                latex_string = f"{image_name} & {result_target} & {vuln_count['Critical Found']} & {vuln_count['High Found']} & {vuln_count['Medium Found']} & {vuln_count['Low Found']} \\\\ \\hline"
                # Store counts for all levels of severity for sorting
                latex_entries.append((vuln_count['Critical Found'], vuln_count['High Found'], vuln_count['Medium Found'], vuln_count['Low Found'], latex_string))
        
    if print_latex:
        # Sort by multiple criteria
        latex_entries.sort(reverse=True, key=lambda x: (x[0], x[1], x[2], x[3]))  # Sort by critical, then high, then medium, then low
        for _, _, _, _, latex_string in latex_entries:
            print(latex_string)

    data_file.close()
            
create_dashboard('trivy-results-dashboard.csv')

# find_secrets()
