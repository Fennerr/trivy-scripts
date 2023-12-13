import os
import subprocess
import sys
import argparse
import boto3
import re

def get_args():
    parser = argparse.ArgumentParser(description="AWS profile name.")
    parser.add_argument('--profile', default='default', help='Name of the AWS profile.')
    parser.add_argument('--region', default='eu-west-1', help='AWS region.')
    return parser.parse_args()

def get_account_id(boto_session):
    sts = boto_session.client("sts")
    return sts.get_caller_identity()["Account"]

def perform_docker_login(profile_name, account_id, region):
    cmd = f"aws ecr get-login-password --profile {profile_name} --region {region} | docker login --username AWS --password-stdin {account_id}.dkr.ecr.{region}.amazonaws.com"
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    return result.stdout, result.stderr

def get_kubectl_output():
    cmd = '''kubectl get pods --all-namespaces -o=jsonpath='{range .items[*]}{.metadata.namespace}/{.metadata.name}: {.spec.containers[*].image}{"\\n"}{end}' '''
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    return result.stdout

def parse_kubectl_output():
    kubectl_output = get_kubectl_output()
    output = {}
    lines = kubectl_output.split('\n')
    if lines[-1] == '':
        lines = lines[:-1]
    # namespace/podname: trivy_url trivy_url2
    for line in lines:
        first_part, second_part = line.split(': ')
        namespace,podname = first_part.split('/')
        image_urls = list(second_part.split(' '))
        output[first_part] = image_urls
    return output

def is_ecr_image(image_url):
    return re.match(r"\d+\.dkr\.ecr\..+\.amazonaws\.com", image_url)

def get_ecr_region_from_url(image_url):
    match = re.search(r"\d+\.dkr\.ecr\.(.+)\.amazonaws\.com", image_url)
    return match.group(1) if match else None


def create_subdirectory(path_str):
    # Split the given string by '/'
    parts = path_str.split('/')

    # Ensure there are exactly two parts (a directory and a subdirectory)
    if len(parts) != 2:
        raise ValueError("Expected a string in the format 'directory/subdirectory'")

    # The main 'output' directory
    output_dir = os.path.join(os.getcwd(), 'output')

    # Create the 'output' directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Create the first directory inside 'output'
    first_directory = os.path.join(output_dir, parts[0])
    if not os.path.exists(first_directory):
        os.makedirs(first_directory)

    # Create the subdirectory inside the first directory
    subdirectory = os.path.join(first_directory, parts[1])
    if not os.path.exists(subdirectory):
        os.makedirs(subdirectory)

# Function that will execute trivy, and print the output from trivy in real-time
def execute_and_stream_trivy_output(namespace_podname, trivy_url):
    create_subdirectory(namespace_podname)
    cmd  = f'trivy image {trivy_url}'
    cmd += f' -f json -o output/{namespace_podname}/{trivy_url.replace("/","_")}.json'
    print(f'Executing: {cmd}')
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)

    while True:
        # Read a line from stdout
        output = process.stdout.readline()

        # If there's output, print it
        if output:
            print(output.strip())

        # Check if process is still running
        retcode = process.poll()

        if retcode is not None:
            # Process has finished, handle remaining output and break from loop
            for output in process.stdout.readlines():
                print(output.strip())
            for error in process.stderr.readlines():
                print(error.strip(), file=sys.stderr)
            break

if __name__ == '__main__':
    args = get_args()

    # Intialize AWS session and login using docker CLI to ECR
    s = boto3.Session(profile_name=args.profile,region_name=args.region)
    account_id = get_account_id(s)

    pods_dict = parse_kubectl_output()
    for k,v in pods_dict.items():
        for image_url in v:
            if is_ecr_image(image_url):
                ecr_region = get_ecr_region_from_url(image_url)
                if ecr_region and ecr_region != last_login_region:
                    stdout, stderr = perform_docker_login(args.profile, account_id, ecr_region)
                    if 'Login Succeeded' in stdout:
                        last_login_region = ecr_region
                    else:
                        print(f"Docker login to {account_id}.dkr.ecr.{ecr_region}.amazonaws.com failed")
                        print("Docker Login STDOUT:", stdout)
                        print("Docker Login STDERR:", stderr)
                        continue
            execute_and_stream_trivy_output(k, image_url)
