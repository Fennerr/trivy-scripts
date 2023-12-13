import subprocess
import sys
import argparse
import boto3

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

args = get_args()

# Intialize AWS session and login using docker CLI to ECR
s = boto3.Session(profile_name=args.profile,region_name=args.region)
account_id = get_account_id(s)
ECR_URI = f"{account_id}.dkr.ecr.{args.region}.amazonaws.com"
stdout, stderr = perform_docker_login(args.profile, account_id, args.region)

if not 'Login Succeeded' in stdout:
    print("Docker login to {ECR_URI} failed")
    print("Docker Login STDOUT:", stdout)
    print("Docker Login STDERR:", stderr)
    exit(-1)

# Get ECR repos
ecr = s.client('ecr')
repositories = ecr.describe_repositories()["repositories"]
print(f"Found {len(repositories)} repositories in ECR")
# Get the latest image tag for each repo
jmespath_expression = 'sort_by(imageDetails, &to_string(imagePushedAt))[-1].imageTags'
for repo in repositories:
    repo_name = repo["repositoryName"]
    paginator = ecr.get_paginator('describe_images')
    iterator = paginator.paginate(repositoryName=repo_name)
    filter_iterator = iterator.search(jmespath_expression)
    repo["latestImageTag"] = list(filter_iterator)[0]

# Function that will execute trivy, and print the output from trivy in real-time
def execute_and_stream_trivy_output(repo_name,latest_image_tag):
    cmd  = f'trivy image {ECR_URI}/{repo_name}:{latest_image_tag}'
    cmd += f' -f table -o {repo_name}:{latest_image_tag}_results.table'
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

for repo in repositories:
    execute_and_stream_trivy_output(repo["repositoryName"],repo["latestImageTag"])



