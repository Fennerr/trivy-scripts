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

def get_regions_for_service(boto_session, service_name):
    return boto_session.get_available_regions(service_name=service_name)

def perform_docker_login(profile_name, account_id, region):
    cmd = f"aws ecr get-login-password --profile {profile_name} --region {region} | docker login --username AWS --password-stdin {account_id}.dkr.ecr.{region}.amazonaws.com"
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    return result.stdout, result.stderr


# Function that will execute trivy, and print the output from trivy in real-time
def execute_and_stream_trivy_output(repo_name,latest_image_tag,ecr_uri):
    output_file = f"{repo_name}:{latest_image_tag}_results.json"
    output_file = output_file.replace("/","_")
    cmd  = f'trivy image {ecr_uri}/{repo_name}:{latest_image_tag}'
    cmd += f' -f json -o {output_file}'
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
    ecs_regions = get_regions_for_service(s, 'ecr')

    for region in ecs_regions:
        print(f"Looking for images in {region}")
        ecr_uri = f"{account_id}.dkr.ecr.{region}.amazonaws.com"
        stdout, stderr = perform_docker_login(args.profile, account_id, region)

        if not 'Login Succeeded' in stdout:
            print("Docker login to %s failed" % ecr_uri)
            print("Docker Login STDOUT:", stdout)
            print("Docker Login STDERR:", stderr)
            print("Skipping the %s region" % region)
            continue

        # Get ECR repos
        ecr = s.client('ecr', region_name=region)
        repositories = ecr.describe_repositories()["repositories"]
        print(f"Found {len(repositories)} ECR repositories in {region}")

        # Get the latest image tag for each repo
        jmespath_expression = 'sort_by(imageDetails, &to_string(imagePushedAt))[-1].imageTags'
        for repo in repositories:
            repo_name = repo["repositoryName"]
            paginator = ecr.get_paginator('describe_images')
            iterator = paginator.paginate(repositoryName=repo_name)
            filter_iterator = iterator.search(jmespath_expression)
            repo["latestImageTag"] = list(filter_iterator)[0]

        for repo in repositories:
            execute_and_stream_trivy_output(repo["repositoryName"],repo["latestImageTag"],ecr_uri)




