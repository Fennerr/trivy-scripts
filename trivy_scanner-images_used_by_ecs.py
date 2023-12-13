import os
import subprocess
import sys
import argparse
import boto3
import re

def get_args():
    parser = argparse.ArgumentParser(description="AWS profile name.")
    parser.add_argument('--profile', default='default', help='Name of the AWS profile.')
    parser.add_argument('--region', default='us-east-1', help='AWS region (default: us-east-1)')
    return parser.parse_args()

def get_account_id(boto_session):
    sts = boto_session.client("sts")
    return sts.get_caller_identity()["Account"]

def get_regions_for_service(boto_session, service_name):
    ec2 = boto_session.client('ec2')
    return [region['RegionName'] for region in ec2.describe_regions()['Regions'] if service_name in ec2.describe_availability_zones(Filters=[{'Name': 'region-name', 'Values': [region['RegionName']]}])['AvailabilityZones'][0]['ZoneName']]

def perform_docker_login(profile_name, account_id, region):
    cmd = f"aws ecr get-login-password --profile {profile_name} --region {region} | docker login --username AWS --password-stdin {account_id}.dkr.ecr.{region}.amazonaws.com"
    result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
    return result.stdout, result.stderr

def get_ecs_task_definitions(boto_session, region):
    ecs = boto_session.client('ecs', region_name=region)
    task_defs = ecs.list_task_definitions()
    images = []
    for task_def_arn in task_defs['taskDefinitionArns']:
        task_def = ecs.describe_task_definition(taskDefinition=task_def_arn)
        for container_def in task_def['taskDefinition']['containerDefinitions']:
            images.append(container_def['image'])
    return images

def is_ecr_image(image_url):
    return re.match(r"\d+\.dkr\.ecr\..+\.amazonaws\.com", image_url)

def get_ecr_region_from_url(image_url):
    match = re.search(r"\d+\.dkr\.ecr\.(.+)\.amazonaws\.com", image_url)
    return match.group(1) if match else None

args = get_args()

# Initialize AWS session
s = boto3.Session(profile_name=args.profile, region_name=args.region)
account_id = get_account_id(s)
ecs_regions = get_regions_for_service(s, 'ecs')

last_login_region = None

def execute_and_stream_trivy_output(image_url):
    cmd  = f'trivy image {image_url}'
    cmd += f' -f table -o {image_url.replace("/","_")}.table'
    print(f'Executing: {cmd}')
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)

    while True:
        output = process.stdout.readline()
        if output:
            print(output.strip())
        retcode = process.poll()
        if retcode is not None:
            for output in process.stdout.readlines():
                print(output.strip())
            for error in process.stderr.readlines():
                print(error.strip(), file=sys.stderr)
            break

for region in ecs_regions:
    images = get_ecs_task_definitions(s, region)
    for image_url in images:
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
        execute_and_stream_trivy_output(image_url)
