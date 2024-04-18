
This repo contains scripts I have made to:
* Scan the latest images in ECR
* Scan images in use by Kubernetes
* Scan images in use by ECS

The scripts will attempt to login to ECR to allow for the images to be pulled.
The scripts will iterate through all regions, and generate json reports.

## Setup

Have a python virtual environment with boto3 installed, and have [trivy](https://github.com/aquasecurity/trivy) installed.

## Execution

Simply pass in the profile that you want to use using the `--profile` parameter
