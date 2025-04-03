Node.js Application with Terraform, Containerization, and CI/CD Pipeline
## Node.js Application with Terraform, Containerization(ECS), and CI/CD Pipeline
Entity ID: https://ap-south-1.signin.aws.amazon.com/platform/saml/d-9f677add25

Assertion Consumer Service (ACS) URL: https://ap-south-1.signin.aws.amazon.com/platform/saml/acs/840fe1f5-6a5b-4a19-b051-b6cbeede3d58

NameID Format: urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress

This repository contains a Node.js application deployed using Docker(ECS), Terraform, and a CI/CD pipeline. The infrastructure is provisioned using Terraform, which includes ECS, ECR, ALB, VPC, Route53, and KMS. The CI/CD pipeline is built using GitHub Actions to automate the build, test, and deployment process.

This README will guide you through the steps to set up the application locally, provision the infrastructure, and understand the CI/CD pipeline flow. Additionally, it covers security considerations and trade-offs made during the design process.

## Table of Contents
- [Local Setup](#local-setup)
- [Infrastructure Provisioning](#infrastructure-provisioning)
- [CI/CD Pipeline Flow](#cicd-pipeline-flow)
- [Security Considerations](#security-considerations)
- [Trade-offs & Decisions](#trade-offs--decisions)

## Local Setup

### Prerequisites
- Node.js (v16 or higher)
- npm (v8 or higher)
- Docker (v20 or higher)
- AWS CLI (configured with credentials)
- Terraform (v1.0 or higher)

### Steps to Run the Application Locally

#### Clone the Repository:
```bash
git clone https://github.com/your-username/node-app.git
cd node-app
```

#### Install Dependencies:
```bash
npm install
```

#### Run the Application Locally:
```bash
npm start
```
The application will be available at [http://localhost:3000](http://localhost:3000).

#### Run the Application Using Docker:

##### Build the Docker image:
```bash
docker build -t node-app:latest .
```

##### Run the Docker container:
```bash
docker run -p 3000:3000 node-app:latest -n node-app
```
The application will be available at [http://localhost:3000](http://localhost:3000).

## Infrastructure Provisioning

### Prerequisites
- AWS account with necessary permissions.
- Terraform installed and configured.
- AWS CLI configured with credentials.

### Steps to Provision Infrastructure

#### Navigate to the Terraform Directory:
```bash
cd terraform
```

#### Initialize Terraform:
```bash
terraform init
```

#### Review the Terraform Plan:
```bash
terraform plan
```

#### Apply the Terraform Configuration:
```bash
terraform apply
```
This will provision the following resources:
- ECS Cluster
- ECR Repository
- Application Load Balancer (ALB)
- VPC with public and private subnets
- Route53 DNS records
- KMS for encryption

#### Verify the Infrastructure:
Once the Terraform apply is complete, verify that the resources are created in the AWS Management Console.

## CI/CD Pipeline Flow

The CI/CD pipeline is built using GitHub Actions and is triggered on every push to the main branch. The pipeline consists of the following steps:

- **Linting and Testing:**
    - Runs ESLint to ensure code quality.
    - Runs unit tests using `npm test`.

- **Scan for Vulnerabilities:**
    - Uses Trivy to scan the application code filesystem for vulnerabilities.
    - Uses OWASP Dependency Check used for security scanning of the third party  dependencies used in application as part of Software Composition Analysis process.

- **Build Docker Image:**
    - Builds the Docker image for the Node.js application.

- **Push to ECR:**
    - Pushes the Docker image to the Elastic Container Registry (ECR) with scan on push enable.

- **Deploy to ECS:**
    - Updates the ECS service with the new Docker image.

- **Destroy Infrastructure (Optional):**
    - A separate workflow is provided to destroy the infrastructure using Terraform.

## How to Deploy the Infrastructure and Application
The deployment process is **fully automated** using **GitHub Actions**. 

### Triggering the Pipeline
The pipeline is triggered automatically on every push to the main branch. You can also trigger it manually from the GitHub Actions tab.

### **1️⃣ Trigger Infrastructure Provisioning**
The GitHub Actions workflow automatically provisions AWS resources (ECS, ECR, ALB, etc.) when you push code to main.
Alternatively, manually trigger it:
Go to **GitHub → Actions → Terraform CI/CD**
Click **Run Workflow**

### **2️⃣ Trigger Application Deployment**
The GitHub Actions workflow automatically deploy the application to ECS cluster with all security scanning incorporated as part of DevSecops.
Alternatively, manually trigger it:
Go to **GitHub → Actions → Secure Build & Deploy to AWS ECSD**
Click **Run Workflow**

## Security Considerations

### Secrets Management
- Secrets such as `AWS_ROLE_ARN`, `AWS_REGION`, `ECR_REGISTRY`, `ECR_REPOSITORY`, `SONARQUBE_URL` and `SONARQUBE_TOKEN` are stored in GitHub Secrets and are accessed during the CI/CD pipeline execution.
- Terraform uses AWS IAM roles with least privilege access to ensure security.
- Logging being enalbed at infra level like vpc flow logs, alb access logs etc. and at application level as well.

### Vulnerability Scanning
- **Trivy:** Used to scan Filesystem scanning of application code and could be extended at conatiner level.
- **OWASP Dependency Check:** Used for security scanning of the third party  dependencies used in application as part of Software Composition Analysis process.
- **Image Scanning:** Used ECR scan on push option to scan images while pushing to ECR repository
- **Tfsec:** Used to scan Terraform code for security misconfigurations.

### Networking Security
- Enabled WAF at Alb level to secure application from DDOS attack, SQL Injection, BruteForce Attack etc.
- The VPC is configured with public and private subnets to ensure that the application is not directly exposed to the internet
- Security groups are tightly configured to allow only necessary traffic.

## Trade-offs & Decisions

### Why ECS and Not EKS?
- **Simplicity:** ECS is easier to set up and manage compared to EKS, especially for smaller applications.
- **Cost:** ECS is generally more cost-effective for smaller workloads.
- **Integration:** ECS integrates seamlessly with other AWS services like ALB, Route53, and CloudWatch.

### Why Terraform?
- **Infrastructure as Code:** Terraform allows us to define the entire infrastructure as code, making it easy to version control and replicate.
- **Modularity:** Terraform modules allow us to reuse code for different environments (e.g., staging, production).

### Why GitHub Actions?
- **Integration with GitHub:** Since the code is hosted on GitHub, using GitHub Actions provides a seamless CI/CD experience.
- **Flexibility:** GitHub Actions supports a wide range of workflows and integrations.

### Dealing with External Terraform Modules
- When using external terraform modules it becomes really important to consider facts like Modules may enforce rigid configurations.
- Terraform cannot resolve dependencies inside modules during terraform plan.
- Debugging an abstracted module is harder than debugging native resources.
