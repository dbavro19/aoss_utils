#!/usr/bin/env python3
"""
Amazon OpenSearch Serverless - Create Network Policy Example
"""

import boto3
import json
import sys

# Configuration
COLLECTION_NAME = "my-sample-collection"
REGION = "us-east-1"
ROLE_ARN = None  # Set to your role ARN if needed: "arn:aws:iam::123456789012:role/OpenSearchRole"

# Network access configuration
NETWORK_ACCESS = "public"  # Options: "public" or "vpc"

# VPC configuration (only used when NETWORK_ACCESS = "vpc")
VPC_ID = "vpc-12345"
SUBNET_IDS = ["subnet-abc123", "subnet-def456"]
SECURITY_GROUP_IDS = ["sg-789xyz"]  # Optional, can be empty list []

# Auto-generate policy name from collection name (max 32 chars)
POLICY_NAME = f"{COLLECTION_NAME}-network"

def get_credentials():
    """Get AWS credentials, trying environment first, then assume role if specified"""
    
    # Try default credentials first (environment, instance profile, etc.)
    try:
        session = boto3.Session()
        # Test if credentials work
        session.client('sts').get_caller_identity()
        print("✅ Using default AWS credentials")
        return session
    except Exception as e:
        if ROLE_ARN:
            print(f"❌ Default credentials failed: {e}")
            print(f"🔄 Attempting to assume role: {ROLE_ARN}")
        else:
            print(f"❌ No default credentials available and no role ARN specified: {e}")
            sys.exit(1)
    
    # Fallback to assume role if specified
    if ROLE_ARN:
        try:
            sts = boto3.client('sts')
            response = sts.assume_role(
                RoleArn=ROLE_ARN,
                RoleSessionName="opensearch-create-network-policy"
            )
            
            credentials = response['Credentials']
            session = boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials['SessionToken']
            )
            print("✅ Successfully assumed IAM role")
            return session
            
        except Exception as e:
            print(f"❌ Failed to assume role: {e}")
            sys.exit(1)
    
    print("❌ No valid credentials available")
    sys.exit(1)

def get_network_config():
    """Build network configuration based on NETWORK_ACCESS setting"""
    
    if NETWORK_ACCESS == "public":
        # Public internet access
        policy_document = [
            {
                "Rules": [
                    {
                        "Resource": [f"collection/{COLLECTION_NAME}"],
                        "ResourceType": "dashboard"
                    },
                    {
                        "Resource": [f"collection/{COLLECTION_NAME}"],
                        "ResourceType": "collection"
                    }
                ],
                "AllowFromPublic": True
            }
        ]
        access_type = "Public internet access"
        
    elif NETWORK_ACCESS == "vpc":
        # VPC access only
        vpc_endpoints = [
            {
                "VpcId": VPC_ID,
                "SubnetIds": SUBNET_IDS
            }
        ]
        
        # Add security groups if specified
        if SECURITY_GROUP_IDS:
            vpc_endpoints[0]["SecurityGroupIds"] = SECURITY_GROUP_IDS
        
        policy_document = [
            {
                "Rules": [
                    {
                        "Resource": [f"collection/{COLLECTION_NAME}"],
                        "ResourceType": "dashboard"
                    },
                    {
                        "Resource": [f"collection/{COLLECTION_NAME}"],
                        "ResourceType": "collection"
                    }
                ],
                "SourceVPCEs": vpc_endpoints
            }
        ]
        
        access_type = f"VPC access only (VPC: {VPC_ID})"
        
    else:
        print(f"❌ Invalid NETWORK_ACCESS value: {NETWORK_ACCESS}")
        print("Valid options: 'public' or 'vpc'")
        sys.exit(1)
    
    return policy_document, access_type

def create_network_policy():
    """Create network policy for OpenSearch Serverless"""
    
    # Get authenticated session
    session = get_credentials()
    client = session.client('opensearchserverless', region_name=REGION)
    
    # Get network configuration
    policy_document, access_type = get_network_config()
    
    print(f"🚀 Creating network policy: {POLICY_NAME}")
    print(f"📋 Collection: {COLLECTION_NAME}")
    print(f"🌐 Access: {access_type}")
    
    if NETWORK_ACCESS == "vpc":
        print(f"   VPC ID: {VPC_ID}")
        print(f"   Subnets: {', '.join(SUBNET_IDS)}")
        if SECURITY_GROUP_IDS:
            print(f"   Security Groups: {', '.join(SECURITY_GROUP_IDS)}")
    
    try:
        response = client.create_security_policy(
            name=POLICY_NAME,
            type='network',
            policy=json.dumps(policy_document)
        )
        
        print(f"✅ Network policy created successfully!")
        print(f"   Name: {response['securityPolicyDetail']['name']}")
        print(f"   Type: {response['securityPolicyDetail']['type']}")
        print(f"   Created: {response['securityPolicyDetail']['createdDate']}")
        
        return response
        
    except Exception as e:
        if "already exists" in str(e).lower():
            print(f"⚠️  Network policy {POLICY_NAME} already exists")
            return None
        else:
            print(f"❌ Failed to create network policy: {e}")
            sys.exit(1)

def main():
    print(f"Creating OpenSearch Serverless Network Policy")
    print(f"Collection: {COLLECTION_NAME}")
    print(f"Policy Name: {POLICY_NAME}")
    print(f"Region: {REGION}")
    print(f"Network Access: {NETWORK_ACCESS}")
    
    create_network_policy()
    
    print(f"\n🎉 Success! Network policy {POLICY_NAME} is ready")
    print("🌐 Network access details:")
    if NETWORK_ACCESS == "public":
        print("   • Collection accessible from public internet")
        print("   • Access controlled by IAM and data access policies")
        print("   • No additional network restrictions")
    else:
        print(f"   • Collection accessible only from VPC: {VPC_ID}")
        print(f"   • Allowed subnets: {', '.join(SUBNET_IDS)}")
        if SECURITY_GROUP_IDS:
            print(f"   • Security groups: {', '.join(SECURITY_GROUP_IDS)}")
        print("   • Internet access blocked")
    
    print("\n📋 Next steps:")
    print("   1. Create encryption policy") 
    print("   2. Create data access policy")
    print("   3. Create the collection")

if __name__ == "__main__":
    main()