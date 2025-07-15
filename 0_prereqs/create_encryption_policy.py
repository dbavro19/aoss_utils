#!/usr/bin/env python3
"""
Amazon OpenSearch Serverless - Create Encryption Policy Example
"""

import boto3
import json
import sys

# Configuration
COLLECTION_NAME = "my-sample-collection"
REGION = "us-east-1"
ROLE_ARN = None  # Set to your role ARN if needed: "arn:aws:iam::123456789012:role/OpenSearchRole"

# KMS Key options:
# "auto" = AWS owned key (default, no extra cost)
# "aws-managed" = AWS managed key for OpenSearch Serverless
# "arn:aws:kms:region:account:key/key-id" = Customer managed key ARN
KMS_KEY = "auto"

# Auto-generate policy name from collection name (max 32 chars)
POLICY_NAME = f"{COLLECTION_NAME}-encryption"

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
                RoleSessionName="opensearch-create-encryption-policy"
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

def get_encryption_config():
    """Build encryption configuration based on KMS_KEY setting"""
    
    base_policy = {
        "Rules": [
            {
                "ResourceType": "collection",
                "Resource": [f"collection/{COLLECTION_NAME}"]
            }
        ]
    }
    
    if KMS_KEY == "auto":
        # AWS owned key
        base_policy["AWSOwnedKey"] = True
        encryption_type = "AWS owned key"
        
    elif KMS_KEY == "aws-managed":
        # AWS managed key for OpenSearch Serverless
        kms_arn = f"arn:aws:kms:{REGION}:{boto3.Session().client('sts').get_caller_identity()['Account']}:key/aws/aoss"
        base_policy["KmsARN"] = kms_arn
        encryption_type = f"AWS managed key: {kms_arn}"
        
    elif KMS_KEY.startswith("arn:aws:kms:"):
        # Customer managed key
        base_policy["KmsARN"] = KMS_KEY
        encryption_type = f"Customer managed key: {KMS_KEY}"
        
    else:
        print(f"❌ Invalid KMS_KEY value: {KMS_KEY}")
        print("Valid options: 'auto', 'aws-managed', or full KMS key ARN")
        sys.exit(1)
    
    return base_policy, encryption_type

def create_encryption_policy():
    """Create encryption policy for OpenSearch Serverless"""
    
    # Get authenticated session
    session = get_credentials()
    client = session.client('opensearchserverless', region_name=REGION)
    
    # Get encryption configuration
    policy_document, encryption_type = get_encryption_config()
    
    print(f"🚀 Creating encryption policy: {POLICY_NAME}")
    print(f"📋 Collection: {COLLECTION_NAME}")
    print(f"🔐 Encryption: {encryption_type}")
    
    try:
        response = client.create_security_policy(
            name=POLICY_NAME,
            type='encryption',
            policy=json.dumps(policy_document)
        )
        
        print(f"✅ Encryption policy created successfully!")
        print(f"   Name: {response['securityPolicyDetail']['name']}")
        print(f"   Type: {response['securityPolicyDetail']['type']}")
        print(f"   Created: {response['securityPolicyDetail']['createdDate']}")
        
        return response
        
    except Exception as e:
        if "already exists" in str(e).lower():
            print(f"⚠️  Encryption policy {POLICY_NAME} already exists")
            return None
        else:
            print(f"❌ Failed to create encryption policy: {e}")
            sys.exit(1)

def main():
    print(f"Creating OpenSearch Serverless Encryption Policy")
    print(f"Collection: {COLLECTION_NAME}")
    print(f"Policy Name: {POLICY_NAME}")
    print(f"Region: {REGION}")
    print(f"KMS Key: {KMS_KEY}")
    
    create_encryption_policy()
    
    print(f"\n🎉 Success! Encryption policy {POLICY_NAME} is ready")
    print("🔐 Encryption details:")
    if KMS_KEY == "auto":
        print("   • Using AWS owned key (no additional cost)")
        print("   • Managed automatically by AWS")
    elif KMS_KEY == "aws-managed":
        print("   • Using AWS managed key for OpenSearch Serverless")
        print("   • Standard KMS pricing applies")
    else:
        print(f"   • Using customer managed key: {KMS_KEY}")
        print("   • Custom KMS pricing applies")
    
    print("\n📋 Next steps:")
    print("   1. Create network policy (if needed)")
    print("   2. Create data access policy") 
    print("   3. Create the collection")

if __name__ == "__main__":
    main()