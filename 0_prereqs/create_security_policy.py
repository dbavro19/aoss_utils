#!/usr/bin/env python3
"""
Amazon OpenSearch Serverless - Create Security Policy Example
"""

import boto3
import json
import sys

# Configuration
COLLECTION_NAME = "my-sample-collection"
REGION = "us-east-1"
ROLE_ARN = None  # Set to your role ARN if needed: "arn:aws:iam::123456789012:role/OpenSearchRole"

# Auto-generate policy name from collection name (max 32 chars)
POLICY_NAME = f"{COLLECTION_NAME}-access"

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
                RoleSessionName="opensearch-create-security-policy"
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

def get_current_principal(session):
    """Get the current principal ARN for the policy"""
    
    try:
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        principal_arn = identity['Arn']
        
        print(f"🔍 Current principal: {principal_arn}")
        return principal_arn
        
    except Exception as e:
        print(f"❌ Failed to get current principal: {e}")
        sys.exit(1)

def create_security_policy():
    """Create data access security policy for OpenSearch Serverless"""
    
    # Get authenticated session
    session = get_credentials()
    client = session.client('opensearchserverless', region_name=REGION)
    
    # Get current principal ARN
    principal_arn = get_current_principal(session)
    
    # Define the security policy
    policy_document = [
        {
            "Rules": [
                {
                    "ResourceType": "index",
                    "Resource": [f"index/{COLLECTION_NAME}/*"],
                    "Permission": ["aoss:*"]
                }
            ],
            "Principal": [principal_arn]
        }
    ]
    
    print(f"🚀 Creating security policy: {POLICY_NAME}")
    print(f"📋 Policy grants full access to collection: {COLLECTION_NAME}")
    print(f"🔐 Principal: {principal_arn}")
    
    try:
        response = client.create_access_policy(
            name=POLICY_NAME,
            type='data',
            policy=json.dumps(policy_document)
        )
        
        print(f"✅ Security policy created successfully!")
        print(f"   Name: {response['accessPolicyDetail']['name']}")
        print(f"   Type: {response['accessPolicyDetail']['type']}")
        print(f"   Created: {response['accessPolicyDetail']['createdDate']}")
        
        return response
        
    except Exception as e:
        if "already exists" in str(e).lower():
            print(f"⚠️  Security policy {POLICY_NAME} already exists")
            return None
        else:
            print(f"❌ Failed to create security policy: {e}")
            sys.exit(1)

def main():
    print(f"Creating OpenSearch Serverless Security Policy")
    print(f"Collection: {COLLECTION_NAME}")
    print(f"Policy Name: {POLICY_NAME}")
    print(f"Region: {REGION}")
    
    create_security_policy()
    
    print(f"\n🎉 Success! Security policy {POLICY_NAME} is ready")
    print("💡 This policy grants full access to:")
    print(f"   • Collection: {COLLECTION_NAME}")
    print("   • All indexes in the collection")
    print("   • All operations (read, write, admin)")
    print("\n📋 Next steps:")
    print("   1. Create encryption policy (if needed)")
    print("   2. Create network policy (if needed)")
    print("   3. Create the collection")

if __name__ == "__main__":
    main()