#!/usr/bin/env python3
"""
Amazon OpenSearch Serverless - Create Collection Example
"""

import boto3
import time
import sys

# Configuration
COLLECTION_NAME = "my-sample-collection"
REGION = "us-east-1"
ROLE_ARN = None  # Set to your role ARN if needed: "arn:aws:iam::123456789012:role/OpenSearchRole"

# Policy names (should match the ones created by the policy examples)
SECURITY_POLICY_NAME = f"{COLLECTION_NAME}-access"
ENCRYPTION_POLICY_NAME = f"{COLLECTION_NAME}-encryption"
NETWORK_POLICY_NAME = f"{COLLECTION_NAME}-network"

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
                RoleSessionName="opensearch-create-collection"
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

def create_collection():
    """Create OpenSearch Serverless collection (policies applied automatically)"""
    
    # Get authenticated session
    session = get_credentials()
    client = session.client('opensearchserverless', region_name=REGION)
    
    print(f"🚀 Creating collection: {COLLECTION_NAME}")
    print(f"📋 Policies will be applied automatically:")
    print(f"   Security: {SECURITY_POLICY_NAME}")
    print(f"   Encryption: {ENCRYPTION_POLICY_NAME}")
    print(f"   Network: {NETWORK_POLICY_NAME}")
    
    try:
        response = client.create_collection(
            name=COLLECTION_NAME,
            type='VECTORSEARCH',
            description=f"Vector search collection {COLLECTION_NAME} created via Python"
        )
        
        print(f"✅ Collection creation started")
        print(f"   ID: {response['createCollectionDetail']['id']}")
        print(f"   ARN: {response['createCollectionDetail']['arn']}")
        
        # Wait for collection to become active
        print("⏳ Waiting for collection to become ACTIVE...")
        wait_for_active(client)
        
    except Exception as e:
        print(f"❌ Failed to create collection: {e}")
        if "policy" in str(e).lower():
            print("💡 Make sure all required policies exist:")
            print(f"   1. Run create_security_policy.py")
            print(f"   2. Run create_encryption_policy.py") 
            print(f"   3. Run create_network_policy.py")
        sys.exit(1)

def wait_for_active(client, timeout=300):
    """Wait for collection to reach ACTIVE status"""
    
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        try:
            response = client.batch_get_collection(names=[COLLECTION_NAME])
            
            if not response['collectionDetails']:
                print(f"❌ Collection {COLLECTION_NAME} not found")
                sys.exit(1)
            
            status = response['collectionDetails'][0]['status']
            
            if status == 'ACTIVE':
                endpoint = response['collectionDetails'][0]['collectionEndpoint']
                print(f"✅ Collection is ACTIVE!")
                print(f"📍 Endpoint: {endpoint}")
                return
            elif status == 'FAILED':
                print(f"❌ Collection creation failed")
                sys.exit(1)
            else:
                print(f"⏳ Status: {status}")
            
            time.sleep(10)
            
        except Exception as e:
            print(f"❌ Error checking collection status: {e}")
            sys.exit(1)
    
    print(f"⏰ Timeout after {timeout} seconds")
    sys.exit(1)

def main():
    print(f"Creating OpenSearch Serverless Collection")
    print(f"Collection: {COLLECTION_NAME}")
    print(f"Region: {REGION}")
    
    create_collection()
    
    print(f"\n🎉 Success! Vector search collection {COLLECTION_NAME} is ready")
    print("💡 Next steps:")
    print("   1. Create vector search indexes")
    print("   2. Index documents with vector embeddings")
    print("   3. Run kNN and hybrid search queries")

if __name__ == "__main__":
    main()