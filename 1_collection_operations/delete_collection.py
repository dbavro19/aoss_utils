#!/usr/bin/env python3
"""
Amazon OpenSearch Serverless - Delete Collection Example
"""

import boto3
import time
import sys

# Configuration
COLLECTION_NAME = "my-sample-collection"
REGION = "us-east-1"
ROLE_ARN = None  # Set to your role ARN if needed: "arn:aws:iam::123456789012:role/OpenSearchRole"

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
                RoleSessionName="opensearch-delete-collection"
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

def get_collection_info(client):
    """Get collection information before deletion"""
    try:
        response = client.batch_get_collection(names=[COLLECTION_NAME])
        
        if response['collectionDetails']:
            collection = response['collectionDetails'][0]
            print(f"📋 Collection found:")
            print(f"   Name: {collection['name']}")
            print(f"   ID: {collection['id']}")
            print(f"   Status: {collection['status']}")
            print(f"   Type: {collection['type']}")
            print(f"   Endpoint: {collection.get('collectionEndpoint', 'N/A')}")
            return collection['id']  # Return the ID for deletion
        else:
            print(f"❌ Collection {COLLECTION_NAME} not found")
            return None
            
    except Exception as e:
        print(f"❌ Error getting collection info: {e}")
        return None

def delete_collection():
    """Delete OpenSearch Serverless collection"""
    
    # Get authenticated session
    session = get_credentials()
    client = session.client('opensearchserverless', region_name=REGION)
    
    print(f"🔍 Checking collection: {COLLECTION_NAME}")
    
    # Get collection info and ID
    collection_id = get_collection_info(client)
    if not collection_id:
        sys.exit(1)
    
    # Confirmation prompt
    print(f"\n⚠️  WARNING: This will permanently delete collection '{COLLECTION_NAME}'")
    print("   All data in this collection will be lost!")
    
    response = input("   Type 'DELETE' to confirm: ")
    if response != 'DELETE':
        print("❌ Deletion cancelled")
        sys.exit(0)
    
    print(f"🗑️  Deleting collection: {COLLECTION_NAME}")
    
    try:
        response = client.delete_collection(id=collection_id)
        
        print(f"✅ Collection deletion initiated")
        print(f"   ID: {response['deleteCollectionDetail']['id']}")
        print(f"   Status: {response['deleteCollectionDetail']['status']}")
        
        # Wait for deletion to complete
        print("⏳ Waiting for deletion to complete...")
        wait_for_deletion(client)
        
    except Exception as e:
        print(f"❌ Failed to delete collection: {e}")
        sys.exit(1)

def wait_for_deletion(client, timeout=300):
    """Wait for collection to be completely deleted"""
    
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        try:
            response = client.batch_get_collection(names=[COLLECTION_NAME])
            
            if not response['collectionDetails']:
                print(f"✅ Collection {COLLECTION_NAME} has been deleted")
                return
            else:
                status = response['collectionDetails'][0]['status']
                print(f"⏳ Status: {status}")
            
            time.sleep(10)
            
        except Exception as e:
            # If we get an error that collection doesn't exist, it's deleted
            if "does not exist" in str(e).lower() or "not found" in str(e).lower():
                print(f"✅ Collection {COLLECTION_NAME} has been deleted")
                return
            print(f"❌ Error checking deletion status: {e}")
            time.sleep(10)
    
    print(f"⏰ Timeout after {timeout} seconds - deletion may still be in progress")
    sys.exit(1)

def main():
    print(f"Deleting OpenSearch Serverless Collection")
    print(f"Collection: {COLLECTION_NAME}")
    print(f"Region: {REGION}")
    
    delete_collection()
    
    print(f"\n🎉 Success! Collection {COLLECTION_NAME} has been deleted")
    print("💡 Note: Associated policies still exist and can be reused:")
    print(f"   • {COLLECTION_NAME}-access (security policy)")
    print(f"   • {COLLECTION_NAME}-encryption (encryption policy)")
    print(f"   • {COLLECTION_NAME}-network (network policy)")

if __name__ == "__main__":
    main()