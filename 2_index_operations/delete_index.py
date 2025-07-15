#!/usr/bin/env python3
"""
Amazon OpenSearch Serverless - Delete Index Example
"""

import boto3
import sys
from opensearchpy import OpenSearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth

# Configuration
COLLECTION_NAME = "my-sample-collection"
INDEX_NAME = "vector-documents"
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
                RoleSessionName="opensearch-delete-index"
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

def get_collection_endpoint(collection_name, session):
    """Get the endpoint URL for a collection"""
    
    client = session.client('opensearchserverless', region_name=REGION)
    
    try:
        response = client.batch_get_collection(names=[collection_name])
        
        if response['collectionDetails']:
            collection = response['collectionDetails'][0]
            if collection['status'] != 'ACTIVE':
                print(f"❌ Collection {collection_name} is not active (Status: {collection['status']})")
                return None
            
            endpoint = collection['collectionEndpoint']
            # Remove https:// prefix for client creation
            return endpoint.replace('https://', '')
        else:
            print(f"❌ Collection {collection_name} not found")
            return None
            
    except Exception as e:
        print(f"❌ Error getting collection endpoint: {e}")
        return None

def get_opensearch_client(endpoint, session):
    """Create OpenSearch client with proper authentication"""
    
    # Get credentials for AWS4Auth
    if ROLE_ARN:
        # Use assumed role credentials
        sts = boto3.client('sts')
        response = sts.assume_role(
            RoleArn=ROLE_ARN,
            RoleSessionName="opensearch-client"
        )
        credentials = response['Credentials']
        auth = AWS4Auth(
            credentials['AccessKeyId'],
            credentials['SecretAccessKey'],
            REGION,
            'aoss',
            session_token=credentials['SessionToken']
        )
    else:
        # Use session credentials
        credentials = session.get_credentials()
        auth = AWS4Auth(
            credentials.access_key,
            credentials.secret_key,
            REGION,
            'aoss',
            session_token=credentials.token
        )
    
    return OpenSearch(
        hosts=[{'host': endpoint, 'port': 443}],
        http_auth=auth,
        use_ssl=True,
        verify_certs=True,
        connection_class=RequestsHttpConnection,
        pool_maxsize=20
    )

def get_index_info(client, index_name):
    """Get information about an index before deletion"""
    
    try:
        # Get index stats
        stats_response = client.indices.stats(index=index_name)
        index_stats = stats_response['indices'][index_name]
        
        # Get index settings and mappings
        index_info = client.indices.get(index=index_name)
        
        print(f"📋 Index information:")
        print(f"   Name: {index_name}")
        print(f"   Document count: {index_stats['total']['docs']['count']}")
        print(f"   Store size: {index_stats['total']['store']['size_in_bytes']} bytes")
        
        # Show field mappings
        mappings = index_info[index_name]['mappings']['properties']
        print(f"   Fields: {len(mappings)} total")
        
        # Show vector field info if present
        vector_fields = []
        for field_name, field_config in mappings.items():
            if field_config.get('type') == 'knn_vector':
                vector_fields.append(f"{field_name} ({field_config.get('dimension')}D)")
        
        if vector_fields:
            print(f"   Vector fields: {', '.join(vector_fields)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error getting index info: {e}")
        return False

def list_indices(client):
    """List all indices in the collection"""
    
    try:
        # Get all indices
        response = client.cat.indices(format='json')
        
        if response:
            print("📋 Available indices:")
            for index in response:
                print(f"   • {index['index']} (docs: {index.get('docs.count', 'N/A')}, size: {index.get('store.size', 'N/A')})")
        else:
            print("📋 No indices found in collection")
        
        return response
        
    except Exception as e:
        print(f"❌ Error listing indices: {e}")
        return []

def delete_index():
    """Delete index from the specified collection"""
    
    print(f"🔍 Getting collection endpoint for: {COLLECTION_NAME}")
    
    # Get authenticated session
    session = get_credentials()
    
    # Get collection endpoint
    endpoint = get_collection_endpoint(COLLECTION_NAME, session)
    if not endpoint:
        return False
    
    print(f"🔗 Collection endpoint: https://{endpoint}")
    
    # Create OpenSearch client
    print("🔐 Creating authenticated OpenSearch client...")
    client = get_opensearch_client(endpoint, session)
    
    try:
        # Check if index exists
        if not client.indices.exists(index=INDEX_NAME):
            print(f"❌ Index {INDEX_NAME} does not exist")
            
            # Show available indices
            print(f"\n📋 Checking available indices in collection {COLLECTION_NAME}...")
            list_indices(client)
            return False
        
        # Get index information
        print(f"\n📋 Getting information about index: {INDEX_NAME}")
        if not get_index_info(client, INDEX_NAME):
            print("⚠️  Could not retrieve index information, but index exists")
        
        # Confirmation prompt
        print(f"\n⚠️  WARNING: This will permanently delete index '{INDEX_NAME}'")
        print("   All documents and vector embeddings in this index will be lost!")
        
        response = input("   Type 'DELETE' to confirm: ")
        if response != 'DELETE':
            print("❌ Deletion cancelled")
            return False
        
        # Delete the index
        print(f"🗑️  Deleting index: {INDEX_NAME}")
        
        response = client.indices.delete(index=INDEX_NAME)
        
        print(f"✅ Index {INDEX_NAME} deleted successfully!")
        
        # Verify deletion
        print("🔍 Verifying index deletion...")
        if not client.indices.exists(index=INDEX_NAME):
            print(f"✅ Confirmed: Index {INDEX_NAME} has been deleted")
        else:
            print(f"⚠️  Warning: Index {INDEX_NAME} still exists")
        
        return True
        
    except Exception as e:
        print(f"❌ Error deleting index: {e}")
        return False

def main():
    print(f"Deleting OpenSearch Index")
    print(f"Collection: {COLLECTION_NAME}")
    print(f"Index: {INDEX_NAME}")
    print(f"Region: {REGION}")
    
    # Delete index
    success = delete_index()
    
    if success:
        print(f"\n🎉 Index {INDEX_NAME} deleted successfully!")
        print("💡 The collection and its policies remain intact")
        print("💡 You can create new indices in this collection anytime")
    else:
        print(f"\n💥 Failed to delete index {INDEX_NAME}")
        print("🔧 Troubleshooting tips:")
        print("   1. Verify collection exists and is ACTIVE")
        print("   2. Check data access policies")
        print("   3. Verify IAM permissions")
        print("   4. Confirm index name is correct")

if __name__ == "__main__":
    main()