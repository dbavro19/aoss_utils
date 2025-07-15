#!/usr/bin/env python3
"""
Amazon OpenSearch Serverless - Delete Documents by Query Example
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

# Delete criteria (set to None to disable a filter)
DELETE_CATEGORY = "tutorial"  # Delete documents with this category
DELETE_TAGS = ["vector-search"]  # Delete documents containing any of these tags
DELETE_SOURCE = None  # Delete documents from this source (set to "documentation" to enable)
DELETE_SCORE_RANGE = None  # Delete documents with score in range, e.g., {"gte": 5.0, "lte": 8.0}

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
                RoleSessionName="opensearch-delete-documents"
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

def build_delete_query():
    """Build the delete query based on metadata filters"""
    
    filters = []
    
    if DELETE_CATEGORY:
        filters.append({
            "term": {
                "category": DELETE_CATEGORY
            }
        })
    
    if DELETE_TAGS:
        filters.append({
            "terms": {
                "tags": DELETE_TAGS
            }
        })
    
    if DELETE_SOURCE:
        filters.append({
            "term": {
                "source": DELETE_SOURCE
            }
        })
    
    if DELETE_SCORE_RANGE:
        filters.append({
            "range": {
                "score": DELETE_SCORE_RANGE
            }
        })
    
    # Build query
    if not filters:
        print("❌ No delete criteria specified - this would delete ALL documents!")
        print("💡 Set at least one filter (DELETE_CATEGORY, DELETE_TAGS, etc.)")
        return None
    
    if len(filters) == 1:
        # Single filter
        delete_query = {
            "query": filters[0]
        }
    else:
        # Multiple filters (AND logic)
        delete_query = {
            "query": {
                "bool": {
                    "must": filters
                }
            }
        }
    
    return delete_query

def search_documents_to_delete(client, delete_query):
    """Search for documents matching delete criteria and return their IDs"""
    
    # Modify query to get document IDs and metadata for preview
    search_query = {
        "query": delete_query["query"],
        "size": 100,  # Get up to 100 documents
        "_source": {
            "excludes": ["vector_embedding"]  # Exclude large vector field
        }
    }
    
    try:
        response = client.search(
            index=INDEX_NAME,
            body=search_query
        )
        
        hits = response['hits']['hits']
        total_hits = response['hits']['total']['value']
        
        print(f"📊 Found {total_hits} documents matching delete criteria")
        
        if total_hits == 0:
            print("   No documents match the specified criteria")
            return [], []
        
        # Collect document IDs and metadata for preview
        doc_ids = []
        doc_metadata = []
        
        for hit in hits:
            doc_ids.append(hit['_id'])
            doc_metadata.append({
                'id': hit['_id'],
                'source': hit['_source']
            })
        
        print(f"📋 Preview of documents to be deleted (showing up to 10):")
        
        for i, doc in enumerate(doc_metadata[:10], 1):
            source = doc['source']
            print(f"\n📄 Document {i}:")
            print(f"   ID: {doc['id']}")
            print(f"   Title: {source.get('title', 'N/A')}")
            print(f"   Category: {source.get('category', 'N/A')}")
            print(f"   Tags: {', '.join(source.get('tags', []))}")
            print(f"   Source: {source.get('source', 'N/A')}")
        
        if total_hits > 10:
            print(f"\n   ... and {total_hits - 10} more documents")
        
        if total_hits > 100:
            print(f"\n⚠️  Note: Only first 100 documents will be deleted in this batch")
            print(f"   Run the script multiple times to delete all {total_hits} documents")
        
        return doc_ids, doc_metadata
        
    except Exception as e:
        print(f"❌ Error searching for documents: {e}")
        return [], []

def delete_documents_by_ids(client, doc_ids):
    """Delete documents by their individual IDs"""
    
    if not doc_ids:
        return True
    
    print(f"🗑️  Deleting {len(doc_ids)} documents...")
    
    deleted_count = 0
    failed_count = 0
    failed_ids = []
    
    for i, doc_id in enumerate(doc_ids, 1):
        try:
            response = client.delete(
                index=INDEX_NAME,
                id=doc_id
            )
            
            if response.get('result') == 'deleted':
                deleted_count += 1
            else:
                failed_count += 1
                failed_ids.append(doc_id)
            
            # Show progress for large batches
            if len(doc_ids) > 10 and i % 10 == 0:
                print(f"   Progress: {i}/{len(doc_ids)} processed...")
                
        except Exception as e:
            failed_count += 1
            failed_ids.append(doc_id)
            print(f"   Failed to delete document {doc_id}: {e}")
    
    print(f"✅ Delete operation completed!")
    print(f"   Documents deleted: {deleted_count}")
    print(f"   Failures: {failed_count}")
    
    if failed_ids:
        print(f"❌ Failed to delete these document IDs:")
        for failed_id in failed_ids[:5]:  # Show first 5 failed IDs
            print(f"   - {failed_id}")
        if len(failed_ids) > 5:
            print(f"   ... and {len(failed_ids) - 5} more")
    
    return failed_count == 0

def delete_documents():
    """Delete documents matching the specified criteria"""
    
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
            print("💡 Create the index and add documents first")
            return False
        
        # Build delete query
        delete_query = build_delete_query()
        if not delete_query:
            return False
        
        print(f"🔍 Delete criteria:")
        if DELETE_CATEGORY:
            print(f"   Category: {DELETE_CATEGORY}")
        if DELETE_TAGS:
            print(f"   Tags: {DELETE_TAGS}")
        if DELETE_SOURCE:
            print(f"   Source: {DELETE_SOURCE}")
        if DELETE_SCORE_RANGE:
            print(f"   Score range: {DELETE_SCORE_RANGE}")
        
        # Search for documents to be deleted
        print(f"\n📋 Searching for documents that match delete criteria...")
        doc_ids, doc_metadata = search_documents_to_delete(client, delete_query)
        
        if not doc_ids:
            print("✅ No documents to delete")
            return True
        
        # Confirmation prompt
        print(f"\n⚠️  WARNING: This will permanently delete {len(doc_ids)} document(s)")
        print("   All vector embeddings and metadata will be lost!")
        
        response = input("   Type 'DELETE' to confirm: ")
        if response != 'DELETE':
            print("❌ Deletion cancelled")
            return False
        
        # Delete documents by their IDs
        success = delete_documents_by_ids(client, doc_ids)
        
        return success
        
    except Exception as e:
        print(f"❌ Error deleting documents: {e}")
        return False

def main():
    print(f"Deleting Documents from OpenSearch Vector Index")
    print(f"Collection: {COLLECTION_NAME}")
    print(f"Index: {INDEX_NAME}")
    print(f"Region: {REGION}")
    
    # Delete documents
    success = delete_documents()
    
    if success:
        print(f"\n🎉 Delete operation completed successfully!")
        print("💡 Tips:")
        print("   • Modify delete criteria variables to target different documents")
        print("   • Use multiple filters for precise targeting")
        print("   • Preview always shows which documents will be deleted")
    else:
        print(f"\n💥 Delete operation failed")
        print("🔧 Troubleshooting tips:")
        print("   1. Verify collection exists and is ACTIVE")
        print("   2. Verify index exists and has documents")
        print("   3. Check data access policies")
        print("   4. Verify IAM permissions")
        print("   5. Ensure at least one delete criteria is specified")

if __name__ == "__main__":
    main()