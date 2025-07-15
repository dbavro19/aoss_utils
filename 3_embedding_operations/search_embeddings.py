#!/usr/bin/env python3
"""
Amazon OpenSearch Serverless - Search Documents Example
"""

import boto3
import sys
import json
from opensearchpy import OpenSearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth

# Configuration
COLLECTION_NAME = "my-sample-collection"
INDEX_NAME = "vector-documents"
REGION = "us-east-1"
ROLE_ARN = None  # Set to your role ARN if needed: "arn:aws:iam::123456789012:role/OpenSearchRole"

# Vector configuration
VECTOR_FIELD_NAME = "vector_embedding"

# Search configuration
SEARCH_QUERY = "How to use vector search with Amazon Bedrock"
RESULT_SIZE = 5  # Number of results to return
K_VALUE = 10  # Number of nearest neighbors to find

# Metadata filters (set to None to disable a filter)
FILTER_CATEGORY = "tutorial"  # Filter by category
FILTER_TAGS = ["bedrock", "vector-search"]  # Must contain at least one of these tags
FILTER_SOURCE = None  # Filter by source (set to "documentation" to enable)

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
                RoleSessionName="opensearch-search-documents"
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

def get_embedding(bedrock, userQuery):
    """Get embedding from Amazon Bedrock Titan model"""
    body = json.dumps({"inputText": userQuery})
    modelId = 'amazon.titan-embed-text-v2:0'
    accept = 'application/json'
    contentType = 'application/json'
    response = bedrock.invoke_model(body=body, modelId=modelId, accept=accept, contentType=contentType)
    response_body = json.loads(response.get('body').read())
    embedding = response_body.get('embedding')
    return embedding

def build_search_query(query_embedding):
    """Build the search query with vector similarity and metadata filters"""
    
    # Base kNN query
    search_query = {
        "size": RESULT_SIZE,
        "query": {
            "bool": {
                "must": [
                    {
                        "knn": {
                            VECTOR_FIELD_NAME: {
                                "vector": query_embedding,
                                "k": K_VALUE
                            }
                        }
                    }
                ]
            }
        },
        "_source": {
            "excludes": [VECTOR_FIELD_NAME]  # Don't return the large embedding vector
        }
    }
    
    # Add metadata filters
    filters = []
    
    if FILTER_CATEGORY:
        filters.append({
            "term": {
                "category": FILTER_CATEGORY
            }
        })
    
    if FILTER_TAGS:
        filters.append({
            "terms": {
                "tags": FILTER_TAGS
            }
        })
    
    if FILTER_SOURCE:
        filters.append({
            "term": {
                "source": FILTER_SOURCE
            }
        })
    
    # Add filters to query if any exist
    if filters:
        search_query["query"]["bool"]["filter"] = filters
    
    return search_query

def search_documents():
    """Search for similar documents using vector search and metadata filters"""
    
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
        
        # Generate embedding for search query
        print(f"🔄 Generating embedding for query: '{SEARCH_QUERY}'")
        bedrock = session.client('bedrock-runtime', region_name=REGION)
        
        try:
            query_embedding = get_embedding(bedrock, SEARCH_QUERY)
            print(f"✅ Generated query embedding with {len(query_embedding)} dimensions")
        except Exception as e:
            print(f"❌ Failed to generate query embedding: {e}")
            return False
        
        # Build search query
        search_query = build_search_query(query_embedding)
        
        print(f"🔍 Search configuration:")
        print(f"   Query: {SEARCH_QUERY}")
        print(f"   Results: {RESULT_SIZE}")
        print(f"   K value: {K_VALUE}")
        print(f"   Filters:")
        if FILTER_CATEGORY:
            print(f"     Category: {FILTER_CATEGORY}")
        if FILTER_TAGS:
            print(f"     Tags: {FILTER_TAGS}")
        if FILTER_SOURCE:
            print(f"     Source: {FILTER_SOURCE}")
        if not any([FILTER_CATEGORY, FILTER_TAGS, FILTER_SOURCE]):
            print(f"     No filters applied")
        
        # Execute search
        print(f"\n🚀 Executing hybrid search...")
        
        response = client.search(
            index=INDEX_NAME,
            body=search_query
        )
        
        # Process results
        hits = response['hits']['hits']
        total_hits = response['hits']['total']['value']
        
        print(f"\n✅ Search completed!")
        print(f"📊 Found {total_hits} matching documents")
        print(f"📋 Showing top {len(hits)} results:")
        
        if not hits:
            print("   No documents found matching the search criteria")
            return True
        
        # Display results
        for i, hit in enumerate(hits, 1):
            source = hit['_source']
            score = hit['_score']
            
            print(f"\n📄 Result {i} (Score: {score:.4f}):")
            print(f"   ID: {hit['_id']}")
            print(f"   Title: {source.get('title', 'N/A')}")
            print(f"   Category: {source.get('category', 'N/A')}")
            print(f"   Tags: {', '.join(source.get('tags', []))}")
            print(f"   Source: {source.get('source', 'N/A')}")
            print(f"   Score: {source.get('score', 'N/A')}")
            
            # Show first 150 chars of content
            content = source.get('content', '')
            if content:
                preview = content[:150] + "..." if len(content) > 150 else content
                print(f"   Content: {preview}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error searching documents: {e}")
        return False

def main():
    print(f"Searching OpenSearch Vector Index")
    print(f"Collection: {COLLECTION_NAME}")
    print(f"Index: {INDEX_NAME}")
    print(f"Region: {REGION}")
    
    # Search documents
    success = search_documents()
    
    if success:
        print(f"\n🎉 Search completed successfully!")
        print("💡 Tips:")
        print("   • Modify SEARCH_QUERY to try different searches")
        print("   • Adjust metadata filters to narrow results")
        print("   • Change K_VALUE to get more/fewer candidates")
        print("   • Increase RESULT_SIZE to see more results")
    else:
        print(f"\n💥 Search failed")
        print("🔧 Troubleshooting tips:")
        print("   1. Verify collection exists and is ACTIVE")
        print("   2. Verify index exists and has documents")
        print("   3. Check data access policies")
        print("   4. Verify IAM permissions")

if __name__ == "__main__":
    main()