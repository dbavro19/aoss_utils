#!/usr/bin/env python3
"""
Amazon OpenSearch Serverless - Write Document Example
"""

import boto3
import sys
import json
from datetime import datetime
from opensearchpy import OpenSearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth

# Configuration
COLLECTION_NAME = "my-sample-collection"
INDEX_NAME = "vector-documents"
REGION = "us-east-1"
ROLE_ARN = None  # Set to your role ARN if needed: "arn:aws:iam::123456789012:role/OpenSearchRole"

# Vector configuration (matching your Bedrock model)
VECTOR_DIMENSION = 1024
VECTOR_FIELD_NAME = "vector_embedding"

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
                RoleSessionName="opensearch-write-document"
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

def create_sample_document(session):
    """Create a sample document with metadata matching the index structure"""
    
    # Create Bedrock client
    bedrock = session.client('bedrock-runtime', region_name=REGION)
    
    # Sample content for embedding
    content = "This document explains how to implement vector search using Amazon Bedrock embedding models with OpenSearch Serverless. Vector search enables semantic similarity matching for documents and improves search relevance beyond traditional keyword matching."
    
    print("🔄 Generating embedding with Bedrock Titan model...")
    try:
        embedding = get_embedding(bedrock, content)
        print(f"✅ Generated embedding with {len(embedding)} dimensions")
    except Exception as e:
        print(f"❌ Failed to generate embedding: {e}")
        return None
    
    # Sample document with your metadata structure
    document = {
        VECTOR_FIELD_NAME: embedding,  # Real Bedrock embedding
        "title": "Introduction to Vector Search with Amazon Bedrock",
        "content": content,
        "category": "tutorial",
        "tags": ["vector-search", "bedrock", "opensearch", "aws"],
        "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "score": 8.5,
        "source": "documentation",
        "metadata": {
            "author": "AWS Documentation Team", 
            "department": "Engineering",
            "version": "1.0",
            "language": "en"
        }
    }
    
    return document

def write_document():
    """Write a document to the vector search index"""
    
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
            print("💡 Create the index first using create_index.py")
            return False
        
        # Create sample document
        print("📄 Creating sample document...")
        document = create_sample_document(session)
        
        if not document:
            print("❌ Failed to create document")
            return False
        
        print(f"📋 Document details:")
        print(f"   Title: {document['title']}")
        print(f"   Category: {document['category']}")
        print(f"   Tags: {', '.join(document['tags'])}")
        print(f"   Source: {document['source']}")
        print(f"   Vector dimensions: {len(document[VECTOR_FIELD_NAME])}")
        
        # Index the document (let OpenSearch auto-generate ID)
        print(f"🚀 Indexing document to: {INDEX_NAME}")
        
        response = client.index(
            index=INDEX_NAME,
            body=document
        )
        
        print(f"✅ Document indexed successfully!")
        print(f"   Document ID: {response['_id']}")
        print(f"   Index: {response['_index']}")
        print(f"   Result: {response['result']}")
        
        return True
        
    except Exception as e:
        print(f"❌ Error indexing document: {e}")
        return False

def main():
    print(f"Writing Document to OpenSearch Vector Index")
    print(f"Collection: {COLLECTION_NAME}")
    print(f"Index: {INDEX_NAME}")
    print(f"Region: {REGION}")
    print(f"Vector Dimensions: {VECTOR_DIMENSION}")
    
    # Write document
    success = write_document()
    
    if success:
        print(f"\n🎉 Document written successfully!")
        print("💡 Next steps:")
        print("   1. Index more documents")
        print("   2. Run similarity searches")
        print("   3. Try hybrid search queries")
        print("\n🔍 Using real Bedrock Titan embeddings")
    else:
        print(f"\n💥 Failed to write document")
        print("🔧 Troubleshooting tips:")
        print("   1. Verify collection exists and is ACTIVE")
        print("   2. Verify index exists")
        print("   3. Check data access policies")
        print("   4. Verify IAM permissions")

if __name__ == "__main__":
    main()