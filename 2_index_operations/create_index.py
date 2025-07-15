#!/usr/bin/env python3
"""
Amazon OpenSearch Serverless - Create Vector Search Index Example
"""

import boto3
import json
from opensearchpy import OpenSearch, RequestsHttpConnection
from requests_aws4auth import AWS4Auth

# Configuration
COLLECTION_NAME = "my-sample-collection"
INDEX_NAME = "vector-documents"
REGION = "us-east-1"
ROLE_ARN = None  # Set to your role ARN if needed: "arn:aws:iam::123456789012:role/OpenSearchRole"

# Vector field configuration
VECTOR_DIMENSION = 1024 #modify this based on your embedding model's dimensionality 
VECTOR_SIMILARITY = "l2"  # Options: cosinesimil, l2, innerproduct
VECTOR_FIELD_NAME = "vector_embedding"
VECTOR_ENGINE = "faiss"  # Options: faiss, nmslib, lucene

# Metadata fields configuration
METADATA_FIELDS = {
    "title": {"type": "text", "searchable": True},
    "content": {"type": "text", "searchable": True},
    "category": {"type": "keyword", "searchable": True},
    "tags": {"type": "keyword", "searchable": True},
    "timestamp": {"type": "date", "searchable": False},
    "score": {"type": "float", "searchable": False},
    "source": {"type": "keyword", "searchable": True},
    "metadata": {"type": "object", "searchable": False}
}

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
                RoleSessionName="opensearch-create-vector-index"
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

def build_vector_mapping():
    """Build the vector field mapping"""
    
    vector_mapping = {
        "type": "knn_vector",
        "dimension": VECTOR_DIMENSION,
        "method": {
            "name": "hnsw",
            "space_type": VECTOR_SIMILARITY,
            "engine": VECTOR_ENGINE
        }
    }
    
    # Add engine-specific parameters
    if VECTOR_ENGINE == "faiss":
        vector_mapping["method"]["parameters"] = {
            "ef_construction": 128,
            "m": 24
        }
    elif VECTOR_ENGINE == "nmslib":
        vector_mapping["method"]["parameters"] = {
            "ef_construction": 128,
            "m": 24
        }
    
    return vector_mapping

def build_metadata_mappings():
    """Build metadata field mappings based on configuration"""
    
    mappings = {}
    
    for field_name, config in METADATA_FIELDS.items():
        field_type = config["type"]
        searchable = config["searchable"]
        
        if field_type == "text":
            field_mapping = {
                "type": "text",
                "analyzer": "standard"
            }
            if not searchable:
                field_mapping["index"] = False
                
        elif field_type == "keyword":
            field_mapping = {
                "type": "keyword"
            }
            if not searchable:
                field_mapping["index"] = False
                
        elif field_type == "date":
            field_mapping = {
                "type": "date",
                "format": "yyyy-MM-dd'T'HH:mm:ss'Z'||epoch_millis"
            }
            if not searchable:
                field_mapping["index"] = False
                
        elif field_type == "float":
            field_mapping = {
                "type": "float"
            }
            if not searchable:
                field_mapping["index"] = False
                
        elif field_type == "integer":
            field_mapping = {
                "type": "integer"
            }
            if not searchable:
                field_mapping["index"] = False
                
        elif field_type == "object":
            field_mapping = {
                "type": "object"
            }
            if not searchable:
                field_mapping["enabled"] = False
                
        else:
            print(f"⚠️  Unknown field type '{field_type}' for field '{field_name}', skipping")
            continue
            
        mappings[field_name] = field_mapping
    
    return mappings

def create_vector_index():
    """Create vector search index in the specified collection"""
    
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
        # Check if index already exists
        if client.indices.exists(index=INDEX_NAME):
            print(f"⚠️  Index {INDEX_NAME} already exists")
            return False
        
        # Build vector field mapping
        vector_mapping = build_vector_mapping()
        
        # Build metadata field mappings
        metadata_mappings = build_metadata_mappings()
        
        # Combine all mappings
        all_mappings = {
            VECTOR_FIELD_NAME: vector_mapping,
            **metadata_mappings
        }
        
        # Create index mapping
        index_mapping = {
            "mappings": {
                "properties": all_mappings
            },
            "settings": {
                "index": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "refresh_interval": "10s",
                    "knn": True
                }
            }
        }
        
        print(f"🚀 Creating vector search index: {INDEX_NAME}")
        print(f"📋 Vector configuration:")
        print(f"   Field: {VECTOR_FIELD_NAME}")
        print(f"   Dimensions: {VECTOR_DIMENSION}")
        print(f"   Similarity: {VECTOR_SIMILARITY}")
        print(f"   Engine: {VECTOR_ENGINE}")
        print(f"📋 Metadata fields: {list(METADATA_FIELDS.keys())}")
        
        # Create the index
        response = client.indices.create(
            index=INDEX_NAME,
            body=index_mapping
        )
        
        print(f"✅ Vector search index {INDEX_NAME} created successfully!")
        
        # Verify index creation
        print("🔍 Verifying index creation...")
        index_info = client.indices.get(index=INDEX_NAME)
        
        properties = index_info[INDEX_NAME]['mappings']['properties']
        print(f"✅ Index verification successful:")
        print(f"   Index: {INDEX_NAME}")
        print(f"   Total fields: {len(properties)}")
        print(f"   Vector field: {VECTOR_FIELD_NAME} ({properties[VECTOR_FIELD_NAME]['dimension']}D)")
        
        return True
        
    except Exception as e:
        print(f"❌ Error creating vector index: {e}")
        return False

def main():
    print(f"Creating OpenSearch Vector Search Index")
    print(f"Collection: {COLLECTION_NAME}")
    print(f"Index: {INDEX_NAME}")
    print(f"Region: {REGION}")
    
    # Create vector index
    success = create_vector_index()
    
    if success:
        print(f"\n🎉 Vector search index {INDEX_NAME} created successfully!")
        print("💡 Next steps:")
        print("   1. Index documents with vector embeddings")
        print("   2. Run kNN similarity searches")
        print("   3. Try hybrid search (vector + text)")
        print(f"\n📋 Example document structure:")
        print("   {")
        print(f'     "{VECTOR_FIELD_NAME}": [0.1, 0.2, ...],  # {VECTOR_DIMENSION} dimensions')
        for field in list(METADATA_FIELDS.keys())[:3]:
            print(f'     "{field}": "example value",')
        print("     ...")
        print("   }")
    else:
        print(f"\n💥 Failed to create vector index {INDEX_NAME}")
        print("🔧 Troubleshooting tips:")
        print("   1. Verify collection exists and is ACTIVE")
        print("   2. Check data access policies")
        print("   3. Verify IAM permissions")
        print("   4. Ensure collection type is VECTORSEARCH")

if __name__ == "__main__":
    main()