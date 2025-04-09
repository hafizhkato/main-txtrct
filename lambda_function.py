import boto3
import csv
from botocore.signers import CloudFrontSigner
import io
import json
import base64
import datetime
import os
import rsa
from collections import defaultdict
from urllib.parse import unquote_plus

# Initialize AWS clients
s3 = boto3.client("s3")
dynamodb = boto3.resource("dynamodb")
TABLE_NAME = os.getenv("DYNAMO_DB_TABLE_NAME")
WEBSOCKET_TABLE_NAME = os.getenv("WEBSOCKET_TABLE_NAME")
table = dynamodb.Table(WEBSOCKET_TABLE_NAME)

api_gateway = boto3.client('apigatewaymanagementapi', 
    endpoint_url= os.getenv("ENDPOINT_URL"))

# CloudFront Configuration
CLOUDFRONT_DOMAIN = os.getenv("CDN_DOMAIN")
KEY_PAIR_ID = os.getenv("KEY_PAIR_ID")

def get_rsa_key_from_secret():
    """Fetches RSA private key from Secrets Manager (plaintext format)."""
    secret_name = os.getenv("SECRET_NAME")
    region = os.getenv("REGION")
    secrets_client = boto3.client("secretsmanager", region_name=region)
    response = secrets_client.get_secret_value(SecretId=secret_name)
    
    return response["SecretString"]  # Just return the string directly

def rsa_signer(message):
    """Signs CloudFront policy using RSA private key from Secrets Manager."""
    private_key = get_rsa_key_from_secret()
    return rsa.sign(message, rsa.PrivateKey.load_pkcs1(private_key.encode("utf-8")), "SHA-1")


def generate_signed_url(file_path):
    """Generates a signed CloudFront URL for secure file download."""
    expire_date = datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # 1-hour expiration
    cf_signer = CloudFrontSigner(KEY_PAIR_ID, rsa_signer)

    # Generate signed URL
    signed_url = cf_signer.generate_presigned_url(
        f"{CLOUDFRONT_DOMAIN}/{file_path}", 
        date_less_than=expire_date
    )
    
    return signed_url

def get_kv_map(bucket, key):
    """Extracts key-value pairs using Textract."""
    textract = boto3.client("textract")
    response = textract.analyze_document(
        Document={"S3Object": {"Bucket": bucket, "Name": key}}, 
        FeatureTypes=["FORMS"]
    )

    key_map, value_map, block_map = {}, {}, {}
    for block in response["Blocks"]:
        block_id = block["Id"]
        block_map[block_id] = block
        if block["BlockType"] == "KEY_VALUE_SET":
            if "KEY" in block["EntityTypes"]:
                key_map[block_id] = block
            else:
                value_map[block_id] = block

    return key_map, value_map, block_map

def get_kv_relationship(key_map, value_map, block_map):
    """Maps key-value relationships."""
    kvs = defaultdict(list)
    for key_block in key_map.values():
        key = get_text(key_block, block_map)
        value_block = find_value_block(key_block, value_map)
        value = get_text(value_block, block_map)
        kvs[key].append(value)
    return kvs

def find_value_block(key_block, value_map):
    """Finds the value block associated with a key block."""
    for rel in key_block.get("Relationships", []):
        if rel["Type"] == "VALUE":
            for value_id in rel["Ids"]:
                return value_map.get(value_id)
    return None

def get_text(block, block_map):
    """Extracts text from a block."""
    text = ""
    if "Relationships" in block:
        for rel in block["Relationships"]:
            if rel["Type"] == "CHILD":
                for child_id in rel["Ids"]:
                    word = block_map[child_id]
                    if word["BlockType"] == "WORD":
                        text += word["Text"] + " "
                    elif word["BlockType"] == "SELECTION_ELEMENT" and word["SelectionStatus"] == "SELECTED":
                        text += "X"
    return text.strip()

def store_in_dynamodb(user_id, document_id, kvs):
    """Stores all extracted fields in one DynamoDB item."""
    table = dynamodb.Table(TABLE_NAME)
    
    # Convert key-value pairs into a single dictionary
    field_data = {key: values[0] for key, values in kvs.items()}

    #  Wrap data inside "Item={}"
    table.put_item(Item={
        "user_id": user_id,        # Partition Key
        "document_id": document_id,  # Sort Key
        "fields": field_data       # Store all extracted data in one column
    })


def generate_csv(document_id, kvs):
    """Generates CSV as a base64-encoded string."""
    with io.StringIO() as output:
        writer = csv.writer(output)
        writer.writerow(["Field Name", "Field Value"])
        for key, value in kvs.items():
            writer.writerow([key, value[0]])
        return output.getvalue()


def notify_clients(user_id, signed_url):
    """Sends WebSocket notifications to connected clients."""
    response = table.scan()
    connections = response.get('Items', [])
    print("Scanned Connections:", connections)  # Debugging line
    print("user id:", user_id)  # Debugging line

    for connection in connections:
        print("Checking connection:", connection)  # Debugging line
        print("user id:", user_id)  # Debugging line
        # Ensure 'user_id' exists in the connection item
        if "user_id" in connection and connection["user_id"] == user_id:
            connection_id = connection["connectionId"]
            try:
                api_gateway.post_to_connection(
                    ConnectionId=connection_id,
                    Data=json.dumps({"status": "ready", "url": signed_url})
                    
                )
            except Exception as e:
                print(f"Error sending WebSocket message: {e}")
                if "GoneException" in str(e):  # If connection is stale, remove from DB
                    table.delete_item(Key={'connectionId': connection_id})


def store_csv_in_s3(bucket, user_id, document_id, csv_data):
    """Uploads the generated CSV to the processed-document folder in S3."""
    s3_key = f"processed-document/{user_id}/{document_id}.csv"

    s3.put_object(
        Bucket=bucket,
        Key=s3_key,
        Body=csv_data.encode(),
        ContentType="text/csv",
        Metadata={"delete_after": "1d"}
    )

    return s3_key  # Return the object key instead of a pre-signed URL

def lambda_handler(event, context):
    """Main Lambda handler function."""
    try:
        file_obj = event["Records"][0]
        bucket = unquote_plus(file_obj["s3"]["bucket"]["name"])
        file_name = unquote_plus(file_obj["s3"]["object"]["key"])  # Moved up to define before use
        
        parts = file_name.split("/")
        user_id = parts[1]  # Extract user ID from path
        document_id = file_name.split("/")[-1].split(".")[0]  # Extract document name without extension
        
        key_map, value_map, block_map = get_kv_map(bucket, file_name)
        kvs = get_kv_relationship(key_map, value_map, block_map)
        
        store_in_dynamodb(user_id, document_id, kvs)  # Cache in DynamoDB
        csv_encoded = generate_csv(document_id, kvs)  # Generate CSV

        s3_key = store_csv_in_s3(bucket, user_id, document_id, csv_encoded)

        # Generate CloudFront signed URL
        signed_url = generate_signed_url(s3_key)

        # Notify frontend
        notify_clients(user_id, signed_url)
        
        return {
            "statusCode": 200,
            "body": json.dumps({"message": "File processed successfully", "csv_url": signed_url})
        }

    except Exception as e:
        print(f"Error in Lambda function: {str(e)}")
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }

