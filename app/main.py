from fastapi import FastAPI, Request, Response, HTTPException
import os
import csv
from datetime import datetime
from threading import Lock
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename='service.log'
)

app = FastAPI()

# Lock for thread-safe writing to the log file
log_lock = Lock()

# Function to load API keys from the key file
def load_api_keys(file_path):
    api_keys = {}
    try:
        with open(file_path, "r") as file:
            for line in file:
                line = line.strip()
                if line:
                    username, api_key = line.split('=')
                    api_keys[username.strip()] = api_key.strip()
    except Exception as e:
        logging.error(f"Error reading API keys from file '{file_path}': {e}")
    return api_keys

# Load valid_keys.conf and parse keys
API_KEYS_FILE_PATH = ".env"
VALID_API_KEYS = load_api_keys(API_KEYS_FILE_PATH)

# Define a middleware function to log requests
@app.middleware("http")
async def log_requests(request: Request, call_next):
    # Log the request details
    log_line = f"Time: {datetime.now()}, Method: {request.method}, Path: {request.url.path}\n"
    logging.info(log_line)
    
    # Proceed with the request
    response = await call_next(request)
    return response

# Function to log API usage
def log_api_usage(api_key, endpoint):
    log_file_path = "./api_usage.csv"
    # Find the username by the given API key
    username = next((user for user, key in VALID_API_KEYS.items() if key == api_key), None)
    with log_lock:
        try:
            with open(log_file_path, "a", newline='') as log_file:
                csv_writer = csv.writer(log_file)
                # Log the datetime, username, API key, and endpoint
                csv_writer.writerow([datetime.now(), username, api_key, endpoint])
        except Exception as e:
            logging.error(f"Error writing to api_usage.csv: {e}")

# Function to log invalid API usage
def log_invalid_api_usage(api_key, endpoint):
    log_file_path = "./invalid_api_usage.csv"
    with log_lock:
        try:
            with open(log_file_path, "a", newline='') as log_file:
                csv_writer = csv.writer(log_file)
                csv_writer.writerow([datetime.now(), api_key, endpoint])
        except Exception as e:
            logging.error(f"Error writing to invalid_api_usage.csv: {e}")

# Function to validate the API key
@app.api_route("/validate", methods=["GET", "POST"])
async def validate_api_key(request: Request):
    authorization: str = request.headers.get("Authorization", "")
    
    if not authorization.startswith("Bearer "):
        log_invalid_api_usage(api_key="no_api_key", endpoint="/validate")
        return Response("Invalid API Key format", status_code=400, headers={"Proxy-Status": "invalid_api_key_format"})

    api_key = authorization[7:]  # Remove the 'Bearer ' prefix
    
    if_usage: str = request.headers.get("usage", "")

    if api_key in VALID_API_KEYS.values():
        # Log API usage after successful validation
        if if_usage == "True":
            log_file_path = "./api_usage.csv"
            try:
                with log_lock:
                    with open(log_file_path, mode="r", newline='') as csvfile:
                        reader = csv.reader(csvfile)
                        # Skipping header row, adjust if your CSV doesn't have one
                        next(reader, None)
                        entries = [{"timestamp": row[0], "username": row[1], "endpoint": row[3]} for row in reader]
                log_api_usage(api_key, "/usage")
                return Response(str(entries), status_code=403) # Return usage data. TODO: Change the status code.
            except Exception as e:
                logging.error(f"Error reading from api_usage.csv: {e}")
                raise HTTPException(status_code=500, detail="Failed to read usage data")
        else:
            log_api_usage(api_key, "/validate")
            return Response("API Key validation successful", status_code=200, headers={"Proxy-Status": "valid_api_key"})
    else:
        log_invalid_api_usage(api_key, "/validate")
        return Response("Invalid API Key", status_code=401, headers={"Proxy-Status": "invalid_api_key"})