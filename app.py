from flask import Flask, request


import base64
import gzip
import json
import logging
import os 
import requests
import datetime
import hashlib
import hmac
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential


app = Flask("strata_log_forwarding_to_Sentinel")

KEYVAULT_URI = "https://prismacloudsaselogkv1.vault.azure.net/"
# Setup KeyVault client
credential = DefaultAzureCredential()
client = SecretClient(vault_url=KEYVAULT_URI, credential=credential)

# Fetch WORKSPACE_ID from KeyVault
WORKSPACE_ID = client.get_secret("LogAnalyticsWorkspaceId").value
SHARED_KEY = os.environ.get('SHARED_KEY')

# Fetch SHARED_KEY from KeyVault
SHARED_KEY = client.get_secret("LogAnalyticsWorkspaceKey").value

if (WORKSPACE_ID is None or SHARED_KEY is None):
    raise Exception("Please add azure sentinel customer_id and shared_key to azure key vault/application settings of web app") 


BASIC_AUTH = base64.b64encode("{}:{}".format(WORKSPACE_ID, SHARED_KEY).encode()).decode("utf-8")
LOG_TYPE = 'Log-Type'
HTTPS = 'https://'
AZURE_URL = '.ods.opinsights.azure.com'
AZURE_API_VERSION = '?api-version=2016-04-01'
RESOURCE = '/api/logs'
POST_METHOD = 'POST'
CONTENT_TYPE = 'application/json'
URI = "{}{}{}{}{}".format(HTTPS, WORKSPACE_ID, AZURE_URL, RESOURCE, AZURE_API_VERSION)
POOL = requests.Session()
POOL.mount(URI, requests.adapters.HTTPAdapter(pool_connections=1, pool_maxsize=8))
FAILURE_RESPONSE = json.dumps({'success':False})
SUCCESS_RESPONSE = json.dumps({'success':True})
APPLICATION_JSON = {'ContentType':'application/json'}


class UnAuthorizedException(Exception):
    pass


class ProcessingException(Exception):
    pass


# Build the API signature
def build_signature(customer_id, shared_key, date, content_length, method, content_type, resource):
    x_headers = 'x-ms-date:' + date
    string_to_hash = "{}\n{}\n{}\n{}\n{}".format(method, str(content_length), content_type, x_headers, resource)
    bytes_to_hash = bytes(string_to_hash, encoding="utf-8")
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(hmac.new(decoded_key, bytes_to_hash, digestmod=hashlib.sha256).digest()).decode()
    authorization = "SharedKey {}:{}".format(customer_id,encoded_hash)
    return authorization


def post(headers, body, isAuth):
    auth_string = ' auth ' if isAuth else ' '
    try:
        logging.info(f"Attempting to connect to Log Analytics Workspace: {WORKSPACE_ID}")
        logging.info(f"Full URI being called: {URI}")
        response = POOL.post(URI, data=body, headers=headers)
        logging.info(f"Successfully connected to Log Analytics Workspace")
    except requests.exceptions.SSLError as ssl_err:
        logging.error(f"SSL Error when connecting to Log Analytics: {ssl_err}")
        logging.error(f"Workspace ID: {WORKSPACE_ID}")
        logging.error(f"Full URI: {URI}")
        raise
    except Exception as e:
        logging.error(f"Other error when connecting to Log Analytics: {e}")
        raise
    if (response.status_code >= 200 and response.status_code <= 299):
        logging.debug('accepted {}'.format(auth_string))
    else:
        resp_body = str(response.json())
        resp_headers = json.dumps(headers)
        failure_resp = "failure{}response details: {}{}{}".format(auth_string, response.status_code, resp_body, resp_headers)
        raise ProcessingException("ProcessingException for{}: {}".format(auth_string, failure_resp)) 


# Build Auth and send request to the POST API
def post_data(customer_id, shared_key, body, log_type, length=0):
    rfc1123date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    signature = build_signature(customer_id, shared_key, rfc1123date, length, POST_METHOD, CONTENT_TYPE, RESOURCE)
    headers = {
        'content-type': CONTENT_TYPE,
        'Authorization': signature,
        'Log-Type': log_type,
        'x-ms-date': rfc1123date
    }
    post(headers, body, False)


# Use Auth and send request to the POST API
def post_data_auth(headers, body):
    post(headers, body, True)


@app.route('/', methods=['POST'])
def func():
    auth_headers = request.headers.get("authorization").split(",")
    body = request.get_data()
    basic_auth_header = ''
    shared_key_header = ''
    try:
        for auth in auth_headers:
            if "Basic" in auth:
                basic_auth_header = auth.strip()
                if (basic_auth_header.split("Basic ")[1] != BASIC_AUTH):
                    logging.error("UnAuthorized Basic header mismatch %s vs %s", basic_auth_header, BASIC_AUTH)
                    raise UnAuthorizedException()
            if "SharedKey" in auth:
                shared_key_header = auth.strip()
        if basic_auth_header == '':
            logging.error("UnAuthorized Basic header")
            raise UnAuthorizedException()   
        log_type = request.headers.get(LOG_TYPE)
        xms_date = ", ".join([each.strip() for each in request.headers.get('x-ms-date').split(",")]).replace("UTC", "GMT")
        headers = {
             'Content-Type': 'application/json; charset=UTF-8',
             'Authorization': shared_key_header,
             'Log-Type': log_type,
             'x-ms-date': xms_date        
        }
        logging.debug(headers)
        # Decompress payload
        decompressed = gzip.decompress(body)
        logging.debug(decompressed)  
        decomp_body_length = len(decompressed)
        if decomp_body_length == 0:
            if len(body) == 0:
              logging.error("decompressed: {} vs body: {}".format(decompressed, body))
              return FAILURE_RESPONSE, 400, APPLICATION_JSON 
            else:
              return FAILURE_RESPONSE, 500, APPLICATION_JSON 
        # Use Authorization header from request
        post_data_auth(headers, decompressed)
        logging.debug("processed request auth")
    except ValueError as e:
        logging.error("ValueError: {}{}{}".format(headers, e, decompressed))
        return FAILURE_RESPONSE, 500, APPLICATION_JSON 
    except UnAuthorizedException:
        return FAILURE_RESPONSE, 401, APPLICATION_JSON 
    except ProcessingException as e:
        logging.debug(e)
        try:
            # Create Authorization header
            post_data(WORKSPACE_ID, SHARED_KEY, decompressed, log_type, length=decomp_body_length)
            logging.debug("processed request by creating auth")
        except ProcessingException as err:
            logging.error("Exception: {}{}{}".format(headers, err, decompressed))
            return FAILURE_RESPONSE, 500, APPLICATION_JSON 
    except Exception as e:
        logging.error(e)
        return FAILURE_RESPONSE, 500, APPLICATION_JSON 
       
    return SUCCESS_RESPONSE, 200, APPLICATION_JSON 


@app.route('/health', methods=['GET'])
def health():
    return SUCCESS_RESPONSE, 200, APPLICATION_JSON 


if __name__ == '__main__':
   app.run()