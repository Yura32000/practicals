from tempfile import NamedTemporaryFile
import requests  
import json  
import pickle
import numpy as np
from io import StringIO
import os

def serializeObject(pythonObj):
    with NamedTemporaryFile(delete=False) as f:
        pickle.dump(pythonObj, f,  pickle.HIGHEST_PROTOCOL)   
    return f.name

def deserializeObject(path):
    return pickle.load(open(path, "rb"))

def serializeKerasModel(model):
    with NamedTemporaryFile() as f:
        model.save(f.name)
    return f.name

def deserializeKerasModel(path):
    from keras.models import Model,load_model
    model = load_model(path)
    return model
    
def serializeNumpyArray(arr):
    with NamedTemporaryFile() as f:
        np.save(f, arr)
    return f.name 

def put_to_objectstore(credentials, object_name, my_data, binary=True, region='dallas'):
    print('my_data', len(my_data))
    url1 = ''.join(['https://identity.open.softlayer.com', '/v3/auth/tokens'])
    data = {'auth': {'identity': {'methods': ['password'],
            'password': {'user': {'name': credentials['username'],'domain': {'id': credentials['domain_id']},
            'password': credentials['password']}}}}}
    headers1 = {'Content-Type': 'application/json'}
    resp1 = requests.post(url=url1, data=json.dumps(data), headers=headers1)
    resp1_body = resp1.json()
    for e1 in resp1_body['token']['catalog']:
        if(e1['type']=='object-store'):
            for e2 in e1['endpoints']:
                        if(e2['interface']=='public'and e2['region']==region):
                            url2 = ''.join([e2['url'],'/', credentials['container'], '/', object_name])
    s_subject_token = resp1.headers['x-subject-token']
    headers_accept = 'application/octet-stream' if (binary) else 'application/json' 
    headers2 = {'X-Auth-Token': s_subject_token, 'accept': headers_accept}
    resp2 = requests.put(url=url2, headers=headers2, data = my_data )

def get_from_objectstore(credentials, object_name, binary=True, region='dallas'):
    url1 = ''.join(['https://identity.open.softlayer.com', '/v3/auth/tokens'])
    data = {'auth': {'identity': {'methods': ['password'], 'password': {'user': {'name': credentials['username'],'domain': {'id': credentials['domain_id']}, 'password': credentials['password']}}}}}
    headers1 = {'Content-Type': 'application/json'}
    resp1 = requests.post(url=url1, data=json.dumps(data), headers=headers1)
    resp1_body = resp1.json()
    for e1 in resp1_body['token']['catalog']:
        if(e1['type']=='object-store'):
            for e2 in e1['endpoints']:
                        if(e2['interface']=='public'and e2['region']==region):
                            url2 = ''.join([e2['url'],'/', credentials['container'], '/', object_name])
    s_subject_token = resp1.headers['x-subject-token']
    headers_accept = 'application/octet-stream' if (binary) else 'application/json' 
    headers2 = {'X-Auth-Token': s_subject_token, 'accept': headers_accept}
    resp2 = requests.get(url=url2, headers=headers2)
    res = resp2.content if (binary) else StringIO(resp2.text)
    return res
    
       
def put_to_cloud_object_storage(api_key, full_object_path, my_data, auth_endpoint="https://iam.ng.bluemix.net/oidc/token", service_endpoint="https://s3-api.us-geo.objectstorage.softlayer.net"): 
    print('my_data', len(my_data))
    response=requests.post(
                url=auth_endpoint,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                params={"grant_type":"urn:ibm:params:oauth:grant-type:apikey","apikey":api_key},
                verify=True)
    access_token=response.json()["access_token"]

    response=requests.put(
                url=service_endpoint+"/"+full_object_path,
                headers={"Authorization": "bearer " + access_token},
                data = my_data)
                
    return response

        
def get_from_cloud_object_storage(api_key, full_object_path, auth_endpoint="https://iam.ng.bluemix.net/oidc/token", service_endpoint="https://s3-api.us-geo.objectstorage.softlayer.net"):
    response=requests.post(
                url=auth_endpoint,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                params={"grant_type":"urn:ibm:params:oauth:grant-type:apikey","apikey":api_key},
                verify=True)
    access_token=response.json()["access_token"]

    response=requests.get(
                url=service_endpoint+"/"+full_object_path,
                headers={"Authorization": "bearer " + access_token},
                params=None,
                verify=True)

    return response.content
        

def put_to_cos(apikey, resource_instance_id, full_object_path, file_path, auth_endpoint="https://iam.bluemix.net/oidc/token", service_endpoint="https://s3-api.us-geo.objectstorage.softlayer.net"):
    import ibm_boto3
    from ibm_botocore.client import Config

    bucket_name, object_name = full_object_path.split("/")

    resource = ibm_boto3.resource('s3',
                      ibm_api_key_id=apikey,
                      ibm_service_instance_id=resource_instance_id,
                      ibm_auth_endpoint=auth_endpoint,
                      endpoint_url=service_endpoint,
                      config=Config(signature_version='oauth'))

    allbuckets = resource.buckets.all()
    targetBucket = None
    for b in allbuckets:          
        if b.name == bucket_name:
            targetBucket = b
            break
   
    with open(file_path, 'rb') as f:
        obj = targetBucket.Object(object_name)        
        obj.upload_fileobj(f)   
       
    print( "An object '%s' has been succesfully uploaded to bucket '%s'." % (object_name, bucket_name) )


def get_from_cos(apikey, resource_instance_id, full_object_path, auth_endpoint="https://iam.bluemix.net/oidc/token", service_endpoint="https://s3-api.us-geo.objectstorage.softlayer.net"):
    import ibm_boto3
    from ibm_botocore.client import Config

    bucket_name, object_name = full_object_path.split("/")

    resource = ibm_boto3.resource('s3',
                      ibm_api_key_id=apikey,
                      ibm_service_instance_id=resource_instance_id,
                      ibm_auth_endpoint=auth_endpoint,
                      endpoint_url=service_endpoint,
                      config=Config(signature_version='oauth'))

    allbuckets = resource.buckets.all()
    targetBucket = None
    for b in allbuckets:          
        if b.name == bucket_name:
            targetBucket = b
            break
    
    file_path = ""
    with NamedTemporaryFile(delete=False) as f:
        file_path = f.name
        obj = targetBucket.Object(object_name)
        obj.download_file(file_path)
    
    print( "An object '%s' has been succesfully downloaded from bucket '%s'." % (object_name, bucket_name) )

    return file_path    

    
# Make sure to install: ibm-cos-sdk
# !pip install ibm-cos-sdk
# https://github.com/IBM/ibm-cos-sdk-python
def create_messagehub_producer(username, password, kafka_brokers_sasl = [], sasl_mechanism = 'PLAIN', security_protocol = 'SASL_SSL', value_serializer=lambda v: json.dumps(v).encode('utf-8')):
    import ssl
    from kafka import KafkaProducer 
    from kafka.errors import KafkaError 

    if (kafka_brokers_sasl == []):
        kafka_brokers_sasl = [
            "kafka01-prod01.messagehub.services.us-south.bluemix.net:9093",
            "kafka02-prod01.messagehub.services.us-south.bluemix.net:9093",
            "kafka03-prod01.messagehub.services.us-south.bluemix.net:9093",
            "kafka04-prod01.messagehub.services.us-south.bluemix.net:9093",
            "kafka05-prod01.messagehub.services.us-south.bluemix.net:9093" 
        ] 

    # Create a new context using system defaults, disable all but TLS1.2
    context = ssl.create_default_context()
    context.options &= ssl.OP_NO_TLSv1
    context.options &= ssl.OP_NO_TLSv1_1

    producer = KafkaProducer(bootstrap_servers = kafka_brokers_sasl,
                             sasl_plain_username = username,
                             sasl_plain_password = password,
                             security_protocol = security_protocol,
                             ssl_context = context,
                             sasl_mechanism = sasl_mechanism,
                             value_serializer=value_serializer)
                             
    return producer
    
    
def create_messagehub_consumer(username, password, kafka_brokers_sasl = [], sasl_mechanism = 'PLAIN', security_protocol = 'SASL_SSL', value_deserializer=lambda v: json.loads(v).encode('utf-8')):
    import ssl
    from kafka import KafkaConsumer 
    from kafka.errors import KafkaError 

    if (kafka_brokers_sasl == []):
        kafka_brokers_sasl = [
            "kafka01-prod01.messagehub.services.us-south.bluemix.net:9093",
            "kafka02-prod01.messagehub.services.us-south.bluemix.net:9093",
            "kafka03-prod01.messagehub.services.us-south.bluemix.net:9093",
            "kafka04-prod01.messagehub.services.us-south.bluemix.net:9093",
            "kafka05-prod01.messagehub.services.us-south.bluemix.net:9093" 
        ] 

    # Create a new context using system defaults, disable all but TLS1.2
    context = ssl.create_default_context()
    context.options &= ssl.OP_NO_TLSv1
    context.options &= ssl.OP_NO_TLSv1_1

    consumer = KafkaConsumer(bootstrap_servers = kafka_brokers_sasl,
                             sasl_plain_username = username,
                             sasl_plain_password = password,
                             security_protocol = security_protocol,
                             ssl_context = context,
                             sasl_mechanism = sasl_mechanism,
                             value_deserializer=value_deserializer)
                             
    return consumer
