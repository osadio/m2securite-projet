from cryptography.hazmat.primitives.asymmetric import ed25519 
from binascii import hexlify, unhexlify
from struct import pack
import paho.mqtt.client as mqtt
import redis
from configparser import ConfigParser


# Read CA Ed25519 private key from file
config_ed25519 = ConfigParser()
config_ed25519.read("Ed25519_ca/ca-crt.ini")
x25519_keys = config_ed25519["ED25519"]
ca_private_key_hex = bytes(x25519_keys["private_key"].strip("\'"), encoding="ascii")
ca_private_key_byte = unhexlify(ca_private_key_hex)
ca_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(ca_private_key_byte)

# MQTT broker
broker_addr = "192.168.64.133"
broker_port = 1883
topic = "ca-iot/#"

# MQTT message type
CRT_REQ = 4
CRT_RESP = 5 

# Redis database config
redis_addr = "localhost"
redis_port = 6379
config_credentials = ConfigParser()
config_credentials.read("credentials/credentials.ini")
redis_credentials = config_credentials["REDIS"]
redis_password = redis_credentials["password"]

# Statistics
certs_req_number = 0

# Connecting to redis database
print("Connecting to the certificate database...")
r = redis.Redis(host=redis_addr, port=redis_port, password=redis_password)

# Publish MQTT message
def mqtt_publish(client, topic, message):
    # Connect to the broker
    client.publish(topic, message)

def detect_payload_format(payload):
    payload_str = str(payload)[1:].strip("\'")
    if len(payload_str) :
        if payload_str[:2] == "\\x" :
            # \x04\x01
            return("ascii_hex")
        else :
            # 41
            return("ascii_string")
    else :
        return("ascii_string")

# Handle device certificate request
def handle_cert_request(client, msg):
    global certs_req_number
    certs_req_number += 1
    print(f"[{certs_req_number}]")
    # Topics are in the format ca-iot/requester_topic 
    try :
        requester_topic = msg.topic.split("/")[1]
    except :
        print("Error : topic format in incorrect.")
        return
    print(f"Receiving certificate request from device '{requester_topic}'")
    device_id = str(msg.payload[1:])[1:].strip("\'")
    device_public_key = r.get(device_id)
    if device_public_key != None :
        # Sign the the device public key (in bytes format)
        device_public_key_b = bytes.fromhex(str(device_public_key)[1:].strip("\'"))
        ca_signature = ca_private_key.sign(device_public_key_b)
        print(f"Certificate of device '{device_id}': {hexlify(device_public_key_b)}")
        print(f"CA signature : {hexlify(ca_signature)}")
        # Build MQTT message : header + device_id + device_certificat + ca_signature
        CRT_RESP_b = pack('B', CRT_RESP)
        message = b"".join((CRT_RESP_b, msg.payload[1:], device_public_key_b, ca_signature))
    else :
        CRT_RESP_b = pack('B', CRT_RESP)
        message = b"".join((CRT_RESP_b, b'None'))
    # Send response to the requester
    print(f"Sending response (publishing) in topic '{requester_topic}'" )
    client.publish(requester_topic, message) 

# The callback for when the client receives a CONNACK response from the server.
def on_connect(client, userdata, flags, rc):
    client.subscribe(topic)
    print(f"Subscribing to topic '{topic}'")
    print("The CA is ready")

# The callback for when a PUBLISH message is received from the server.
def on_message(client, userdata, msg):
    # Determine the payload format
    rep = detect_payload_format(msg.payload)
    # Decode header : the first byte is the header
    if rep == "ascii_hex":
        header = int(msg.payload[0])
    else :
        header = int(chr(msg.payload[0]))
    # handling
    if header == CRT_REQ:
        handle_cert_request(client, msg)
    else:
        print("Unknown request")


# MQTT Client creation
client = mqtt.Client(client_id="ca-iot")
client.on_connect = on_connect
client.on_message = on_message

# Connect to MQTT broker
print("Connecting to the MQTT broker...")
client.connect(broker_addr, broker_port, 60)
client.loop_forever()

