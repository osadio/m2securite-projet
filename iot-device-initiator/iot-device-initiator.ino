#include <mqttsn-messages.h>
#include <Crypto.h>
#include <Curve25519.h>
#include <Ed25519.h>
#include <ChaChaPoly.h>
#include <RNG.h>
#include <TransistorNoiseSource.h>

// Data type (proposed protocol)
#define DH_REQ                           1
#define DH_RESP                          2
#define CHACHA_POLY                      3
#define CRT_REQ                          4
#define CRT_RESP                         5

// Ed25519 and X25519
#define ED_KEY_SIZE                      32
#define ED_SIGN_SIZE                     64 
#define DH_KEY_SIZE                      32

// CHACHAPOLY
#define CHACHA_MSG_SIZE                  16

// MQTT-SN 
#define HEADER_SIZE                      1 
#define DEVICE_ID_MAX_SIZE               4
#define DEVICE_ID                        "d001"  // the device ID corresponds to device topic
#define CA_TOPIC                         "ca-iot/" DEVICE_ID

// Paramètres Ed25519
byte ed_private_key[ED_KEY_SIZE] = {0x6b,0x64,0x1c,0xd7,0x2a,0xd6,0xde,0x26,0xae,0x2b,0x9b,0x15,0x66,0xf3,0x52,0x01,
                                    0x4d,0x01,0x68,0x96,0x91,0x51,0x9d,0xeb,0x3f,0xfa,0x43,0x26,0x63,0xdc,0xb8,0xa0};
byte ed_public_key[ED_KEY_SIZE] = {0xf3,0xb5,0x99,0x9b,0x8f,0xb0,0x39,0x5f,0xa9,0x70,0xe6,0x73,0x15,0x77,0x98,0xf5,
                                   0xfa,0xdf,0xc8,0xdc,0xc7,0x15,0x19,0x45,0xb0,0x1f,0xcc,0x9c,0xa4,0x64,0xd5,0x01};
byte ca_public_key[ED_KEY_SIZE] = {0x84,0x82,0x9a,0xc8,0xf5,0x51,0xe7,0x9e,0x6c,0x85,0xcc,0x82,0x1e,0xe1,0xb3,0x48,
                                   0xe9,0xd7,0x14,0x0d,0xed,0x85,0x5e,0xf8,0x48,0x7a,0x08,0xb6,0x0e,0x11,0x0e,0xbe};
byte peer_signature[ED_SIGN_SIZE];

// Paramètres X25519 
static uint8_t dh_public_key[DH_KEY_SIZE];   
static uint8_t dh_private_key[DH_KEY_SIZE ];  
static uint8_t dh_shared_secret_key[DH_KEY_SIZE ];

// Paramètres CHACHAPOLY
byte plaintext[CHACHA_MSG_SIZE]; // Recommanded minimal size is 16 bytes
unsigned long t = 0;
bool respond = false;

// Paramètres MQTTSN
uint16_t u16_CA_TopicID = 0xffff;
uint16_t u16_device_TopicID = 0xffff;
uint16_t u16_peer_device_TopicID = 0xffff;
char peer_device_id[] = "d002"; // The initiator know the responder ID;
uint8_t flags = 0;
bool subscribe = false;
unsigned long t0 = 0;
bool dh_initiate = true; 
bool dh_response = false;
bool ca_request = false; 
byte dh_step;
uint8_t register_count = 0;

 
MQTTSN mqttsn;

ChaChaPoly chachapoly;

TransistorNoiseSource noise(A1);


void setup() {
    Serial.begin(9600);
    Serial3.begin(9600);

    // Initialisation du generateur de nombre aléatoire
    RNG.begin("One Two Three");
    // Ajouter une source de bruit
    RNG.addNoiseSource(noise);

    Serial3.println(F("Starting initiator..."));
}

void loop() {
    CheckSerial();
    delay(2000);

    RNG.loop();
 
    if (mqttsn.wait_for_response()) {
        return;
    }

    // CONNECT
    if (!mqttsn.connected()) {
        mqttsn.connect(flags, 60, DEVICE_ID);
        return;
    }

    // To keep the connection in place, the client sends a PINGREQ before the keep alive window expires, 
    // to which the broker responds with a PINGRESP
    if (millis() - t0 > 50000){
        mqttsn.pingreq(DEVICE_ID);
        t0 = millis();
    }

    // REGISTER
    uint8_t index;
    if (u16_CA_TopicID == 0xffff) {
        u16_CA_TopicID = mqttsn.find_topic_id(CA_TOPIC, &index);
        if (u16_CA_TopicID == 0xffff) {
            mqttsn.register_topic(CA_TOPIC);
        }
        return;
    }

    if (u16_device_TopicID == 0xffff) {
        u16_device_TopicID = mqttsn.find_topic_id(DEVICE_ID, &index);
        if (u16_device_TopicID == 0xffff) {
            mqttsn.register_topic(DEVICE_ID);
        }
        return;
    }

    // SUBSCRIBE
    // Subscribing : if the device is already subscribed, do not subscribe again
    if (!subscribe) {
        mqttsn.subscribe_by_name(flags, DEVICE_ID);
        subscribe = true;
    }

    // DH REQUEST (i.e. publish DH public key)
    if (dh_initiate){
        // REGISTER
        if (u16_peer_device_TopicID == 0xffff) {
            u16_peer_device_TopicID = mqttsn.find_topic_id(peer_device_id, &index);
            if (u16_peer_device_TopicID == 0xffff) {
                mqttsn.register_topic(peer_device_id);
            }
            // Used to speed up dh reply, i.e. avoid multiple registering
            register_count++;
            if(register_count == 2){
                mqttsn.pingreq(DEVICE_ID);
            }
            return;
        }

        // LOGGING
        Serial3.println(F("Sending DH request..."));
        
        // Compute DH public and private key
        Curve25519::dh1(dh_public_key, dh_private_key);
        dh_send_key(DH_REQ);
        dh_initiate = false;
    }

    // DH RESPONSE
    if (dh_response) {
        // REGISTER
        if (u16_peer_device_TopicID == 0xffff) {
            u16_peer_device_TopicID = mqttsn.find_topic_id(peer_device_id, &index);
            if (u16_peer_device_TopicID == 0xffff) {
                mqttsn.register_topic(peer_device_id);
            }
            return;
        }

        // LOGGING
        Serial3.println(F("Sending DH response..."));
        
        dh_send_key(DH_RESP);
        dh_response = false;
    }

    // CA REQUEST
    if (ca_request){               
       certificate_request(peer_device_id); 
       ca_request = false; 
    }

    // END OF DH
    if (dh_step == 255){
         // Send message every 20s
         if (millis() - t > 20000){
             String data = "I:01234";
             data.getBytes(plaintext, sizeof(plaintext));
             encrypt_and_send(plaintext);
             t = millis();
         }
    }
}

void device_certificate_reception(const msg_publish *msg){
    byte device_id[DEVICE_ID_MAX_SIZE];
    byte device_certificate[ED_KEY_SIZE];
    byte ca_signature[ED_SIGN_SIZE];

    memcpy(device_id, msg->data + HEADER_SIZE, DEVICE_ID_MAX_SIZE);
    memcpy(device_certificate, msg->data + HEADER_SIZE + DEVICE_ID_MAX_SIZE, ED_KEY_SIZE);
    memcpy(ca_signature, msg->data + HEADER_SIZE + DEVICE_ID_MAX_SIZE + ED_KEY_SIZE, ED_SIGN_SIZE);

    // LOGGING
    Serial3.println(F("Receiving response from CA..."));
    Serial3.print(F("Peer device certificate : "));
    printHex(device_certificate, ED_KEY_SIZE);
    Serial3.print(F("CA signature : "));
    printHex(ca_signature, ED_SIGN_SIZE);

    // Check CA signature of the device_certificate
    if (!Ed25519::verify(ca_signature, ca_public_key, device_certificate, ED_KEY_SIZE)) {
        Serial3.println(F("The CA signature is invalid."));
        return;
    }

    finalize_dh_handling(device_id, device_certificate);   
}

void certificate_request(char *peer_device_id){
    uint8_t message_buffer[HEADER_SIZE + DEVICE_ID_MAX_SIZE];
    uint8_t header[1] = {CRT_REQ};
    
    // Concatenate with memcpy. You just need to set the pointer at the right place inside the message_buffer array
    memcpy(message_buffer, header, HEADER_SIZE);  
    memcpy(message_buffer + HEADER_SIZE, peer_device_id, DEVICE_ID_MAX_SIZE);

    // LOGGING
    Serial3.println(F("Sending certificate request to CA...")); 
    
    mqttsn.publish(flags, u16_CA_TopicID, message_buffer, HEADER_SIZE + DEVICE_ID_MAX_SIZE);  
}

void dh_send_key(uint8_t message_type){
    uint8_t message_buffer[HEADER_SIZE + DEVICE_ID_MAX_SIZE + DH_KEY_SIZE + ED_SIGN_SIZE];
    uint8_t header[HEADER_SIZE];
    uint8_t signature[ED_SIGN_SIZE];

    header[0] = message_type;
    
    // Sign the message (i.e. the dh_public_key)
    Ed25519::sign(signature, ed_private_key, ed_public_key, dh_public_key, DH_KEY_SIZE);

    // Concatenate with memcpy. You just need to set the pointer at the right place inside the message_buffer array
    memcpy(message_buffer, header, HEADER_SIZE);  
    memcpy(message_buffer + HEADER_SIZE, DEVICE_ID, DEVICE_ID_MAX_SIZE);
    memcpy(message_buffer + HEADER_SIZE + DEVICE_ID_MAX_SIZE, dh_public_key, DH_KEY_SIZE);
    memcpy(message_buffer + HEADER_SIZE + DEVICE_ID_MAX_SIZE + DH_KEY_SIZE, signature, ED_SIGN_SIZE);
      
    mqttsn.publish(flags, u16_peer_device_TopicID, message_buffer, HEADER_SIZE + DEVICE_ID_MAX_SIZE + DH_KEY_SIZE + ED_SIGN_SIZE);  
}

void dh_receive_key(const msg_publish *msg, uint8_t message_type){ 
    memcpy(peer_device_id, msg->data + HEADER_SIZE, DEVICE_ID_MAX_SIZE);
    memcpy(dh_shared_secret_key, msg->data + HEADER_SIZE + DEVICE_ID_MAX_SIZE, DH_KEY_SIZE);
    memcpy(peer_signature, msg->data + HEADER_SIZE + DEVICE_ID_MAX_SIZE + DH_KEY_SIZE, ED_SIGN_SIZE);

    // LOGGING
    String peer_device_id_str = String((char *)peer_device_id);
    Serial3.println(F("Receiving peer DH message..."));
    Serial3.print(F("Peer device ID : "));
    Serial3.println(peer_device_id_str);
    Serial3.print(F("Peer device DH public key : "));
    printHex(dh_shared_secret_key, DH_KEY_SIZE);
    Serial3.print(F("Peer device signature : "));
    printHex(peer_signature, ED_SIGN_SIZE);

    if (message_type == DH_REQ){
        // Send certificate (ed public key) request to the CA
        ca_request = true; 
        dh_step = DH_REQ;
    }
    else if(message_type == DH_RESP){
        // Send certificate (ed public key) request to the CA
        ca_request = true; 
        dh_step = DH_RESP;
    }
}

void finalize_dh_handling(byte *device_id, byte *device_certificate){
    // peer_device_id != device_id; then cancel DH key exchange
    // TODO

    // Check signature of received dh_public_key 
    if (!Ed25519::verify(peer_signature, device_certificate, dh_shared_secret_key, DH_KEY_SIZE)) {
        Serial3.println(F("Peer signature is invalid."));
        // Abort DH key exchange
        return;
    }
    
    if(dh_step == DH_REQ){
        // Compute DH public and private key
        Curve25519::dh1(dh_public_key, dh_private_key);
     
        // Compute shared secret key
        if (Curve25519::dh2(dh_shared_secret_key, dh_private_key)){   
            // Logging
            Serial3.print(F("DH shared secret key : "));
            printHex(dh_shared_secret_key, DH_KEY_SIZE);

            // End of DH
            dh_step = 255;

            // Send response to the peer
            dh_response = true;
        }
        else{
            // Logging
            Serial3.println(F("Received DH peer public key is invalid")); 
        }  
    }
    else if(dh_step == DH_RESP){
        // Compute shared secret key
        if (Curve25519::dh2(dh_shared_secret_key, dh_private_key)){   
            // Logging
            Serial3.print(F("DH shared secret key : "));
            printHex(dh_shared_secret_key, DH_KEY_SIZE);

            // End of DH
            dh_step = 255;
        }
        else{
            // Logging
            Serial3.println(F("Received DH peer public key is invalid")); 
        }        
    } 
}

void encrypt_and_send(byte *msg){
    byte iv[12];
    byte tag[16];
    byte authdata[16];
    byte ciphertext[CHACHA_MSG_SIZE];
    
    uint8_t message_buffer[HEADER_SIZE + CHACHA_MSG_SIZE + sizeof(iv) + sizeof(authdata) + sizeof(tag)];
    uint8_t header[HEADER_SIZE];

    header[0] = CHACHA_POLY;

    // Generate a random IV
    if (RNG.available(sizeof(iv))) {
        RNG.rand(iv, sizeof(iv));
    }

    // Generate authdata
    String add = String(t);
    add.getBytes(authdata, sizeof(authdata));

    // Encryption
    chachapoly.clear(); 
    chachapoly.setKey(dh_shared_secret_key, DH_KEY_SIZE);
    chachapoly.setIV(iv, sizeof(iv));
    chachapoly.addAuthData(authdata, sizeof(authdata));
    chachapoly.encrypt(ciphertext, msg, CHACHA_MSG_SIZE);
    chachapoly.computeTag(tag, sizeof(tag));

    // Concatenate with memcpy. You just need to set the pointer at the right place inside the message_buffer array
    memcpy(message_buffer, header, HEADER_SIZE);  
    memcpy(message_buffer + HEADER_SIZE, ciphertext, CHACHA_MSG_SIZE);
    memcpy(message_buffer + HEADER_SIZE + CHACHA_MSG_SIZE, iv, sizeof(iv));
    memcpy(message_buffer + HEADER_SIZE + CHACHA_MSG_SIZE + sizeof(iv), authdata, sizeof(authdata));
    memcpy(message_buffer + HEADER_SIZE + CHACHA_MSG_SIZE + sizeof(iv) + sizeof(authdata), tag, sizeof(tag));

    // Logging
    Serial3.println(F("Encrypt and send : "));
    Serial3.print(F("Plaintext message : "));
    printHex(msg, CHACHA_MSG_SIZE);
    Serial3.print(F("Ciphertext : "));
    printHex(ciphertext, sizeof(ciphertext));
    Serial3.print(F("IV : "));
    printHex(tag, sizeof(iv)); 
    Serial3.print(F("Auth data : "));
    printHex(authdata, sizeof(authdata));
    Serial3.print(F("Tag : "));
    printHex(tag, sizeof(tag)); 

    mqttsn.publish(flags, u16_peer_device_TopicID, message_buffer, HEADER_SIZE + CHACHA_MSG_SIZE + sizeof(iv) + sizeof(authdata) + sizeof(tag)); 
}

void receive_and_decrypt(const msg_publish *msg){
    byte iv[12];
    byte authdata[16];
    byte tag[16];
    byte ciphertext[CHACHA_MSG_SIZE];
    byte plaintext[CHACHA_MSG_SIZE];
   
    memcpy(ciphertext, msg->data + HEADER_SIZE, CHACHA_MSG_SIZE);
    memcpy(iv, msg->data + HEADER_SIZE + CHACHA_MSG_SIZE, sizeof(iv));
    memcpy(authdata, msg->data + HEADER_SIZE + CHACHA_MSG_SIZE + sizeof(iv), sizeof(authdata));
    memcpy(tag, msg->data + HEADER_SIZE + CHACHA_MSG_SIZE + sizeof(iv) + sizeof(authdata), sizeof(tag));

    // Logging
    Serial3.println(F("Receive and decrypt : "));
    Serial3.print(F("Ciphertext : "));
    printHex(ciphertext, sizeof(ciphertext));
    Serial3.print(F("IV : "));
    printHex(iv, sizeof(iv)); 
    Serial3.print(F("Auth data : "));
    printHex(authdata, sizeof(authdata));
    Serial3.print(F("Tag : "));
    printHex(tag, sizeof(tag));

    // Decrypt and authenticate message
    chachapoly.clear();
    chachapoly.setKey(dh_shared_secret_key, DH_KEY_SIZE);
    chachapoly.setIV(iv, sizeof(iv));
    chachapoly.addAuthData(authdata, sizeof(authdata));
    chachapoly.decrypt(plaintext, ciphertext, CHACHA_MSG_SIZE);

    if (chachapoly.checkTag(tag, sizeof(tag))) {
        String data = String((char *)plaintext);

        // Logging
        Serial3.print("Decrypted message with zero padding : ");
        printHex(plaintext, sizeof(plaintext));
        Serial3.print("Data : ");
        Serial3.println(data);
    }
    else{
        Serial3.println("Erreur! invalid tag");
    }
}

void MQTTSN_serial_send(uint8_t *message_buffer, int length) {
    Serial.write(message_buffer, length);
    Serial.flush();
}

void MQTTSN_publish_handler(const msg_publish *msg) {
    uint8_t header = msg->data[0];
    uint8_t message_type = header; // will be change

    switch (message_type) {
        case DH_REQ:
            dh_receive_key(msg, message_type);
            break;
        case DH_RESP:
            dh_receive_key(msg, message_type);
            break;
        case CRT_RESP:
            device_certificate_reception(msg);
            break;
        case CHACHA_POLY:
            receive_and_decrypt(msg);
            break;
    }
}

void MQTTSN_gwinfo_handler(const msg_gwinfo *msg) { 
}

void CheckSerial() {
    uint16_t cnt = 0;
    uint8_t buffer[128];
    uint8_t *buf = &buffer[0];

    while (Serial.available()) {
        buffer[cnt++] = Serial.read();
    }

    if (cnt > 0) {
       mqttsn.parse_stream(buf, cnt);
    }
}

void printHex(byte *buffer, byte bufferSize) {
  for (byte i = 0; i < bufferSize; i++) {
    Serial3.print(buffer[i] < 0x10 ? "0" : "");
    Serial3.print(buffer[i], HEX);
  }
  Serial3.println();
}
