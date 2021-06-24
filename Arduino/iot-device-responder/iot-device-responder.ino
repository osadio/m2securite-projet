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
#define DEVICE_ID                        "d002"  // the device ID corresponds to device topic
#define CA_TOPIC                         "ca-iot/" DEVICE_ID

// Paramètres Ed25519
byte ed_private_key[ED_KEY_SIZE] = {0xc6,0x18,0x10,0x0a,0xa2,0x57,0xf0,0xf5,0xd7,0xd3,0x60,0x01,0xa7,0x21,0x8a,0x2d,
                                    0x4f,0x7d,0x8d,0x38,0xdf,0xf7,0xd7,0x62,0xa5,0x54,0x5b,0xe4,0x61,0x89,0xbf,0x86};
byte ed_public_key[ED_KEY_SIZE] = {0xdd,0x4a,0xa8,0xd7,0xf2,0x88,0xb7,0x7d,0x80,0x43,0xfa,0x25,0xf9,0xd3,0x2c,0x55,
                                   0x0d,0xc0,0xcb,0x7e,0xea,0x66,0x8e,0x50,0xbf,0x3e,0xfc,0x9d,0xb6,0xaa,0xc2,0x56};
byte ca_public_key[ED_KEY_SIZE] = {0x84,0x82,0x9a,0xc8,0xf5,0x51,0xe7,0x9e,0x6c,0x85,0xcc,0x82,0x1e,0xe1,0xb3,0x48,
                                   0xe9,0xd7,0x14,0x0d,0xed,0x85,0x5e,0xf8,0x48,0x7a,0x08,0xb6,0x0e,0x11,0x0e,0xbe};
byte peer_signature[ED_SIGN_SIZE];

// Paramètres X25519 
static uint8_t dh_public_key[DH_KEY_SIZE];   
static uint8_t dh_private_key[DH_KEY_SIZE];  
static uint8_t dh_shared_secret_key[DH_KEY_SIZE];

// Paramètres CHACHAPOLY
byte plaintext[CHACHA_MSG_SIZE]; // Recommanded minimal size is 16 bytes
unsigned long t = 0;
bool respond = false; 

// Paramètres MQTTSN
uint16_t u16_CA_TopicID = 0xffff;
uint16_t u16_device_TopicID = 0xffff;
uint16_t u16_peer_device_TopicID = 0xffff;
char peer_device_id[] = "0000";
uint8_t flags = 0;
bool subscribe = false;
unsigned long t0 = millis();
bool dh_initiate = false; 
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

    Serial3.println(F("Starting responder..."));
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
    // Send response when receiving message from initiator
    if (dh_step == 255 && respond){
        String data = "R:56789";
        data.getBytes(plaintext, sizeof(plaintext));
        respond = false;
        encrypt_and_send(plaintext);
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
        ca_request = true;
        dh_step = DH_RESP;
    }
}

void finalize_dh_handling(byte device_id, byte *device_certificate){
    // if peer_device_id != device_id; resend cert request
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

            // End of DH
            dh_step = 255;
        }  
    }
    else if(dh_step == DH_RESP){
        // Compute shared secret key
        if (Curve25519::dh2(dh_shared_secret_key, dh_private_key)){   
            // Logging
            Serial3.print(F("DH shared secret key : "));
            printHex(dh_shared_secret_key, DH_KEY_SIZE);
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
        respond = true;
        
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

void MQTTSN_serial_send(uint8_t *message_buffer, int length){
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
