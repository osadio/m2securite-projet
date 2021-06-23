from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from binascii import hexlify

def key_c_format(key_hex):
    """
       Convert key in C-like byte array
       Ex : key = {0x1F, 0x23,...}
    """
    key_str = str(key_hex)[1:].strip("\'")
    key_c = "{0x"
    i = 1
    for hex_character in key_str : 
        if i < 2 :
            key_c += hex_character
            i += 1
        else :
            key_c += hex_character + ",0x"
            i = 1     
    key_c = key_c[:-3]+"}"
    return key_c
            
private_key = ed25519.Ed25519PrivateKey.generate()
public_key = private_key.public_key()

# Serialization
private_bytes = private_key.private_bytes(
     encoding=serialization.Encoding.Raw,
     format=serialization.PrivateFormat.Raw,
     encryption_algorithm=serialization.NoEncryption()
)
        
print("Private key :")
print(private_bytes)
print(hexlify(private_bytes))
print(key_c_format(hexlify(private_bytes)))

public_bytes = public_key.public_bytes(
     encoding=serialization.Encoding.Raw,
     format=serialization.PublicFormat.Raw
)
print("\n\nPublique key :")
print(public_bytes)
print(hexlify(public_bytes))
print(key_c_format(hexlify(public_bytes)))



print()
ca = b'de6afb9395eb7c72f1ec9ba1d52cda4c456649f9a7ba58c5e959559a0b099ce92d96f5e867a9d8cf32b47eeb2fd9e9ec38aaa8ca9e0da3cbbcbbf61a0169670c'
print(ca)
print(key_c_format(ca))

