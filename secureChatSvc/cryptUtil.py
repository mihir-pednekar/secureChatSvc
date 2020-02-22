'''
Created on 16-Feb-2020
rw5
@author: mihir
'''
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES, PKCS1_OAEP

class cryptoUtil:
    '''
    classdocs
    '''
    
    @classmethod
    def generate_public_private_key(self):
        
        key = RSA.generate(2048)
        public_key = key.publickey().export_key()
        print("public_key created public.pem")
        file_out = open("public.pem", "wb")
        file_out.write(public_key)
        private_key = key.export_key()
        print("private_key created private.pem")
        file_out = open("private.pem", "wb")
        file_out.write(private_key)
        
    @classmethod
    def generate_receiver_public_private_key(self):
        
        
        receiver_key = RSA.generate(2048)
        receiver_public_key = receiver_key.publickey().export_key()
        print("receiver_public_key created receiver_public.pem")
        file_out = open("receiver_public.pem", "wb")
        file_out.write(receiver_public_key)
        receiver_private_key = receiver_key.export_key()
        print("receiver_private_key created private.pem")
        file_out = open("receiver_private.pem", "wb")
        file_out.write(receiver_private_key)
        
    @classmethod
    def generate_hash_sh256(self, msg):
        
        hash_object = SHA256.new(data=msg)
        return hash_object.digest()
    
    @classmethod
    def generate_session_key(self):
        
        return get_random_bytes(16)
    
    @classmethod
    def encrypt_session_key_with_public_key(self, public_key_file_name, encrypted_file_name, session_key):
        
        # Encrypt the session key with the public RSA key
        recipient_public_key = RSA.import_key(open(public_key_file_name).read())
        cipher_rsa = PKCS1_OAEP.new(recipient_public_key)
        enc_session_key = cipher_rsa.encrypt(session_key)
        file_out = open(encrypted_file_name, "wb")
        file_out.write(enc_session_key)
        return enc_session_key
        #[ file_out.write(x) for x in (enc_session_key) ]
    
    @classmethod
    def encrypt_data_with_aes_session_key(self, data, session_key, enc_session_key, encrypted_file_name):
        
        # Encrypt the data with the AES session key
        print("Inside method encrypt_data_with_aes_session_key()")
        # Encrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher_aes.encrypt_and_digest(data)
        file_out = open(encrypted_file_name, "wb")
        print(cipher_aes.nonce)
        [ file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext) ]
        print("End of method encrypt_data_with_aes_session_key()")
        
    @classmethod
    def decrypt_session_key_with_private_key(self, private_key_file_name, encrypted_file_name, enc_session_key):
    
        # Decrypt the session key with the private RSA key
        file_in = open(encrypted_file_name, "rb")
        private_key = RSA.import_key(open(private_key_file_name).read())
        enc_session_key, nonce, tag, ciphertext = \
        [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
        # Decrypt the session key with the private RSA key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        return cipher_rsa.decrypt(enc_session_key)
    
    @classmethod
    def decrypt_data_with_aes_session_key(self, session_key, private_key_file_name, encrypted_file_name):
        
        # Decrypt the data with the AES session key
        print("Inside method decrypt_data_with_aes_session_key()")
        private_key = RSA.import_key(open("private.pem").read())
        file_in = open(encrypted_file_name, "rb")
        enc_session_key, nonce, tag, ciphertext = \
        [ file_in.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1) ]
        print(nonce)
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        print(data.decode("utf-8"))
        return data