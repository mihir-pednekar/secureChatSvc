'''
Created on 20-Feb-2020

@author: mihir
'''
from cryptUtil import cryptoUtil

data = "hello mihir".encode("utf-8")
encrypted_file_name ="encrypted_session_key.bin"
encrypted_data ="encrypted_data.bin"

cryp = cryptoUtil()

cryp.generate_public_private_key()
cryp.generate_receiver_public_private_key()
session_key = cryp.generate_session_key()
print(session_key)
enc_session_key = cryp.encrypt_session_key_with_public_key("receiver_public.pem", encrypted_file_name, session_key)
decrypted_session_key = cryp.decrypt_session_key_with_private_key("receiver_private.pem", encrypted_file_name, enc_session_key)
print(decrypted_session_key)
cryp.encrypt_data_with_aes_session_key(data, session_key, enc_session_key, encrypted_data)
decrypted_data = cryp.decrypt_data_with_aes_session_key(session_key, "receiver_private.pem", encrypted_data)

