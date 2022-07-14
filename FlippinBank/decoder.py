#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from Crypto.Random import get_random_bytes
from binascii import unhexlify

m = 'logged_username=12345678901admim&password=g0ld3n_b0y'

key = get_random_bytes(16)
iv = get_random_bytes(16)

def encrypt_data(data):
	padded = pad(data.encode(),16,style='pkcs7')
	cipher = AES.new(key, AES.MODE_CBC,iv)
	enc = cipher.encrypt(padded)
	return enc.hex()

def decrypt_data(encryptedParams):
	cipher = AES.new(key, AES.MODE_CBC,iv)
	paddedParams = cipher.decrypt( unhexlify(encryptedParams))
	print(paddedParams)
	if b'admin&password=g0ld3n_b0y' in unpad(paddedParams,16,style='pkcs7'):
		return 1
	else:
		return 0

enc = encrypt_data(m)
# enc = '3959013a41db05dd405c9a9d22f39375dd35b05dd9a2a979cd1476dc427dfa3c22099175b66ff7ac79fc9eefaa261413541887463b2d88c32cf7fe31abac00e5'
fake_enc = bytes.fromhex(enc)
fake_enc = list(fake_enc)
fake_enc[15] = fake_enc[15] ^ ord('m') ^ ord('n')
fake_enc = bytes(fake_enc).hex()
print(fake_enc)

dec = decrypt_data(fake_enc) # enc
print(dec)
