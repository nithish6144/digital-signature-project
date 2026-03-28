from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
key=b'Mykeyforsixteena'
data=b'HELLOAES'
Cipher=AES.new(key,AES.MODE_ECB)
enc=Cipher.encrypt(pad(data,16))
print("Original data:",data)
print("Encrypted data:",enc)
dec=unpad(Cipher.decrypt(enc),16)
print("Dcrypted data:",dec.decode())