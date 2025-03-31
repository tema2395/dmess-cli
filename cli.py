import argparse # import for create cli-app

from cryptography.hazmat.primitives.asymmetric import x25519 # реализация асимметричного шифрования по алгоритму Curve25519, 
#используемого для генерации приватных и паблик ключей, а также обмен ключами по протоколу ECDH

from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_private_key, load_pem_public_key
)
#Encoding(PEM) - формат для хранения ключей(текстовый формат)
#PrivateFormat(PKCS8) - формат хранения приватных ключей
#PublicFormat(SubjectPublicKeyInfo) - формат для публичных ключей
#NoEncryption - указывает, что приватный ключ сохраняется без доп пароля
#load_pem_private_key/load_pem_public_key - функции загрузки ключей из PEM - файлов

from cryptography.hazmat.primitives.kdf.hkdf import HKDF # механизм получения производного ключа из исходного секрета.

from cryptography.hazmat.primitives import hashes # нужен для указания хеш-функции (например, SHA256), используемой в HKDF для обеспечения безопасности ключа.

from cryptography.hazmat.primitives.ciphers.aead import AESGCM #реализация симметричного шифрования AES в режиме Galois/Counter Mode (GCM). 
#Шифрует данные и одновременно обеспечивает их целостность и аутентичность (т.е. обнаруживает изменения в зашифрованном сообщении).

import os


KEYS_DIR = 'keys'
os.makedirs(KEYS_DIR, exist_ok=True)


#Генерация ключей
def generate_keys():
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    
    #Сохраняем приватный ключ
    with open(f'{KEYS_DIR}/private_key.pem', "wb") as f:
        f.write(private_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
       
    #Сохраняем паблик ключ 
    with open(f'{KEYS_DIR}/public_key.pem', "wb") as f:
        f.write(public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
        
    print("Keys generated successfully")
    

# Генерация общего ключа ECDH
def generate_shared_key(peer_public_key_file):
    with open(f'{KEYS_DIR}/private_key.pem', 'rb') as f:
        private_key = load_pem_private_key(f.read(), password=None)
        
    with open(peer_public_key_file, 'rb') as f:
        peer_public_key = load_pem_public_key(f.read())
        
    shared_key = private_key.exchange(peer_public_key)
    
    # Производная от общего ключа (используем HKDF)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info = b'dmess-cli-ecdh',
    ).derive(shared_key)
    
    return derived_key


#Шифрование сообщений
def encrypt_message(peer_public_key_file, message):
    key = generate_shared_key(peer_public_key_file)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    encrypted = aesgcm.encrypt(nonce, message.encode(), None)
    with open('encrypted_message.bin', 'wb') as f:
        f.write(nonce + encrypted)
    print("Message ecnrypted and saved to encrypted_message.bin")
    
#Дешифрование сообщения
def decrypt_message(peer_public_key_file, encrypted_message_file):
    key = generate_shared_key(peer_public_key_file)
    aesgcm = AESGCM(key)
    with open(encrypted_message_file, 'rb') as f:
        data = f.read()
        nonce, encrypted = data[:12], data[12:]
        decrypted = aesgcm.decrypt(nonce, encrypted, None)
        print("Decrypted message:", decrypted.decode())
        

#CLI-аргументы
parser = argparse.ArgumentParser(description="dMess CLI App")
subparser = parser.add_subparsers(dest="command")


gen_keys_cmd = subparser.add_parser('gen_keys', help="Generate key pair")

encrypt_cmd = subparser.add_parser('encrypt', help="Encrypt a message")
encrypt_cmd.add_argument('--peer-key', required=True, help="Peer`s public key file")
encrypt_cmd.add_argument('--message', required=True, help="Mesage to encrypt")

decrypt_cmd = subparser.add_parser('decrypt', help="Decrypt a message")
decrypt_cmd.add_argument('--peer-key', required=True, help="Peer`s public key file")
decrypt_cmd.add_argument('--file', required=True, help="Encrypted message file")

args = parser.parse_args()


if args.command == 'gen_keys':
    generate_keys()
elif args.command == 'encrypt':
    encrypt_message(args.peer_key, args.message)
elif args.command == 'decrypt':
    decrypt_message(args.peer_key, args.file)
else:
    parser.print_help()
    


    
    