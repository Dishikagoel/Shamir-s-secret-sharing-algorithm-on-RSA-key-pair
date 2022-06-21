from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from sslib import shamir
import base64
import sys

# A func to generate a private and public key pair using RSA
def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    private_key_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=serialization.NoEncryption())

    public_key = private_key.public_key()
    public_key_pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

    return private_key_pem, public_key_pem

# A func to split the generated RSA private key into n shards using Shamir's secret scheme, 
# where a minimum of k shards will be required to reassemble the key
def split_into_shards(n, k, private_key):

    shares = shamir.split_secret(secret_bytes=private_key,
                                   required_shares=k,
                                   distributed_shares=n)

    data_base64 = shamir.to_base64(shares)
    with open('PrimeMod.txt', mode='w') as file:
        file.write(data_base64.get("prime_mod"))

    return data_base64["shares"], data_base64["required_shares"]

# A func to save the public key into Public.txt and the private key shards into respectives files (Shard[index].txt)
def shares_to_files(public_key, private_key_shares):

    with open("Public.txt", mode='w') as file:
        file.write(public_key.decode())

    for i in range(len(private_key_shares)):
        with open(f"Shard{i+1}.txt", mode='w') as file:
            file.write(private_key_shares[i])
    return 0

# A func to get the shards from the respective file whose indices have been given by the user to regenrate the private key
def shares_from_files(indices):
    shares = []
    for i in indices:
        with open(f"Shard{i}.txt", mode='r') as file:
            shares.append(file.read())

    return shares

# A function to reassemble the shards to reproduce the sam eRSA private key
def reassemble_shards(min_shares_required, shares):
    data = {}
    with open("PrimeMod.txt", 'r') as file:
        prime_mod = file.read()
    data["required_shares"], data["shares"], data["prime_mod"] = min_shares_required, shares, prime_mod
    private_key = shamir.recover_secret(shamir.from_base64(data))

    return private_key

# A function to encrypt a random message input by the user
def encrypt_message(message: str, public_key_pem):
    serialize_public_key = serialization.load_pem_public_key(public_key_pem,backend=default_backend())
    ciphertext = base64.b64encode(serialize_public_key.encrypt(message, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)))

    return ciphertext

# A function to decrypt the encrypted message using the regenrated private key
def decrypt_message(cipher, private_key_pem):
    serialize_private_key = serialization.load_pem_private_key(private_key_pem,password=None,backend=default_backend())
    plaintext = serialize_private_key.decrypt(base64.b64decode(cipher), padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(), label=None))

    return plaintext

# main func
if __name__ == "__main__":

    print("Welcome to RSA and Shamir'r Secret Algorithm testing")
    private_key, public_key = generate_key_pair()

    if len(sys.argv) < 2:
        n = int(input("Enter the number of shares you would like to split your RSA key into: "))
        k = int(input("Enter the minimum number of shares needed to reassemble the private key: "))
        msg = input("Enter the message to encrypt: ")
    else:
        if len(sys.argv) == 2:
            n = int(sys.argv[1])
            k = int(input("Enter the minimum number of shares needed to reassemble the private key: "))
            msg = input("Enter the message to encrypt: ")
        elif len(sys.argv) == 3:
            n = int(sys.argv[1])
            k = int(sys.argv[2])
            msg = input("Enter the message to encrypt: ")
        else:
            n = int(sys.argv[1])
            k = int(sys.argv[2])
            msg = str(sys.argv[3])

    shares, required_shares= split_into_shards(n, k, private_key)
    shares_to_files(public_key, shares)

    indices = input("Enter the indices of shards you would like to use to reassemble the private key (separate the values by ','): ").split(',')
    indices = set(indices)

    if len(indices) < k:
        sys.exit(f"You need at least {k} shares.")
    if len(indices) > n:
        sys.exit("Too many indices")

    shares_from_files = shares_from_files(indices)
    regenerated_private_key = reassemble_shards(k, shares_from_files)
    ciphertext = encrypt_message(msg.encode(), public_key)
    plaintext = decrypt_message(ciphertext, regenerated_private_key)
    if msg == plaintext.decode():
        print(f"\nMessage successfully decrypted.\nDecrypted message: {plaintext.decode()}")
    else:
        print("Message did not get decrypted. That's sus (◔_◔)")