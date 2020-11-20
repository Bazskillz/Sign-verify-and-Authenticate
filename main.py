#!/usr/bin/python

import argparse
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from hashlib import sha256
from Crypto.Cipher import AES, PKCS1_OAEP

# init argparse
parser = argparse.ArgumentParser(description='Sign, verify and authenticate an input file')

parser.add_argument('studentnummer', metavar='studentnummer', type=int, help='Your studentnummer')
parser.add_argument('input_file', metavar='input_file', type=str, help='the path to list')

args = parser.parse_args()

# generate RSA keypair
key_pair = RSA.generate(bits=1024)


def verify_signature(shasum, signature):
    """ verifies the rsa signature with the hash, using the private RSA key.

    :param shasum: the shasum of the signed file
    :param signature: signature of the shasum

    """
    int_sha_sum = int.from_bytes(shasum, byteorder='big')
    hash_signature = pow(signature, key_pair.e, key_pair.n)
    print("Signature valid:", int_sha_sum == hash_signature)


def file_sign_and_verify():
    """ sign, verify and authenticate input_file.
    :return:
    """
    write_pub_key()
    file_sha256sum = sha256_input_file(args.input_file)
    sha_256_signature = sign_sha256sum_pvt_key(file_sha256sum)
    verify_signature(file_sha256sum, sha_256_signature)
    encrypt_input_file_aes()


def sha256_input_file(input_file):
    """ returns the sha256sum of input_file
    :param input_file: the input file / document
    :return bytes hash digest
    """
    with open(input_file, "rb") as f:
        input_file_bytes = f.read()  # read entire file as bytes
        sha_hash = sha256(input_file_bytes)
        with open('%s.hash' % args.studentnummer, "w") as w:
            sha_hash_hex_dig = sha_hash.hexdigest()
            w.write(sha_hash_hex_dig)
        return sha_hash.digest()


def sign_sha256sum_pvt_key(file_sha256sum):
    """ returns the RSA signature of SHA256sum
    :param file_sha256sum: the input sha256sum

    """
    signature = pow(int.from_bytes(file_sha256sum, byteorder='big'), key_pair.d, key_pair.n)
    with open("%s.sign" % args.studentnummer, "w") as f:
        f.write(str(signature))
    return signature


def write_pub_key():
    """
    writes the public RSA key to {studentnummer}.pub
    :return:
    """
    with open('%s.pub' % args.studentnummer, 'wb') as f:
        f.write(key_pair.publickey().export_key('PEM'))


def encrypt_input_file_aes():
    """ creates session key, encrypts input file with key to studentnummer.code.
    then encrypts and writes that with frans public key

    :return:
    """
    with open(args.input_file, 'rb') as f:
        data = f.read()
    file_out = open("%s.code" % args.studentnummer, "wb")
    recipient_key = RSA.import_key(open("keys/frans_rsa_key.pem").read())
    session_key = get_random_bytes(16)

    # Encrypt the session key with the public RSA key
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    enc_session_key = cipher_rsa.encrypt(session_key)

    # Write encrypted session key to file
    with open("%s.skey" % args.studentnummer, "wb") as s:
        s.write(enc_session_key)

    # Encrypt the data with the AES session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    [file_out.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
    file_out.close()


if __name__ == '__main__':
    file_sign_and_verify()
