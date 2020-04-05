import os
import argparse
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


def read(file_name, tp):
    with open(file_name, tp) as f:
        data = f.read()
    return data


def write(file_name, data, tp):
    with open(file_name, tp) as f:
        f.write(data)


def create_keys(passphrase, private='my_private_rsa_key.pem', public='my_rsa_public.pem'):
    key = RSA.generate(2048)

    encrypted_key = key.exportKey(
        passphrase=passphrase,
        pkcs=8,
        protection="scryptAndAES128-CBC"
    )
    public_key = key.publickey().exportKey()

    write(private, encrypted_key, 'wb')
    write(public, public_key, 'wb')
    print(f'Keys was saved in:\n{private}\n{public}')
    return encrypted_key, public_key


def encrypt_file(file_data, output=None, public='my_rsa_public.pem'):
    output = output or file_data
    data = read(file_data, 'rb')
    recipient_key = RSA.import_key(read(public, 'rb'))

    session_key = get_random_bytes(16)
    cipher_rsa = PKCS1_OAEP.new(recipient_key)
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(data)
    with open(output, 'wb') as out_f:
        out_f.write(cipher_rsa.encrypt(session_key))
        out_f.write(cipher_aes.nonce)
        out_f.write(tag)
        out_f.write(ciphertext)


def decrypt_file(file_data, passphrase, output=None, private='my_private_rsa_key.pem'):
    output = output or file_data
    try:
        private_key = RSA.import_key(read(private, 'rb'), passphrase=passphrase)
    except ValueError:
        print('Wrong passphrase or private_rsa_key')
        return
    with open(file_data, 'rb') as fobj:
        enc_session_key, nonce, tag, ciphertext = [
            fobj.read(x) for x in (private_key.size_in_bytes(), 16, 16, -1)
        ]

    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)

    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    write(output, data.decode(), 'w')
    print(f'Decryption saved into {output}')


def iterable_decor(function):
    def wrapper(directory, *args, **kwargs):
        for _dir, _, files in os.walk(directory):
            for file in files:
                path = os.path.join(_dir, file)
                try:
                    function(path, *args, **kwargs)
                except Exception as exp:
                    print(path, exp, exp.args)
        print('Completed')

    return wrapper


@iterable_decor
def encrypt_dir(*args, **kwargs):
    encrypt_file(*args, **kwargs)


@iterable_decor
def decrypt_dir(*args, **kwargs):
    decrypt_file(*args, **kwargs)


def parser():
    arg_parser = argparse.ArgumentParser(description='Encryptor/Decryptor for files')
    arg_parser.add_argument(
        '-f', '--input',
        help='input file',
        type=str)

    arg_parser.add_argument(
        '-d', '--dir',
        help='directory',
        type=str)

    arg_parser.add_argument(
        '-o', '--output',
        help='output file',
        type=str)

    arg_parser.add_argument(
        '-pub', '--public',
        help='public key',
        type=str)

    arg_parser.add_argument(
        '-p', '--phrase',
        help='passphrase for crypt',
        type=str)

    arg_parser.add_argument(
        '-priv', '--private',
        help='private key',
        type=str)

    arg_parser.add_argument(
        '-m', '--mode',
        choices=['encrypt', 'decrypt', 'create'],
        help='encrypt, decrypt or create',
        type=str)

    args = arg_parser.parse_args()

    return args.input, args.dir, args.output, args.public, args.phrase, args.private, args.mode


def main():
    basic_private = 'my_private_rsa_key.pem'
    basic_public = 'my_rsa_public.pem'
    input_file, directory, output_file, public_key, passphrase, private_key, mode = parser()
    if mode == 'create':
        if passphrase is None:
            passphrase = input('Enter passphrase: ')

        create_keys(passphrase,
                    private_key or basic_private,
                    public_key or basic_public)

    elif mode == 'encrypt':

        if directory:
            encrypt_dir(directory, output=output_file,
                        public=public_key or basic_public)

        elif input_file:
            encrypt_file(input_file, output=output_file,
                         public=public_key or basic_public)

        else:
            print('Enter -f file name or -d directory to encrypt')

    elif mode == 'decrypt':
        if passphrase is None:
            passphrase = input('Enter passphrase: ')

        if directory:
            decrypt_dir(directory, passphrase=passphrase,
                        output=output_file,
                        private=private_key or basic_private)

        elif input_file:
            decrypt_file(input_file, passphrase=passphrase,
                         output=output_file,
                         private=private_key or basic_private)

        else:
            print('Enter -f file name or -d directory to decrypt')


if __name__ == '__main__':
    main()
