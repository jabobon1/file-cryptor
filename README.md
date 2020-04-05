# file-cryptor
Decrypt and encrypt files with RSA from module Crypto

all possible args:
-f, --input - input file
-d, --dir - directory
-o, --output - output files
-pub, --public - path to public key
-priv, --private - path to private key
-p, --phrase - passphrase for encryption
-m, --mode - [encrypt, decrypt, create] choosing mode


Example:
# Create keys
python3 cryptor.py -m create -priv private_key.pem -pub public_key.pem
python3 cryptor.py -m create        # For default paths

# Encrypt file
python3 cryptor.py -f test.txt -m encrypt
# Decrypt file
python3 cryptor.py -f test.txt -m decrypt -p phrase -priv private_key.pem
