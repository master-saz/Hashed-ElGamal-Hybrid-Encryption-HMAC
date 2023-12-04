import os
import sys
import re


def decryption(cipher_file="ciphertext.pem", dest_name="alice"):

    """if not os.path.isfile(f"{dest_name}_pkey.pem"):
        print(f"{dest_name}_pkey.pem does not exist")
        sys.exit(1)"""

    try:
        f = open(cipher_file, "r")
        file_content = f.read()
        f.close()
    except:
        print(f"{cipher_file} does not exist")
        sys.exit(1)

    pub_key_i = file_content.find("-----END PUBLIC KEY-----")
    #pub_key = file_content[:pub_key_i + 24]

    file_content = file_content.split('\n')
    sys.exit(0)
    os.system("echo -n \"" + pub_key + "\" > ephpub.pem")

    # IV
    iv_i = file_content.find("-----END AES-128-CBC IV-----")
    iv = file_content[pub_key_i + 56:iv_i]
    os.system("echo -n \"" + iv + "\" | openssl base64 -d -out iv.bin")

    # CIPHERTEXT
    cipher_i = file_content.find("-----END AES-128-CBC CIPHERTEXT-----")
    cipher = file_content[iv_i + 68:cipher_i]
    os.system("echo -n \"" + cipher + "\" | openssl base64 -d -out ciphertext.bin")

    # TAG
    tag_i = file_content.find("-----END SHA256-HMAC TAG-----")
    tag = file_content[cipher_i + 69:tag_i]
    os.system("echo -n \"" + tag + "\" | openssl base64 -d -out tag.bin")

    # Generating common key
    os.system("openssl pkeyutl -inkey " + sys.argv[2] + "_pkey.pem -peerkey ephpub.pem -derive -out common.bin")

    # Extracting Key1 & Key2
    os.system("cat common.bin | openssl dgst -sha256 -binary | head -c 16 > k1.bin")
    os.system("cat common.bin | openssl dgst -sha256 -binary | tail -c 16 > k2.bin")

    # Generating the tag
    os.system(
        "cat iv.bin ciphertext.bin | openssl dgst -sha256 -mac hmac -macopt hexkey:`cat k2.bin | xxd -p` -binary > deciphered_tag.bin")

    # Checking the tag
    if os.popen("cat tag.bin | openssl base64").read() == os.popen("cat deciphered_tag.bin | openssl base64").read():
        # Decrypting the message
        os.system(
            "openssl enc -aes-128-cbc -d -in ciphertext.bin -iv `cat iv.bin | xxd -p` -K `cat k1.bin | xxd -p` -out deciphered.txt")
    else:
        print("*** ERROR: Wrong TAG. Please specify the correct receiver. ***")

    # Cleaning the aux files
    os.system("rm iv.bin ciphertext.bin ephpub.pem tag.bin k1.bin k2.bin common.bin deciphered_tag.bin")


def encryption(name="alice", msg="This is a test"):

    if not os.path.isfile("param.pem"):
        print("param.pem does not exist")
        sys.exit(1)

    if not os.path.isfile(f"{name}_pubkey.pem"):
        print(f"{name}_pubkey.pem does not exist")
        sys.exit(1)

    os.system("openssl genpkey -paramfile param.pem -out ephpkey.pem") # Compute an ephemeral Diffie-Hellman keypair
    os.system("openssl pkey -in ephpkey.pem -pubout -out  ephpubkey.pem") # Generate the corresponding ephemeral public key file

    """Derive a common secret from the secret ephemeral key r, contained in ephpkey.pem, and the long-term
    public key of the recipient, contained in alice_pubkey.pem, with openssl pkeyutl with the -derive
    option.
    """
    os.system(f"openssl pkeyutl -inkey ephpkey.pem -peerkey {name}_pubkey.pem -derive -out common_secret.bin")

    """Apply SHA256 to the common secret with openssl dgst (see the previous practical work), and split
    it into two halves to obtain k1 and k2. Starting from the 32 bytes long binary file with the hash value,
    you can use head -c 16 and tail -c 16 to extract the first and the last 16 bytes."""
    os.system("cat common_secret.bin | openssl dgst -sha256 -binary | head -c 16 > k1.bin")
    os.system("cat common_secret.bin | openssl dgst -sha256 -binary | tail -c 16 > k2.bin")

    """Encrypt the desired file with AES-128-CBC using key k1, with openssl enc -aes-128-cbc and store
    the result in the file ciphertext.bin (see previous practical works). Some useful tools helps converting
    binary files into the plain hexadecimal representation, like xxd -p. You would need to provide an iv
    for the encryption operation. You can generate a random one with openssl rand 16 and store it in
    the file iv.bin.
    """
    os.system("openssl rand 16 > iv.bin")
    os.system(f"echo -n \"{msg}\" | openssl enc -aes-128-cbc -K `cat k1.bin | xxd -p` -iv `cat iv.bin | xxd -p` > ciphertext.bin")

    """Use key k2 to compute the SHA256-HMAC tag of the concatenation of iv.bin and ciphertext.bin
    with openssl dgst -hmac -sha256 to obtain the binary file tag.bin (again, you can find the details
    in the previous practical work)."""
    os.system("cat iv.bin ciphertext.bin | openssl dgst -sha256 -mac hmac -macopt hexkey:`cat k2.bin | xxd -p` -binary > tag.bin")

    """Ideally, a single file in PEM or DER format joining the four would be a better option. You can do that
    by concatenating the printable (base64 encoded) files with adequate headers and footers. For instance, you
    can start from the file ephpubkey.pem that already is in PEM format, then concatenate it with the base64
    encoding of ciphertext.bin , iv.bin and tag.bin with some PEM style headers and footers added:"""
    os.system("cat ephpubkey.pem > ciphertext.pem")
    os.system("echo \"-----BEGIN AES-128-CBC IV-----\" >> ciphertext.pem")
    os.system("cat iv.bin | openssl base64 >> ciphertext.pem")
    os.system("echo \"-----END AES-128-CBC IV-----\" >> ciphertext.pem")
    os.system("echo \"-----BEGIN AES-128-CBC CIPHERTEXT-----\" >> ciphertext.pem")
    os.system("cat ciphertext.bin | openssl base64 >> ciphertext.pem")
    os.system("echo \"-----END AES-128-CBC CIPHERTEXT-----\" >> ciphertext.pem")
    os.system("echo \"-----BEGIN SHA256-HMAC TAG-----\" >> ciphertext.pem")
    os.system("cat tag.bin | openssl base64 >> ciphertext.pem")
    os.system("echo \"-----END SHA256-HMAC TAG-----\" >> ciphertext.pem")

    # remove the temporary files
    os.system("rm iv.bin eph* ciphertext.bin tag.bin k1.bin k2.bin common_secret.bin")


def param_key_gen(name="alice"):

    # If it is not generated, it creates it
    if not os.path.isfile("param.pem"):
        os.system("openssl genpkey -genparam -algorithm dh -pkeyopt dh_rfc5114:3 -out param.pem")

    os.system(f"openssl genpkey -paramfile param.pem -out {name}_pkey.pem") # Generate the long-term keypair
    os.system(f"openssl pkey -in {name}_pkey.pem -pubout -out {name}_pubkey.pem") # Extract the long-term public key


if __name__ == '__main__':
    #param_key_gen()
    #encryption()
    decryption()