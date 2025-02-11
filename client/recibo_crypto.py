import encrypt_pgp
import encrypt
import encrypt_none
import json

class ReciboCrypto():
    # current version
    VERSION = "circle-0.2beta"

    # encrypt_alg_ids
    ENCRYPT_PGP =  "pgp"
    ENCRYPT_RSA = "RSA_PKCS1_OAEP_AES_EAX"
    NOENCRYPT = "none"

    # IANA media types
    PLAINTEXT = "text/plain;charset=UTF-8"
    PNG = "image/png"
    JPEG = "image/jpeg"
    GIF = "image/gif"

    @staticmethod
    def get_cryptomodule(encrypt_alg_id):
        if encrypt_alg_id == ReciboCrypto.ENCRYPT_PGP:
            return encrypt_pgp
        elif encrypt_alg_id == ReciboCrypto.ENCRYPT_RSA:
            return encrypt
        elif encrypt_alg_id == ReciboCrypto.NOENCRYPT:
            return encrypt_none
        else:
            return None

    @staticmethod
    def generate_encrypt_metadata(version, encrypt_alg_id, mime=None, encrypt_pub_key_filename=None, response_pub_key_filename = None, response_encrypt_alg_id = None):
        send_crypto = ReciboCrypto.get_cryptomodule(encrypt_alg_id)
        respond_crypto = ReciboCrypto.get_cryptomodule(response_encrypt_alg_id)

        metadata = {
            "version": version,
            "encrypt": encrypt_alg_id
        }
        
        if mime:
            metadata["mime"] = mime

        if encrypt_pub_key_filename and send_crypto:
            metadata["encrypt_pub_key"] = send_crypto.read_pub_key(encrypt_pub_key_filename)
            
        if response_pub_key_filename and respond_crypto:
            metadata["response_pub_key"] = respond_crypto.read_pub_key(response_pub_key_filename)

        if response_encrypt_alg_id:
            metadata["response_encrypt_alg_id"] = response_encrypt_alg_id

        return json.dumps(metadata, indent=2)

