import base64
import binascii
import logging
from xml.etree import ElementTree as ET

from django.conf import settings

from Crypto.Cipher import AES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from .objects import LoginGovPlUser

logger = logging.getLogger(__name__)


def get_otherinfo(concat_kdf_params):
    """Concatenate ConcatKDFParams.

    Args:
        concat_kdf_params (Element): xml.tree element

    Returns:
        string: concatenated AlgorithmID, PartyUInfo, PartyVInfo

    """
    attrib = concat_kdf_params.attrib
    AlgorithmID = attrib['AlgorithmID']
    PartyUInfo = attrib['PartyUInfo']
    PartyVInfo = attrib['PartyVInfo']
    otherinfo = ''.join([AlgorithmID, PartyUInfo, PartyVInfo])
    logger.debug('otherinfo: %s', otherinfo)
    return otherinfo


def get_user(content):
    """Get user from ACS service response.

    Args:
        content (bytes): response.content

    Returns:
        tuple: first_name, last_name, DOB, PESEL

    """
    tree = ET.fromstring(content)

    PUBLIC_KEY = tree.find('.//{http://www.w3.org/2009/xmldsig11#}PublicKey').text
    CIPHER_VALUE = tree.find('.//{http://www.w3.org/2001/04/xmlenc#}CipherValue').text
    USER_ATTRS = tree.find('.//{http://www.w3.org/2001/04/xmlenc#}EncryptedData/{http://www.w3.org/2001/04/xmlenc#}CipherData/{http://www.w3.org/2001/04/xmlenc#}CipherValue').text
    concatKDFParams = tree.find('.//{http://www.w3.org/2009/xmlenc11#}ConcatKDFParams')

    with open(settings.LOGINGOVPL_ENC_KEY, 'rb') as f:
        server_private_key = load_pem_private_key(f.read(), None, default_backend())

    public_key_bytes = base64.b64decode(PUBLIC_KEY)
    curve = ec.SECP256R1()

    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, public_key_bytes)

    peer_public_key_pem = peer_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    logger.debug('Peer public key:\n%s', peer_public_key_pem.decode())

    shared_key = server_private_key.exchange(
        ec.ECDH(), peer_public_key)
    logger.debug('Shared key: %s', shared_key)

    otherinfo = get_otherinfo(concatKDFParams)

    ckdf = ConcatKDFHash(
        algorithm=hashes.SHA256(),
        length=32,
        otherinfo=binascii.unhexlify(otherinfo.encode()),
        backend=default_backend()
    )

    cipher_bytes = base64.b64decode(CIPHER_VALUE)
    wrapping_key = ckdf.derive(shared_key)
    logger.debug("Wrapping key: %s", wrapping_key)

    session_key = aes_key_unwrap(wrapping_key, cipher_bytes, default_backend())
    user_attr_bytes = base64.b64decode(USER_ATTRS)
    nonce, tag = user_attr_bytes[:12], user_attr_bytes[-16:]
    cipher = AES.new(session_key, AES.MODE_GCM, nonce)
    decoded_saml = cipher.decrypt_and_verify(user_attr_bytes[12:-16], tag)

    tree = ET.fromstring(decoded_saml)

    first_name = tree.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue[@{http://www.w3.org/2001/XMLSchema-instance}type="naturalperson:CurrentGivenNameType"]').text
    last_name = tree.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue[@{http://www.w3.org/2001/XMLSchema-instance}type="naturalperson:CurrentFamilyNameType"]').text
    date_of_birth = tree.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue[@{http://www.w3.org/2001/XMLSchema-instance}type="naturalperson:DateOfBirthType"]').text
    pesel = tree.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue[@{http://www.w3.org/2001/XMLSchema-instance}type="naturalperson:PersonIdentifierType"]').text

    user = LoginGovPlUser(first_name, last_name, date_of_birth, pesel)
    return user
