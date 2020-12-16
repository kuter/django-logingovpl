import base64
import binascii
import logging

from django.conf import settings

from Crypto.Cipher import AES
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from defusedxml.lxml import fromstring, tostring
import xmlsec

logger = logging.getLogger(__name__)


def get_otherinfo(concat_kdf_params):
    """Concatenate ConcatKDFParams.

    Args:
        concat_kdf_params (Element): xml.tree element

    Returns:
        string: concatenated AlgorithmID, PartyUInfo, PartyVInfo

    """
    otherinfo = ''.join([
        concat_kdf_params.attrib['AlgorithmID'],
        concat_kdf_params.attrib['PartyUInfo'],
        concat_kdf_params.attrib['PartyVInfo'],
    ])
    return otherinfo


def decode_cipher_value(content):
    """Get user from ACS service response.

    Args:
        content (bytes): response.content

    Returns:
        tuple: first_name, last_name, DOB, PESEL

    """
    tree = fromstring(content)

    PUBLIC_KEY = tree.find('.//{http://www.w3.org/2009/xmldsig11#}PublicKey').text
    CIPHER_VALUE = tree.find('.//{http://www.w3.org/2001/04/xmlenc#}CipherValue').text
    USER_ATTRS = tree.find('.//{http://www.w3.org/2001/04/xmlenc#}EncryptedData/{http://www.w3.org/2001/04/xmlenc#}CipherData/{http://www.w3.org/2001/04/xmlenc#}CipherValue').text
    concatKDFParams = tree.find('.//{http://www.w3.org/2009/xmlenc11#}ConcatKDFParams')

    with open(settings.LOGINGOVPL_ENC_KEY, 'rb') as f:
        server_private_key = load_pem_private_key(
            f.read(), None, default_backend(),
        )

    public_key_bytes = base64.b64decode(PUBLIC_KEY)
    curve = ec.SECP256R1()

    peer_public_key = ec.EllipticCurvePublicKey.from_encoded_point(curve, public_key_bytes)

    peer_public_key_pem = peer_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    logger.debug('peer public key:\n%s', peer_public_key_pem.decode())

    shared_key = server_private_key.exchange(
        ec.ECDH(), peer_public_key)
    logger.debug('shared key: %s', shared_key)

    otherinfo = get_otherinfo(concatKDFParams)
    logger.debug('otherinfo: %s', otherinfo)

    ckdf = ConcatKDFHash(
        algorithm=hashes.SHA256(),
        length=32,
        otherinfo=binascii.unhexlify(otherinfo.encode()),
        backend=default_backend()
    )

    cipher_bytes = base64.b64decode(CIPHER_VALUE)
    wrapping_key = ckdf.derive(shared_key)
    logger.debug('wrapping key: %s', wrapping_key)

    session_key = aes_key_unwrap(wrapping_key, cipher_bytes, default_backend())
    user_attr_bytes = base64.b64decode(USER_ATTRS)
    nonce, tag = user_attr_bytes[:12], user_attr_bytes[-16:]
    cipher = AES.new(session_key, AES.MODE_GCM, nonce)
    decoded_saml = cipher.decrypt_and_verify(user_attr_bytes[12:-16], tag)
    logger.debug(decoded_saml)

    return decoded_saml


def add_sign(xml, key, cert, debug=False):
    """Add sign.

    Args:
        xml (str): SAML assertion
        key (Path): path enc key
        cert (Path): path to cert/pem
        debug (boolean): xmlsec enable debug trace

    Returns:
        str: signed SAML assertion

    Raises:
        Exception: if xml is empty
    """
    if xml is None or xml == '':
        raise Exception('Empty string supplied as input')

    elem = fromstring(xml.encode('utf-8'), forbid_dtd=True)

    sign_algorithm_transform = xmlsec.Transform.ECDSA_SHA256

    signature = xmlsec.template.create(
        elem, xmlsec.Transform.EXCL_C14N, sign_algorithm_transform, ns='ds',
    )

    issuer = elem.findall('.//{urn:oasis:names:tc:SAML:2.0:assertion}Issuer')
    if issuer:
        issuer = issuer[0]
        issuer.addnext(signature)
        elem_to_sign = issuer.getparent()

    elem_id = elem_to_sign.get('ID', None)
    if elem_id is not None:
        if elem_id:
            elem_id = f'#{elem_id}'

    xmlsec.enable_debug_trace(debug)
    xmlsec.tree.add_ids(elem_to_sign, ['ID'])

    digest_algorithm_transform = xmlsec.Transform.SHA256

    ref = xmlsec.template.add_reference(
        signature, digest_algorithm_transform, uri=elem_id,
    )
    xmlsec.template.add_transform(ref, xmlsec.Transform.ENVELOPED)
    xmlsec.template.add_transform(ref, xmlsec.Transform.EXCL_C14N)
    key_info = xmlsec.template.ensure_key_info(signature)
    xmlsec.template.add_x509_data(key_info)

    dsig_ctx = xmlsec.SignatureContext()
    sign_key = xmlsec.Key.from_file(key, xmlsec.KeyFormat.PEM, None)
    sign_key.load_cert_from_file(cert, xmlsec.KeyFormat.PEM)

    dsig_ctx.key = sign_key
    dsig_ctx.sign(signature)

    return tostring(elem).decode()
