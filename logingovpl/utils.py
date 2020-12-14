import datetime
import random
import string

import xmlsec
from defusedxml.lxml import fromstring, tostring


def add_sign(xml, key, cert, debug=False):
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
            elem_id = '#{}'.format(elem_id)

    xmlsec.enable_debug_trace(debug)
    xmlsec.tree.add_ids(elem_to_sign, ['ID'])

    digest_algorithm_transform = xmlsec.Transform.SHA256

    ref = xmlsec.template.add_reference(
        signature, digest_algorithm_transform, uri=elem_id
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


def get_status_code(content):
    tree = fromstring(content)
    try:
        elem = tree.find(
            './/{urn:oasis:names:tc:SAML:2.0:protocol}Response/{urn:oasis:names:tc:SAML:2.0:protocol}Status/{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode/{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode',
        ).attrib
    except AttributeError:
        elem = tree.find(
            './/{urn:oasis:names:tc:SAML:2.0:protocol}Response/{urn:oasis:names:tc:SAML:2.0:protocol}Status/{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode',
        ).attrib
    finally:
        status_code = elem.get('Value')

    return status_code


def get_issue_instant():
    return datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')


def get_relay_state(size=16):
    allowed_chars = string.ascii_letters + string.digits
    return ''.join(random.choice(allowed_chars) for x in range(size))  # noqa
