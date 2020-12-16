import datetime
import random
import string

from defusedxml.lxml import fromstring

from .objects import LoginGovPlUser


def get_issue_instant():
    return datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%SZ')


def get_relay_state(size=16):
    allowed_chars = string.ascii_letters + string.digits
    return ''.join(random.choice(allowed_chars) for x in range(size))  # noqa


def get_status_code(content):
    tree = fromstring(content)
    try:
        elem_attrib = tree.find(
            './/{urn:oasis:names:tc:SAML:2.0:protocol}Response/{urn:oasis:names:tc:SAML:2.0:protocol}Status/{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode/{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode',
        ).attrib
    except AttributeError:
        elem_attrib = tree.find(
            './/{urn:oasis:names:tc:SAML:2.0:protocol}Response/{urn:oasis:names:tc:SAML:2.0:protocol}Status/{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode',
        ).attrib
    finally:
        status_code = elem_attrib.get('Value')

    return status_code


def get_user(content):
    """Return LoginGovPlUser instance based on ArtifactResponse.

    Args:
        content (str): decoded cipher value

    Returns:
        LoginGovPlUser: user object

    """
    tree = fromstring(content)

    first_name = tree.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue[@{http://www.w3.org/2001/XMLSchema-instance}type="naturalperson:CurrentGivenNameType"]').text
    last_name = tree.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue[@{http://www.w3.org/2001/XMLSchema-instance}type="naturalperson:CurrentFamilyNameType"]').text
    date_of_birth = tree.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue[@{http://www.w3.org/2001/XMLSchema-instance}type="naturalperson:DateOfBirthType"]').text
    pesel = tree.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue[@{http://www.w3.org/2001/XMLSchema-instance}type="naturalperson:PersonIdentifierType"]').text

    return LoginGovPlUser(first_name, last_name, date_of_birth, pesel)


def get_in_response_to(content):
    """Return InResponseTo value.

    Args:
        content (str): decoded cipher value

    Returns:
        str: AuthnRequest id

    """
    tree = fromstring(content)

    elem = tree.find('.//{urn:oasis:names:tc:SAML:2.0:assertion}SubjectConfirmationData')

    in_response_to = elem.attrib.get("InResponseTo")

    return in_response_to
