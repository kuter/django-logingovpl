# flake8: noqa: E501
from appconf import AppConf


class LoginGovPLConf(AppConf):
    ENC_KEY = "pki/MinisterstwoCyfryzacji_MinisterstwoCyfryzacji_enc_ec.key"
    ENC_CERT = "pki/MinisterstwoCyfryzacji_MinisterstwoCyfryzacji_enc_ec.pem"
    ARTIFACT_RESOLVE_URL = "https://symulator.login.gov.pl/login-services/idpArtifactResolutionService"
    SSO_URL = "https://symulator.login.gov.pl/login/SingleSignOnService"
    ASSERTION_CONSUMER_URL = "http://kro-dev.kronika.gov.pl/idp"
    ISSUER = "MinisterstwoCyfryzacji"
    TIMEOUT = 10
