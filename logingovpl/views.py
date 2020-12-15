import base64
import logging
import uuid

from django.conf import settings
from django.contrib.auth import get_user_model, login
from django.core.exceptions import ObjectDoesNotExist
from django.http import (
    HttpResponse,
    HttpResponseBadRequest,
    HttpResponseRedirect,
)
from django.template.loader import render_to_string
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.views.generic import FormView, TemplateView

import requests

from .forms import ACSForm
from .services import get_user, decode_cipher_value
from .statuses import SUCCESS
from .utils import (
    add_sign,
    get_issue_instant,
    get_relay_state,
    get_status_code,
)

logger = logging.getLogger(__name__)


class SSOView(TemplateView):
    """Single sign-on view.

    Returns:
        HttpResponse: redirect to IDP auth view
    """

    http_method_names = ['get']
    template_name = 'Envelop.html'

    def get_authn_request_id(self):
        authn_request_id = 'ID-{}'.format(uuid.uuid4())
        logger.debug('auth_request: %s', authn_request_id)
        return authn_request_id

    def get_signed_authn_request(self):
        xml = render_to_string(
            'AuthnRequest.xml',
            {
                'authn_request_id': self.get_authn_request_id(),
                'authn_request_issue_instant': get_issue_instant(),
                'issuer': settings.LOGINGOVPL_ISSUER,
                'sso_url': settings.LOGINGOVPL_SSO_URL,
                'acs_url': settings.LOGINGOVPL_ASSERTION_CONSUMER_URL,
            },
        )

        return add_sign(
            xml, settings.LOGINGOVPL_ENC_KEY, settings.LOGINGOVPL_ENC_CERT,
        )

    def get_context_data(self, **kwargs):
        relay_state = get_relay_state()
        signed = self.get_signed_authn_request()

        return {
            'envelop': base64.b64encode(signed.encode()).decode(),
            'relay_state': relay_state,
        }


@method_decorator(csrf_exempt, name='dispatch')
class ACSView(FormView):
    http_method_names = ['post']
    form_class = ACSForm

    def success(self, logingovpl_user):
        """Get or create user and login into the site.

        Args:
            logingovpl_user (LoginGovPlUser): data from ACS response

        Returns:
            HttpResponseRedirect: settings.LOGIN_REDIRECT_URL
        """
        try:
            user = get_user_model().objects.get(
                username=logingovpl_user.pesel,
            )
        except ObjectDoesNotExist:
            user = get_user_model().objects.create_user(
                username=logingovpl_user.pesel,
                first_name=logingovpl_user.first_name,
                last_name=logingovpl_user.last_name,
            )
        login(self.request, user)
        return HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)

    def error(self, response):
        status_code = get_status_code(response.content)
        return HttpResponseBadRequest(status_code)

    def resolve_artifact(self, saml_art):
        xml = render_to_string(
            'ArtifactResolve.xml',
            {
                'artifact_resolve_issue_instant': get_issue_instant(),
                'artifact_resolve_artifact': saml_art,
                'issuer': settings.LOGINGOVPL_ISSUER,
            },
        )

        signed = add_sign(
            xml, settings.LOGINGOVPL_ENC_KEY, settings.LOGINGOVPL_ENC_CERT,
        )

        try:
            response = requests.post(
                settings.LOGINGOVPL_ARTIFACT_RESOLVE_URL,
                data=signed,
                timeout=settings.LOGINGOVPL_TIMEOUT,
            )
        except requests.RequestException:
            logger.exception('ArtifactResolve service request failed:')
            raise

        return response

    def form_valid(self, form):
        saml_art = form.cleaned_data['SAMLart']
        response = self.resolve_artifact(saml_art)
        status_code = get_status_code(response.content)

        if status_code != SUCCESS:
            return self.error(response)

        decoded_content = decode_cipher_value(response.content)
        logingovpl_user = get_user(decoded_content)
        return self.success(logingovpl_user)

    def form_invalid(self, form):
        logger.error('Invalid response from IDP %s', form.errors)  # noqa
