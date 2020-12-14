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
from django.views.generic import FormView

import requests

from .forms import ACSForm
from .services import get_user
from .statuses import SUCCESS
from .utils import (
    add_sign,
    get_issue_instant,
    get_relay_state,
    get_status_code,
)

logger = logging.getLogger(__name__)


def sso(request):
    """Signle sign-on view.

    Returns:
        HttpResponse: redirect to IDP auth view
    """
    authn_request_id = 'ID-{}'.format(uuid.uuid4())
    relay_state = get_relay_state()

    xml = render_to_string(
        'AuthnRequest.xml',
        {
            'authn_request_id': authn_request_id,
            'authn_request_issue_instant': get_issue_instant(),
            'issuer': settings.LOGINGOVPL_ISSUER,
            'sso_url': settings.LOGINGOVPL_SSO_URL,
            'acs_url': settings.LOGINGOVPL_ASSERTION_CONSUMER_URL,
        },
    )

    signed = add_sign(
        xml, settings.LOGINGOVPL_ENC_KEY, settings.LOGINGOVPL_ENC_CERT,
    )

    data = render_to_string(
        'Envelop.html',
        {
            'envelop': base64.b64encode(signed.encode()).decode(),
            'relay_state': relay_state,
        },
    )

    return HttpResponse(data)


@method_decorator(csrf_exempt, name='dispatch')
class ACSView(FormView):
    http_method_names = ['post']
    form_class = ACSForm

    def success(self, response):
        login_gov_pl_user = get_user(response.content)
        try:
            user = get_user_model().objects.get(
                username=login_gov_pl_user.pesel,
            )
        except ObjectDoesNotExist:
            user = get_user_model().objects.create_user(
                username=login_gov_pl_user.pesel,
                first_name=login_gov_pl_user.first_name,
                last_name=login_gov_pl_user.last_name,
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

        return self.success(response)

    def form_invalid(self, form):
        logger.error('Invalid response from IDP %s', form.errors)  # noqa
