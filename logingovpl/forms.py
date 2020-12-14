from django import forms


class ACSForm(forms.Form):
    SAMLart = forms.CharField()
    RelayState = forms.CharField()
