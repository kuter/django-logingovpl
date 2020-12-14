[![LICENSE](https://img.shields.io/pypi/l/version_control.svg?style=flat-square)](https://raw.githubusercontent.com/kuter/django-version-control/master/LICENSE)
[![pypi-version](https://img.shields.io/pypi/v/django_logingovpl.svg?style=flat-square)](https://pypi.python.org/pypi/django_logingovpl/)
[![wemake-python-styleguide](https://img.shields.io/badge/style-wemake-000000.svg?style=flat-square)](https://github.com/wemake-services/wemake-python-styleguide)
[![gitmoji](https://img.shields.io/badge/gitmoji-%20😜%20😍-FFDD67.svg?style=flat-square)](https://gitmoji.carloscuesta.me)

# Django Login.gov.pl


## Instalacja

1. Korzystając z Python Package Index:

```
$ pip install logingovpl
```

2. Dodaj `logingovpl` do `INSTALLED_APPS`:

```
INSTALLED_APPS = [
    ...
    'logingovpl',
]
```

3. Uzupełnij `urls.py` projektu:

```
urlpatterns = [
    ...
    path('logingovpl/', include('logingovpl.urls')),
]
```

3. Konfiguracja:
