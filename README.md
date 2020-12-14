[![build status](http://gitlab/kuter/logingovpl/badges/master/build.svg)](http://gitlab/kuter/logingovpl/commits/master)
[![coverage report](http://gitlab/kuter/logingovpl/badges/master/coverage.svg)](http://gitlab/kuter/logingovpl/commits/master)
=====
Django Login.gov.pl auth
=============================
Third-party app created with https://github.com/kuter/django-plugin-template-cookiecutter

Quick start
-----------
1. Add "logingovpl" to your INSTALLED_APPS setting like this::

    INSTALLED_APPS = [
        ...
        'logingovpl',
    ]
2. Include the polls URLconf in your project urls.py like this::

    path('logingovpl/', include('logingovpl.urls')),

3. Run `python manage.py migrate` to create the logingovpl models.
4. Start the development server and visit http://127.0.0.1:8000/admin/
to create a logingovpl object (you'll need the Admin app enabled).
5. Visit http://127.0.0.1:8000/logingovpl/.
