from django.contrib import admin
from django.contrib.auth import views
from django.http import HttpResponse
from django.urls import include, path

from logingovpl import views as logingovpl_views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('idp', logingovpl_views.ACSView.as_view()),
    path('accounts/logout/', views.LogoutView.as_view(), name='logout'),
    path('logingovpl/', include('logingovpl.urls')),
    path(
        'accounts/profile/',
        lambda x: HttpResponse(
            "You're logged in as {}".format(x.user.get_full_name()),
        ),
    ),
]
