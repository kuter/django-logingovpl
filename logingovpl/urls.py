from django.urls import path

from . import views

urlpatterns = [
    path('login/', views.sso),
    path('acs/', views.ACSView.as_view()),
]
