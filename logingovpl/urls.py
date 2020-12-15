from django.urls import path

from . import views

urlpatterns = [
    path('login/', views.SSOView.as_view()),
    path('acs/', views.ACSView.as_view()),
]
