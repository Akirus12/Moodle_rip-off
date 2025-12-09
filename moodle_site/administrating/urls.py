from django.urls import path
from . import views

urlpatterns = [
    path("", views.administrating_page, name="administrating_page"),
]