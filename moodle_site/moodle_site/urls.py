"""moodle_site URL Configuration."""

from django.contrib import admin
from django.urls import path, include

from home.views import home

urlpatterns = [
    path("admin/", admin.site.urls),
    path("", home, name="home"),
    path("messages/", include("messaging.urls")),
]
