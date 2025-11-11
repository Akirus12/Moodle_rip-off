"""moodle_site URL Configuration."""

from django.contrib import admin
from django.urls import path, include

from home.views import auth_panel, home, logout_view

urlpatterns = [
    path("admin/", admin.site.urls),
    path("login/", auth_panel, name="login"),
    path("logout/", logout_view, name="logout"),
    path("", home, name="home"),
    path("assignments/", include("assignments.urls")),

    # Core file management
    path("", include("core.urls")),
]
