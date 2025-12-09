from django.urls import path
from . import views

urlpatterns = [
    path("", views.assignments_page, name="assignments"),
]