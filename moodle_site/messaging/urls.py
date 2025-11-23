# messaging/urls.py
from django.urls import path
from . import views

app_name = "messaging"

urlpatterns = [
    path("", views.messages_page, name="page"),  # use {% url 'messaging:page' %} for menu
    path("send/", views.send_message, name="send_message"),
    path("edit/<int:pk>/", views.edit_message, name="edit_message"),
    path("delete/<int:pk>/", views.delete_message, name="delete_message"),
    path("broadcast/", views.broadcast_message, name="broadcast_message"),
]
