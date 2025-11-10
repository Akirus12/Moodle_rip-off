"""URL patterns for core file management."""
from django.urls import path
from . import views

app_name = 'core'

urlpatterns = [
    # File list and upload
    path('files/', views.file_list, name='file_list'),
    path('files/upload/', views.file_upload, name='file_upload'),

    # File detail and actions
    path('files/<int:file_id>/', views.file_detail, name='file_detail'),
    path('files/<int:file_id>/view/', views.file_view_metadata, name='file_view_metadata'),
    path('files/<int:file_id>/get/', views.file_retrieve, name='file_retrieve'),
    path('files/<int:file_id>/delete/', views.file_delete, name='file_delete'),

    # File sharing
    path('files/<int:file_id>/share/create/', views.file_share_create, name='file_share_create'),
    path('s/<uuid:uuid>/', views.share_access, name='share_access'),
    path('s/<uuid:uuid>/download/', views.share_download, name='share_download'),
]
