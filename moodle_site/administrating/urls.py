from django.urls import path
from . import views

urlpatterns = [
    path("admin/", views.admin_dashboard, name="admin_dashboard"),
    path("admin/users/delete/<int:user_id>/", views.delete_user, name="delete_user"),
    path("admin/reports/courses/", views.course_report, name="course_report"),
    path("admin/reports/courses/export/", views.export_course_report, name="export_course_report"),
]
