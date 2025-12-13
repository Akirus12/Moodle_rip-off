from django.urls import path
from . import views

app_name = "administrating"

urlpatterns = [
    path("admin/", views.dashboard, name="dashboard"),
    path("admin/users/", views.user_list, name="user_list"),
    path("admin/users/<int:pk>/", views.user_detail, name="user_detail"),
    path("admin/users/<int:pk>/edit/", views.user_edit, name="user_edit"),
    path("admin/users/<int:pk>/delete/", views.user_delete, name="user_delete"),
    path("admin/reports/enrollments/", views.enrollment_report, name="enrollment_report"),
    path("admin/reports/grades/", views.grade_statistics, name="grade_statistics"),
    path("admin/reports/enrollments/export/", views.enrollment_report_csv, name="enrollment_report_csv"),
]
