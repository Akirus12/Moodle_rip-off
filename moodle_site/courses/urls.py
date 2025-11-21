from django.urls import path
from . import views

app_name = 'courses'

urlpatterns = [
    path("", views.courses_list, name="courses_list"),
    path("<int:course_id>/", views.course_detail, name="course_detail"),
    path("material/<int:material_id>/", views.material_detail, name="material_detail"),
]