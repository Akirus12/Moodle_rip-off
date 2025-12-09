from django.shortcuts import render
from core.models import Course
from .models import CourseMaterial
from django.http import HttpRequest, HttpResponse
from django.shortcuts import get_object_or_404

def courses_list(request: HttpRequest) -> HttpResponse:
    """Display all available courses."""
    courses = Course.objects.filter(is_active=True)
    return render(request, "courses/courses_list.html", {"courses": courses})

def course_detail(request: HttpRequest, course_id: int) -> HttpResponse:
    """Display a specific course and its materials."""
    course = get_object_or_404(Course, id=course_id, is_active=True)
    materials = course.course_materials.all()  # Changed from materials to course_materials
    return render(request, "courses/course_detail.html", {
        "course": course,
        "materials": materials
    })

def material_detail(request: HttpRequest, material_id: int) -> HttpResponse:
    """Display a specific course material."""
    material = get_object_or_404(CourseMaterial, id=material_id)
    return render(request, "courses/material_detail.html", {"material": material})