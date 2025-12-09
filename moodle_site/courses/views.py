from django.http import HttpRequest, HttpResponse
from django.shortcuts import render, get_object_or_404
from .models import Course, CourseMaterial
from core.models import Assignment


def courses_list(request: HttpRequest) -> HttpResponse:
    """Display all available courses."""
    courses = Course.objects.filter(is_active=True)
    return render(request, "courses/courses_list.html", {"courses": courses})


def course_detail(request: HttpRequest, course_id: int) -> HttpResponse:
    """Display a specific course and its materials."""
    course = get_object_or_404(Course, id=course_id, is_active=True)

    # Teachers who are not the assigned instructor cannot access this course
    user = request.user
    if getattr(user, "is_authenticated", False) and hasattr(user, "is_teacher"):
        if user.is_teacher() and user != course.instructor:
            # Allow admins / superusers to view
            if not getattr(user, "is_superuser", False) and not user.is_administrator():
                return render(request, "courses/courses_list.html", {
                    "courses": Course.objects.filter(is_active=True),
                    "error_message": "You are not the instructor for this course."
                })
    materials = course.materials.all()
    assignments = course.assignments.filter(status__in=['active', 'due']).order_by('-due_date', '-created_at')
    return render(request, "courses/course_detail.html", {
        "course": course,
        "materials": materials,
        "assignments": assignments
    })


def material_detail(request: HttpRequest, material_id: int) -> HttpResponse:
    """Display a specific course material."""
    material = get_object_or_404(CourseMaterial, id=material_id)
    return render(request, "courses/material_detail.html", {"material": material})