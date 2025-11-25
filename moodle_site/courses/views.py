from django.http import HttpRequest, HttpResponse
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from .models import Course, CourseMaterial, CourseCompletion

@login_required
def course_statistics(request: HttpRequest, course_id: int) -> HttpResponse:
    """Display course completion statistics."""
    course = get_object_or_404(Course, id=course_id, is_active=True)

    # Get or create completion tracking for this user
    completion, created = CourseCompletion.objects.get_or_create(
        course=course,
        user=request.user
    )

    context = {
        'course': course,
        'completion_percentage': completion.get_completion_percentage(),
        'completed_materials': completion.completed_materials.all(),
        'remaining_materials': course.materials.exclude(
            id__in=completion.completed_materials.values_list('id', flat=True)
        )
    }

    return render(request, 'courses/course_statistics.html', context)
def courses_list(request: HttpRequest) -> HttpResponse:
    """Display all available courses."""
    courses = Course.objects.filter(is_active=True)
    return render(request, "courses/courses_list.html", {"courses": courses})

@login_required
def course_detail(request: HttpRequest, course_id: int) -> HttpResponse:
    """Display a specific course and its materials."""
    course = get_object_or_404(Course, id=course_id, is_active=True)
    materials = course.materials.all()
    completion_percentage = course.get_completion_percentage(request.user)

    context = {
        "course": course,
        "materials": materials,
    }
    
    if completion_percentage is not None:
        context["completion_percentage"] = completion_percentage
    
    return render(request, "courses/course_detail.html", context)


def material_detail(request: HttpRequest, material_id: int) -> HttpResponse:
    """Display a specific course material."""
    material = get_object_or_404(CourseMaterial, id=material_id)
    return render(request, "courses/material_detail.html", {"material": material})