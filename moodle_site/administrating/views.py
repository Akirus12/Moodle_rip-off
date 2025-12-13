from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import user_passes_test
from django.db.models import Count, Avg
from django.http import HttpResponse
from django.shortcuts import render, get_object_or_404, redirect
import csv

from courses.models import Course

User = get_user_model()


def is_admin(user):
    return user.is_staff or user.is_superuser

@user_passes_test(is_admin)
def select_course(request, action):
    courses = Course.objects.all()
    return render(request, "administrating/select_course.html", {
        "courses": courses,
        "action": action,  # "enrollment" or "grades"
    })

@user_passes_test(is_admin)
def admin_dashboard(request):
    users = User.objects.all().order_by('id')
    courses = Course.objects.select_related('instructor')

    return render(request, "administrating/dashboard.html", {
        "users": users,
        "courses": courses,
    })

@user_passes_test(is_admin)
def delete_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    if request.method == "POST":
        user.delete()
    return redirect("administrating/dashboard")

@user_passes_test(is_admin)
def course_report(request, course_id):
    course = get_object_or_404(Course, id=course_id)

    report = course.materials.count()

    return render(request, "administrating/course_report.html", {
        "course": course,
        "materials_count": report,
    })

@user_passes_test(is_admin)
def export_course_report(request):
    courses = Course.objects.annotate(
        materials_count=Count("materials")
    )

    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="course_report.csv"'

    response.write("Course Title,Instructor,Materials Count\n")
    for c in courses:
        response.write(f"{c.title},{c.instructor.email},{c.materials_count}\n")

    return response

@user_passes_test(is_admin)
def export_grades(request, course_id):
    format = request.GET.get("format", "csv")
    course = get_object_or_404(Course, id=course_id)

    # placeholder until Grade model exists
    grades = [
        ("student1@example.com", 85),
        ("student2@example.com", 72),
    ]

    if format == "csv":
        response = HttpResponse(content_type="text/csv")
        response["Content-Disposition"] = "attachment; filename=grades.csv"
        writer = csv.writer(response)
        writer.writerow(["Student", "Grade"])
        for row in grades:
            writer.writerow(row)
        return response

    if format == "txt":
        response = HttpResponse(content_type="text/plain")
        for s, g in grades:
            response.write(f"{s}: {g}\n")
        return response

    return HttpResponse("Unsupported format", status=400)
