from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import user_passes_test
from django.db.models import Count, Avg
from django.http import HttpResponse
from django.shortcuts import render, get_object_or_404, redirect

from courses.models import Course

User = get_user_model()


def is_admin(user):
    return user.is_staff or user.is_superuser


@user_passes_test(is_admin)
def admin_dashboard(request):
    users = User.objects.all().order_by('id')
    courses = Course.objects.select_related('instructor')

    return render(request, "admin_dashboard.html", {
        "users": users,
        "courses": courses,
    })


@user_passes_test(is_admin)
def delete_user(request, user_id):
    user = get_object_or_404(User, id=user_id)
    if request.method == "POST":
        user.delete()
    return redirect("admin_dashboard")


@user_passes_test(is_admin)
def course_report(request):
    report = (
        Course.objects
        .values("title")
        .annotate(
            materials_count=Count("materials"),
        )
        .order_by("title")
    )

    return render(request, "course_report.html", {
        "report": report
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
