from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.db.models import Count
from django.views.decorators.http import require_http_methods
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
import csv
from django.contrib import messages

from core.models import User, Course, UserCourse, Role

def admin_required(view):
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated or not request.user.is_administrator():
            return HttpResponseForbidden("Admins only.")
        return view(request, *args, **kwargs)
    return wrapper


@login_required
@admin_required
def dashboard(request):
    context = {
        "user_count": User.objects.count(),
        "course_count": Course.objects.count(),
        "enrollment_count": UserCourse.objects.count(),
    }
    return render(request, "administrating/dashboard.html", context)


@login_required
@admin_required
def user_list(request):
    users = User.objects.all().order_by("username")
    return render(request, "administrating/user_list.html", {"users": users})


@login_required
@admin_required
def user_detail(request, pk):
    user = get_object_or_404(User, pk=pk)
    enrollments = user.course_enrollments.select_related("course")
    return render(
        request,
        "administrating/user_detail.html",
        {
            "target_user": user,
            "enrollments": enrollments,
        },
    )


@login_required
@admin_required
@require_http_methods(["GET", "POST"])
def user_edit(request, pk):
    user = get_object_or_404(User, pk=pk)

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        email = request.POST.get("email", "").strip()
        role = request.POST.get("role")

        if not username:
            return HttpResponse("Username is required.", status=400)

        if email:
            try:
                validate_email(email)
            except ValidationError:
                return HttpResponse("Invalid email address.", status=400)

        if role not in Role.values:
            return HttpResponse("Invalid role.", status=400)

        # Prevent demoting the last admin
        if (
            user.is_administrator()
            and role != Role.ADMINISTRATOR
            and User.objects.filter(role=Role.ADMINISTRATOR, is_active=True).count() <= 1
        ):
            return HttpResponse(
                "Cannot remove administrator role from the last admin.",
                status=400,
            )

        # Enforce unique username
        if User.objects.exclude(pk=user.pk).filter(username=username).exists():
            return HttpResponse("Username already exists.", status=400)

        user.username = username
        user.email = email
        user.role = role
        user.save(update_fields=["username", "email", "role"])

        return redirect("administrating:user_detail", pk=user.pk)

    return render(
        request,
        "administrating/user_edit.html",
        {
            "target_user": user,
            "roles": Role.choices,
        },
    )


@login_required
@admin_required
def user_delete(request, pk):
    user = get_object_or_404(User, pk=pk)

    if user.is_administrator():
        admin_count = User.objects.filter(role=Role.ADMINISTRATOR, is_active=True).count()
        if admin_count <= 1:
            return HttpResponse(
                "Cannot delete the last administrator.",
                status=400,
            )

    if request.method == "POST":
        user.delete()
        return redirect("administrating:user_list")

    return render(
        request,
        "administrating/user_confirm_delete.html",
        {"target_user": user},
    )

@login_required
@admin_required
def enrollment_report(request):
    courses = (
        Course.objects
        .annotate(
            student_count=Count("enrollments", distinct=True)
        )
        .order_by("-student_count")
    )
    return render(
        request,
        "administrating/enrollment_report.html",
        {"courses": courses},
    )


@login_required
@admin_required
def enrollment_report_csv(request):
    response = HttpResponse(
        content_type="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="course_enrollments.csv"'
        },
    )

    writer = csv.writer(response)
    writer.writerow(["Course Code", "Course Name", "Enrolled Students"])

    courses = (
        Course.objects
        .annotate(student_count=Count("enrollments"))
        .order_by("code")
    )

    for course in courses:
        writer.writerow([
            course.code,
            course.name,
            course.student_count,
        ])

    return response


@login_required
@admin_required
def grade_statistics(request):
    # You don’t have grades yet → placeholder but DB-driven
    return render(request, "administrating/grade_statistics.html")
