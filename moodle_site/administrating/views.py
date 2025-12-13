from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.db.models import Count

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
def user_delete(request, pk):
    user = get_object_or_404(User, pk=pk)
    if request.method == "POST":
        user.delete()
        return redirect("administrating:user_list")
    return render(request, "administrating/user_confirm_delete.html", {"target_user": user})


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
def grade_statistics(request):
    # You don’t have grades yet → placeholder but DB-driven
    return render(request, "administrating/grade_statistics.html")
