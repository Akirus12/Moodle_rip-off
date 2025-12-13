from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseForbidden
from django.shortcuts import get_object_or_404, redirect, render
from django.db.models import Prefetch, Count
from django.views.decorators.http import require_http_methods
from django.core.validators import validate_email
from django.core.exceptions import ValidationError
from django.contrib import messages
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas
from core.models import Course, UserCourse, Assignment
from openpyxl import Workbook
from statistics import mean
import csv, random, reportlab

from core.models import User, Course, UserCourse, Role, Assignment


def export_grades_pdf(courses, mode):
    response = HttpResponse(content_type="application/pdf")
    response["Content-Disposition"] = 'attachment; filename="grade_statistics.pdf"'

    c = canvas.Canvas(response, pagesize=A4)
    width, height = A4

    y = height - 2 * cm

    # Title
    c.setFont("Helvetica-Bold", 16)
    c.drawString(2 * cm, y, "Grade Statistics Report")
    y -= 1.2 * cm

    c.setFont("Helvetica", 10)
    c.drawString(2 * cm, y, f"Grade generation mode: {mode}")
    y -= 1 * cm

    for course in courses:
        if course.student_count == 0:
            continue

        # Page break safety
        if y < 4 * cm:
            c.showPage()
            c.setFont("Helvetica", 10)
            y = height - 2 * cm

        # Course header
        c.setFont("Helvetica-Bold", 12)
        c.drawString(
            2 * cm,
            y,
            f"{course.code} – {course.name}",
        )
        y -= 0.6 * cm

        c.setFont("Helvetica", 10)
        c.drawString(
            2 * cm,
            y,
            f"Enrolled students: {course.student_count}",
        )
        y -= 0.5 * cm

        # Generate statistics once per course
        stats = generate_mock_statistics(
            course.assignments.all(),
            course.student_count,
            mode,
        )

        for s in stats:
            if y < 3 * cm:
                c.showPage()
                c.setFont("Helvetica", 10)
                y = height - 2 * cm

            c.drawString(
                2.5 * cm,
                y,
                f"Assignment: {s['assignment'].title}",
            )
            y -= 0.4 * cm

            c.drawString(
                3 * cm,
                y,
                f"Avg: {s['avg']} | "
                f"Min: {s['min']} | "
                f"Max: {s['max']} | "
                f"Max score: {s['assignment'].max_score}",
            )
            y -= 0.5 * cm

        y -= 0.6 * cm

    c.showPage()
    c.save()

    return response

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


@login_required
@admin_required
def grade_statistics_pdf(request):
    response = HttpResponse(content_type="application/pdf")
    response["Content-Disposition"] = 'attachment; filename="grade_statistics.pdf"'

    c = canvas.Canvas(response, pagesize=A4)
    width, height = A4

    y = height - 2 * cm
    c.setFont("Helvetica-Bold", 16)
    c.drawString(2 * cm, y, "Grade Statistics Report")
    y -= 1.5 * cm

    c.setFont("Helvetica", 10)

    courses = (
        Course.objects
        .prefetch_related(
            "assignments",
            Prefetch(
                "enrollments",
                queryset=UserCourse.objects.filter(is_active=True),
            ),
        )
        .order_by("code")
    )

    for course in courses:
        enrollments = course.enrollments.all()
        student_count = enrollments.count()

        if student_count == 0:
            continue

        c.setFont("Helvetica-Bold", 12)
        c.drawString(2 * cm, y, f"{course.code} – {course.name}")
        y -= 0.7 * cm

        c.setFont("Helvetica", 10)
        c.drawString(2 * cm, y, f"Enrolled students: {student_count}")
        y -= 0.5 * cm

        for assignment in course.assignments.all():
            # Generate mock grades
            grades = [
                round(random.uniform(0, float(assignment.max_score)), 2)
                for _ in range(student_count)
            ]

            avg_grade = round(mean(grades), 2)
            min_grade = round(min(grades), 2)
            max_grade = round(max(grades), 2)

            c.drawString(
                2.5 * cm,
                y,
                f"Assignment: {assignment.title}",
            )
            y -= 0.4 * cm

            c.drawString(
                3 * cm,
                y,
                f"Avg: {avg_grade} / {assignment.max_score} | "
                f"Min: {min_grade} | Max: {max_grade}",
            )
            y -= 0.5 * cm

            if y < 3 * cm:
                c.showPage()
                c.setFont("Helvetica", 10)
                y = height - 2 * cm

        y -= 0.7 * cm
        if y < 3 * cm:
            c.showPage()
            c.setFont("Helvetica", 10)
            y = height - 2 * cm

    c.showPage()
    c.save()

    return response


def generate_mock_statistics(assignments, student_count, mode):
    stats = []

    for assignment in assignments:
        max_score = float(assignment.max_score)

        if mode == "passing_bias":
            grades = [
                round(random.triangular(max_score * 0.5, max_score, max_score * 0.75), 2)
                for _ in range(student_count)
            ]
        else:
            grades = [
                round(random.uniform(0, max_score), 2)
                for _ in range(student_count)
            ]

        stats.append({
            "assignment": assignment,
            "avg": round(mean(grades), 2),
            "min": round(min(grades), 2),
            "max": round(max(grades), 2),
        })

    return stats


@login_required
@admin_required
def grade_export_options(request):
    return render(request, "administrating/grade_export_options.html")


@login_required
@admin_required
def grade_statistics_export(request):
    export_format = request.GET.get("format", "pdf")
    mode = request.GET.get("mode", "uniform")

    courses = (
        Course.objects
        .annotate(student_count=Count("enrollments"))
        .prefetch_related("assignments")
        .order_by("code")
    )

    if export_format == "csv":
        return export_grades_csv(courses, mode)

    if export_format == "xlsx":
        return export_grades_xlsx(courses, mode)

    return export_grades_pdf(courses, mode)


def export_grades_csv(courses, mode):
    response = HttpResponse(
        content_type="text/csv",
        headers={
            "Content-Disposition": 'attachment; filename="grade_statistics.csv"'
        },
    )

    writer = csv.writer(response)
    writer.writerow([
        "Course Code",
        "Assignment",
        "Average",
        "Minimum",
        "Maximum",
        "Max Score",
    ])

    for course in courses:
        if course.student_count == 0:
            continue

        stats = generate_mock_statistics(
            course.assignments.all(),
            course.student_count,
            mode,
        )

        for s in stats:
            writer.writerow([
                course.code,
                s["assignment"].title,
                s["avg"],
                s["min"],
                s["max"],
                s["assignment"].max_score,
            ])

    return response


def export_grades_xlsx(courses, mode):
    wb = Workbook()
    ws = wb.active
    ws.title = "Grade statistics"

    ws.append([
        "Course Code",
        "Assignment",
        "Average",
        "Minimum",
        "Maximum",
        "Max Score",
    ])

    for course in courses:
        if course.student_count == 0:
            continue

        stats = generate_mock_statistics(
            course.assignments.all(),
            course.student_count,
            mode,
        )

        for s in stats:
            ws.append([
                course.code,
                s["assignment"].title,
                s["avg"],
                s["min"],
                s["max"],
                float(s["assignment"].max_score),
            ])

    response = HttpResponse(
        content_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )
    response["Content-Disposition"] = 'attachment; filename="grade_statistics.xlsx"'
    wb.save(response)
    return response


