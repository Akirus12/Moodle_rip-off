from django.contrib.auth.decorators import login_required
from django.shortcuts import render

#@login_required
def messages_page(request):
    # show broadcast button to staff/teachers/admin later; for now pass a flag
    is_teacher_or_admin = True #request.user.is_staff or request.user.is_superuser
    return render(request, "messages.html", {
        "is_teacher_or_admin": is_teacher_or_admin,
    })
