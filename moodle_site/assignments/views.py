from django.contrib.auth.decorators import login_required
from django.shortcuts import render


@login_required
def assignments_page(request):
    return render(request, "assignments.html")