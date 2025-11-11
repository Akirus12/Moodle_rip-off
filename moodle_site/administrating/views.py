from django.http import HttpRequest, HttpResponse
from django.shortcuts import render


def administrating_page(request: HttpRequest) -> HttpResponse:
    """Render the landing page."""
    return render(request, "administrating.html")
