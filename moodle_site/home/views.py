from django.contrib import messages
from django.contrib.auth import login as auth_login
from django.contrib.auth import logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect, render

from .forms import LoginForm, RegisterForm


def auth_panel(request: HttpRequest) -> HttpResponse:
    """Combine login and registration into one sleek panel."""

    if request.user.is_authenticated and request.method != "POST":
        return redirect("home")

    active_tab = request.POST.get("action", "login")

    if request.method == "POST":
        if active_tab == "register":
            login_form = LoginForm(request=request)
            register_form = RegisterForm(request.POST)
            if register_form.is_valid():
                user = register_form.save()
                auth_login(request, user)
                messages.success(request, "Welcome aboard! You're all set.")
                return redirect("home")
        else:
            login_form = LoginForm(request=request, data=request.POST)
            register_form = RegisterForm()
            if login_form.is_valid():
                auth_login(request, login_form.get_user())
                messages.success(request, "Good to see you again!")
                return redirect("home")
    else:
        login_form = LoginForm(request=request)
        register_form = RegisterForm()

    return render(
        request,
        "auth_panel.html",
        {
            "login_form": login_form,
            "register_form": register_form,
            "active_tab": active_tab,
        },
    )


def logout_view(request: HttpRequest) -> HttpResponse:
    """Log the user out and send them back to the login screen."""
    auth_logout(request)
    messages.info(request, "You have been logged out.")
    return redirect("login")


@login_required
def home(request: HttpRequest) -> HttpResponse:
    """Render the landing page."""
    return render(request, "home.html")
