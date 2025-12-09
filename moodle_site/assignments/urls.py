from django.urls import path
from . import views

app_name = 'assignments'

urlpatterns = [
    path("", views.assignments_page, name="assignments"),
    path('assignments/<int:assignment_id>/', views.assignment_detail, name='assignment_detail'),
    path('assignments/<int:assignment_id>/edit/', views.edit_assignment, name='edit_assignment'),
    path('assignments/<int:assignment_id>/submit/', views.submit_assignment, name='submit_assignment'),
    path('assignments/<int:assignment_id>/submissions/', views.view_submissions, name='view_submissions'),
    path('assignments/<int:assignment_id>/submissions/<int:submission_id>/grade/', views.grade_submission, name='grade_submission'),
    path('assignments/<int:assignment_id>/groups/', views.manage_groups, name='manage_groups'),
    path('assignments/<int:assignment_id>/groups/create/', views.create_group, name='create_group'),
    path('assignments/<int:assignment_id>/groups/<int:group_id>/questionnaire/', views.submit_questionnaire, name='submit_questionnaire'),
    path('assignments/<int:assignment_id>/groups/<int:group_id>/questionnaires/', views.view_questionnaires, name='view_questionnaires'),
    path('assignments/<int:assignment_id>/toggle-close/', views.toggle_assignment_close, name='toggle_assignment_close'),
    path('assignments/<int:assignment_id>/delete/', views.delete_assignment, name='delete_assignment'),
    path('create-assignment/<int:course_id>/', views.create_assignment, name='create_assignment'),
]
