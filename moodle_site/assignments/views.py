from django.contrib.auth.decorators import login_required
from django.shortcuts import render, get_object_or_404, redirect
from django.contrib import messages
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect
from courses.models import Course
from core.models import Assignment, AssignmentSubmission, File, AssignmentGroup, GroupQuestionnaire
from core.services.file_utils import (
    process_uploaded_file, FileValidationError,
    compress_file
)
from core.services.virustotal_service import (
    get_virustotal_service, VirusTotalError
)
from .forms import AssignmentForm, SubmissionForm, GradeSubmissionForm, AssignmentGroupForm, GroupQuestionnaireForm


@login_required
def assignments_page(request):
    return render(request, "assignments/assignments.html")

@login_required
def assignment_detail(request, assignment_id):
    assignment = get_object_or_404(Assignment, id=assignment_id)
    course = assignment.course

    # Teachers who are not the assigned instructor cannot access this assignment
    if request.user.is_authenticated and hasattr(request.user, "is_teacher"):
        if request.user.is_teacher() and request.user != course.instructor:
            # Allow admins / superusers
            if not getattr(request.user, "is_superuser", False) and not request.user.is_administrator():
                messages.error(request, "You are not the instructor for this course.")
                return redirect('courses:courses_list')
    
    # Check if user is the instructor
    is_instructor = request.user == course.instructor
    
    # Get user's submission if they're a student
    user_submission = None
    user_group = None
    group_submission = None
    questionnaire = None
    
    if not is_instructor:
        if assignment.is_group_assignment:
            # Get user's group
            user_group = AssignmentGroup.objects.filter(
                assignment=assignment,
                students=request.user
            ).first()
            
            if user_group:
                # Get group submission (any submission from the group)
                group_submission = AssignmentSubmission.objects.filter(
                    assignment=assignment,
                    group=user_group
                ).first()
                
                # Get user's individual submission record (for grading)
                user_submission = AssignmentSubmission.objects.filter(
                    assignment=assignment,
                    student=request.user,
                    group=user_group
                ).first()
                
                # Check if questionnaire is submitted
                questionnaire = GroupQuestionnaire.objects.filter(
                    group=user_group,
                    student=request.user
                ).first()
        else:
            # Individual assignment
            try:
                user_submission = AssignmentSubmission.objects.get(
                    assignment=assignment,
                    student=request.user
                )
            except AssignmentSubmission.DoesNotExist:
                pass
    
    # Get groups for instructor view
    groups = None
    if is_instructor and assignment.is_group_assignment:
        groups = AssignmentGroup.objects.filter(assignment=assignment).prefetch_related('students')
    
    return render(request, 'assignments/assignment_detail.html', {
        'assignment': assignment,
        'course': course,
        'is_instructor': is_instructor,
        'user_submission': user_submission,
        'user_group': user_group,
        'group_submission': group_submission,
        'questionnaire': questionnaire,
        'groups': groups
    })

@login_required
def edit_assignment(request, assignment_id):
    assignment = get_object_or_404(Assignment, id=assignment_id)
    course = assignment.course
    
    if request.method == 'POST':
        form = AssignmentForm(request.POST, instance=assignment)
        if form.is_valid():
            form.save()
            messages.success(request, f'Assignment "{assignment.title}" has been updated successfully!')
            return redirect('courses:course_detail', course_id=course.id)
    else:
        form = AssignmentForm(instance=assignment)
    
    return render(request, 'assignments/create_assignment.html', {
        'course': course,
        'form': form,
        'assignment': assignment,
        'is_edit': True
    })

@login_required
def create_assignment(request, course_id):
    course = get_object_or_404(Course, id=course_id, is_active=True)

    # Only the course instructor (or admin/superuser) can create an assignment
    if request.user != course.instructor:
        if not getattr(request.user, "is_superuser", False) and not request.user.is_administrator():
            messages.error(request, "You are not the instructor for this course.")
            return redirect('courses:courses_list')
    
    # Get students - we'll need to get them from User model with role='student'
    # For now, get all students (you may want to filter by course enrollment if that's implemented)
    from django.contrib.auth import get_user_model
    User = get_user_model()
    course_students = User.objects.filter(role='student').order_by('username')
    
    if request.method == 'POST':
        form = AssignmentForm(request.POST)
        if form.is_valid():
            assignment = form.save(commit=False)
            assignment.course = course
            assignment.save()
            
            # Handle group creation if this is a group assignment
            if assignment.is_group_assignment:
                group_names = request.POST.getlist('group_names[]')
                groups_created = 0
                
                for group_index, group_name in enumerate(group_names):
                    if group_name and group_name.strip():  # Only create groups with names
                        # Get students for this group
                        # Django converts [] to empty string in POST keys, so we need to check the actual key format
                        student_key = f'group_students_{group_index}[]'
                        student_ids = request.POST.getlist(student_key)
                        
                        if student_ids:
                            group = AssignmentGroup.objects.create(
                                assignment=assignment,
                                name=group_name.strip(),
                                created_by=request.user
                            )
                            # Add students to group
                            students = User.objects.filter(id__in=student_ids, role='student')
                            group.students.set(students)
                            groups_created += 1
                
                if groups_created > 0:
                    messages.success(request, f'Assignment "{assignment.title}" and {groups_created} group(s) created successfully!')
                else:
                    messages.warning(request, f'Assignment "{assignment.title}" created. Remember to create groups!')
            else:
                messages.success(request, f'Assignment "{assignment.title}" has been created successfully!')
            
            return redirect('courses:course_detail', course_id=course.id)
    else:
        form = AssignmentForm()
    
    return render(request, 'assignments/create_assignment.html', {
        'course': course,
        'form': form,
        'course_students': course_students
    })


@login_required
@csrf_protect
@require_http_methods(["GET", "POST"])
def submit_assignment(request, assignment_id):
    """View for students to submit assignment files."""
    assignment = get_object_or_404(Assignment, id=assignment_id)
    course = assignment.course
    
    # Check if user is the instructor (instructors can't submit)
    if request.user == course.instructor:
        messages.error(request, "Instructors cannot submit assignments.")
        return redirect('assignments:assignment_detail', assignment_id=assignment_id)
    
    # Check if assignment is closed
    if assignment.is_closed:
        messages.error(request, "This assignment is closed. Submissions are no longer accepted.")
        return redirect('assignments:assignment_detail', assignment_id=assignment_id)
    
    # Check if assignment is still accepting submissions
    if assignment.status not in ['active', 'due']:
        messages.error(request, "This assignment is not accepting submissions.")
        return redirect('assignments:assignment_detail', assignment_id=assignment_id)
    
    # Handle group assignments
    user_group = None
    if assignment.is_group_assignment:
        user_group = AssignmentGroup.objects.filter(
            assignment=assignment,
            students=request.user
        ).first()
        if not user_group:
            messages.error(request, "You are not assigned to any group for this assignment.")
            return redirect('assignments:assignment_detail', assignment_id=assignment_id)
        
        # For group assignments, check if group has submitted
        existing_submission = AssignmentSubmission.objects.filter(
            assignment=assignment,
            group=user_group
        ).first()
    else:
        # For individual assignments
        existing_submission = AssignmentSubmission.objects.filter(
            assignment=assignment,
            student=request.user
        ).first()
    
    if request.method == 'POST':
        files = request.FILES.getlist('files')
        
        if not files:
            messages.error(request, "Please select at least one file to submit.")
            form = SubmissionForm()
        else:
            try:
                uploaded_files = []
                
                # Process each uploaded file
                for uploaded_file in files:
                    # Validate file size
                    if uploaded_file.size > 200 * 1024 * 1024:  # 200 MB
                        messages.error(
                            request,
                            f"File '{uploaded_file.name}' exceeds 200 MB limit."
                        )
                        form = SubmissionForm()
                        return render(request, 'assignments/submit_assignment.html', {
                            'assignment': assignment,
                            'course': course,
                            'form': form,
                            'existing_submission': existing_submission
                        })
                    
                    # Process the uploaded file
                    file_bytes, metadata = process_uploaded_file(uploaded_file)
                    
                    # Prepare for VirusTotal scan
                    scan_bytes = file_bytes
                    was_compressed = False
                    
                    if metadata['needs_compression']:
                        try:
                            scan_bytes = compress_file(
                                file_bytes,
                                metadata['original_filename']
                            )
                            was_compressed = True
                        except Exception as e:
                            messages.error(
                                request,
                                f"Failed to compress file '{uploaded_file.name}' for scanning: {str(e)}"
                            )
                            form = SubmissionForm()
                            return render(request, 'assignments/submit_assignment.html', {
                                'assignment': assignment,
                                'course': course,
                                'form': form,
                                'existing_submission': existing_submission
                            })
                    
                    # Scan with VirusTotal
                    try:
                        vt_service = get_virustotal_service()
                        is_malicious, summary, report_id = vt_service.scan_file(
                            scan_bytes,
                            metadata['safe_filename']
                        )
                        
                        if is_malicious:
                            messages.error(
                                request,
                                f"File '{uploaded_file.name}' rejected: VirusTotal detected malware "
                                f"({summary['malicious']} engines flagged it as malicious)"
                            )
                            form = SubmissionForm()
                            return render(request, 'assignments/submit_assignment.html', {
                                'assignment': assignment,
                                'course': course,
                                'form': form,
                                'existing_submission': existing_submission
                            })
                    
                    except VirusTotalError as e:
                        messages.error(
                            request,
                            f"VirusTotal scan failed for '{uploaded_file.name}': {str(e)}. Upload rejected for security."
                        )
                        form = SubmissionForm()
                        return render(request, 'assignments/submit_assignment.html', {
                            'assignment': assignment,
                            'course': course,
                            'form': form,
                            'existing_submission': existing_submission
                        })
                    
                    # Create file record
                    file_obj = File.objects.create(
                        name=metadata['safe_filename'],
                        description=f"Submission file for assignment: {assignment.title}",
                        bytes=file_bytes,
                        extension=metadata['extension'],
                        checksum_hash=metadata['checksum'],
                        size=metadata['size'],
                        original_filename=metadata['original_filename'],
                        uploaded_by=request.user,
                        virustotal_report_id=report_id,
                        virustotal_scan_date=timezone.now(),
                        is_malicious=is_malicious,
                        virustotal_summary=summary,
                        was_compressed=was_compressed,
                        original_size=metadata['size'] if was_compressed else None,
                    )
                    uploaded_files.append(file_obj)
                
                # Create or update submission
                if existing_submission:
                    # Update existing submission - add new files
                    for file_obj in uploaded_files:
                        existing_submission.files.add(file_obj)
                    existing_submission.updated_at = timezone.now()
                    existing_submission.submitted_by = request.user
                    existing_submission.save()
                    messages.success(
                        request,
                        f"Submission updated successfully! {len(uploaded_files)} file(s) added."
                    )
                else:
                    # Create new submission
                    if assignment.is_group_assignment and user_group:
                        # Group assignment - create submission for the group
                        submission = AssignmentSubmission.objects.create(
                            assignment=assignment,
                            student=request.user,  # Primary student record
                            group=user_group,
                            submitted_by=request.user
                        )
                        # Create individual submission records for other group members (for grading)
                        for student in user_group.students.exclude(id=request.user.id):
                            AssignmentSubmission.objects.create(
                                assignment=assignment,
                                student=student,
                                group=user_group,
                                submitted_by=request.user
                            )
                    else:
                        # Individual assignment
                        submission = AssignmentSubmission.objects.create(
                            assignment=assignment,
                            student=request.user,
                            submitted_by=request.user
                        )
                    
                    # Add files to the primary submission
                    for file_obj in uploaded_files:
                        submission.files.add(file_obj)
                    
                    # For group assignments, also add files to other group members' submissions
                    if assignment.is_group_assignment and user_group:
                        for student in user_group.students.exclude(id=request.user.id):
                            student_submission = AssignmentSubmission.objects.get(
                                assignment=assignment,
                                student=student,
                                group=user_group
                            )
                            for file_obj in uploaded_files:
                                student_submission.files.add(file_obj)
                    
                    messages.success(
                        request,
                        f"Assignment submitted successfully! {len(uploaded_files)} file(s) uploaded."
                    )
                
                return redirect('assignments:assignment_detail', assignment_id=assignment_id)
                
            except FileValidationError as e:
                messages.error(request, str(e))
            except Exception as e:
                messages.error(request, f"Upload failed: {str(e)}")
        
        form = SubmissionForm()
    else:
        form = SubmissionForm()
    
    return render(request, 'assignments/submit_assignment.html', {
        'assignment': assignment,
        'course': course,
        'form': form,
        'existing_submission': existing_submission,
        'user_group': user_group
    })


@login_required
def view_submissions(request, assignment_id):
    """View for instructors to see all submissions for an assignment."""
    assignment = get_object_or_404(Assignment, id=assignment_id)
    course = assignment.course
    
    # Check if user is the instructor
    if request.user != course.instructor:
        messages.error(request, "Only the course instructor can view submissions.")
        return redirect('assignments:assignment_detail', assignment_id=assignment_id)
    
    submissions = AssignmentSubmission.objects.filter(
        assignment=assignment
    ).select_related('student', 'graded_by').prefetch_related('files').order_by('-submitted_at')
    
    graded_count = sum(1 for s in submissions if s.is_graded())
    
    return render(request, 'assignments/submissions_list.html', {
        'assignment': assignment,
        'course': course,
        'submissions': submissions,
        'graded_count': graded_count
    })


@login_required
@csrf_protect
@require_http_methods(["GET", "POST"])
def grade_submission(request, assignment_id, submission_id):
    """View for instructors to grade a submission."""
    assignment = get_object_or_404(Assignment, id=assignment_id)
    course = assignment.course
    submission = get_object_or_404(
        AssignmentSubmission,
        id=submission_id,
        assignment=assignment
    )
    
    # Check if user is the instructor
    if request.user != course.instructor:
        messages.error(request, "Only the course instructor can grade submissions.")
        return redirect('assignments:assignment_detail', assignment_id=assignment_id)
    
    if request.method == 'POST':
        form = GradeSubmissionForm(request.POST, instance=submission, assignment=assignment)
        if form.is_valid():
            submission = form.save(commit=False)
            submission.graded_by = request.user
            submission.graded_at = timezone.now()
            submission.save()
            messages.success(request, f"Submission graded successfully! Score: {submission.score}/{assignment.max_score}")
            return redirect('assignments:view_submissions', assignment_id=assignment_id)
    else:
        form = GradeSubmissionForm(instance=submission, assignment=assignment)
    
    return render(request, 'assignments/grade_submission.html', {
        'assignment': assignment,
        'course': course,
        'submission': submission,
        'form': form
    })


@login_required
def manage_groups(request, assignment_id):
    """View for teachers to create and manage groups for a group assignment."""
    assignment = get_object_or_404(Assignment, id=assignment_id)
    course = assignment.course
    
    # Check if user is the instructor
    if request.user != course.instructor:
        messages.error(request, "Only the course instructor can manage groups.")
        return redirect('assignments:assignment_detail', assignment_id=assignment_id)
    
    # Check if this is a group assignment
    if not assignment.is_group_assignment:
        messages.error(request, "This is not a group assignment.")
        return redirect('assignments:assignment_detail', assignment_id=assignment_id)
    
    groups = AssignmentGroup.objects.filter(assignment=assignment).prefetch_related('students')
    
    return render(request, 'assignments/manage_groups.html', {
        'assignment': assignment,
        'course': course,
        'groups': groups
    })


@login_required
@csrf_protect
@require_http_methods(["GET", "POST"])
def create_group(request, assignment_id):
    """View for teachers to create a new group."""
    assignment = get_object_or_404(Assignment, id=assignment_id)
    course = assignment.course
    
    # Check if user is the instructor
    if request.user != course.instructor:
        messages.error(request, "Only the course instructor can create groups.")
        return redirect('assignments:assignment_detail', assignment_id=assignment_id)
    
    # Check if this is a group assignment
    if not assignment.is_group_assignment:
        messages.error(request, "This is not a group assignment.")
        return redirect('assignments:assignment_detail', assignment_id=assignment_id)
    
    if request.method == 'POST':
        form = AssignmentGroupForm(request.POST, assignment=assignment, course=course)
        if form.is_valid():
            group = form.save(commit=False)
            group.assignment = assignment
            group.created_by = request.user
            group.save()
            form.save_m2m()  # Save the many-to-many students relationship
            messages.success(request, f"Group '{group.name}' created successfully!")
            return redirect('assignments:manage_groups', assignment_id=assignment_id)
    else:
        form = AssignmentGroupForm(assignment=assignment, course=course)
    
    return render(request, 'assignments/create_group.html', {
        'assignment': assignment,
        'course': course,
        'form': form
    })


@login_required
def submit_questionnaire(request, assignment_id, group_id):
    """View for students to submit their group assignment questionnaire."""
    assignment = get_object_or_404(Assignment, id=assignment_id)
    group = get_object_or_404(AssignmentGroup, id=group_id, assignment=assignment)
    
    # Check if user is in the group
    if request.user not in group.students.all():
        messages.error(request, "You are not a member of this group.")
        return redirect('assignments:assignment_detail', assignment_id=assignment_id)
    
    # Check if already submitted
    existing_questionnaire = GroupQuestionnaire.objects.filter(
        group=group,
        student=request.user
    ).first()
    
    if request.method == 'POST':
        if existing_questionnaire:
            form = GroupQuestionnaireForm(request.POST, instance=existing_questionnaire)
        else:
            form = GroupQuestionnaireForm(request.POST)
        
        if form.is_valid():
            questionnaire = form.save(commit=False)
            questionnaire.group = group
            questionnaire.student = request.user
            questionnaire.save()
            messages.success(request, "Questionnaire submitted successfully!")
            return redirect('assignments:assignment_detail', assignment_id=assignment_id)
    else:
        if existing_questionnaire:
            form = GroupQuestionnaireForm(instance=existing_questionnaire)
        else:
            form = GroupQuestionnaireForm()
    
    return render(request, 'assignments/submit_questionnaire.html', {
        'assignment': assignment,
        'group': group,
        'form': form,
        'existing_questionnaire': existing_questionnaire
    })


@login_required
def view_questionnaires(request, assignment_id, group_id):
    """View for teachers to view all questionnaires from a group."""
    assignment = get_object_or_404(Assignment, id=assignment_id)
    course = assignment.course
    group = get_object_or_404(AssignmentGroup, id=group_id, assignment=assignment)
    
    # Check if user is the instructor
    if request.user != course.instructor:
        messages.error(request, "Only the course instructor can view questionnaires.")
        return redirect('assignments:assignment_detail', assignment_id=assignment_id)
    
    questionnaires = GroupQuestionnaire.objects.filter(
        group=group
    ).select_related('student').order_by('student__username')
    
    return render(request, 'assignments/view_questionnaires.html', {
        'assignment': assignment,
        'course': course,
        'group': group,
        'questionnaires': questionnaires
    })


@login_required
@require_http_methods(["POST"])
def toggle_assignment_close(request, assignment_id):
    """View for teachers to close/open an assignment."""
    assignment = get_object_or_404(Assignment, id=assignment_id)
    course = assignment.course
    
    # Check if user is the instructor
    if request.user != course.instructor:
        messages.error(request, "Only the course instructor can close/open assignments.")
        return redirect('assignments:assignment_detail', assignment_id=assignment_id)
    
    # Toggle closed status
    assignment.is_closed = not assignment.is_closed
    assignment.save()
    
    if assignment.is_closed:
        messages.success(request, f'Assignment "{assignment.title}" has been closed. Students can no longer submit.')
    else:
        messages.success(request, f'Assignment "{assignment.title}" has been reopened. Students can now submit.')
    
    return redirect('assignments:assignment_detail', assignment_id=assignment_id)


@login_required
@require_http_methods(["POST"])
def delete_assignment(request, assignment_id):
    """Allow the course instructor (or admin) to delete an assignment."""
    assignment = get_object_or_404(Assignment, id=assignment_id)
    course = assignment.course

    # Permission check
    if request.user != course.instructor:
        if not getattr(request.user, "is_superuser", False) and not request.user.is_administrator():
            messages.error(request, "You are not the instructor for this course.")
            return redirect('courses:courses_list')

    title = assignment.title
    assignment.delete()
    messages.success(request, f'Assignment "{title}" has been deleted.')
    return redirect('courses:course_detail', course_id=course.id)
