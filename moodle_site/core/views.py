"""
Views for file operations and management.

Implements the five main workflows:
1. Upload submission file
2. Generate file share
3. Delete file
4. Post view request (metadata)
5. Retrieve file (blob or metadata)
"""
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import check_password
from django.db import models
from django.http import HttpResponse, JsonResponse, HttpRequest
from django.shortcuts import render, redirect, get_object_or_404
from django.utils import timezone
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_protect

from core.models import File, FileShare
from core.forms import (
    FileUploadForm, FileShareCreateForm, SharePasswordForm,
    FileDeleteForm, FileEditForm
)
from core.services.file_utils import (
    process_uploaded_file, FileValidationError,
    compress_file, format_file_size
)
from core.services.virustotal_service import (
    get_virustotal_service, VirusTotalError
)
from core.services.permissions import (
    can_view_file, can_download_file, can_delete_file,
    can_create_share, can_access_share, require_permission,
    PermissionDenied
)


@login_required
def file_list(request: HttpRequest) -> HttpResponse:
    """List all files accessible to the user."""
    user = request.user

    if user.is_administrator():
        files = File.objects.filter(is_malicious=False).order_by('-date_uploaded')
    elif user.is_teacher():
        # Files uploaded by teacher or in their courses
        files = File.objects.filter(
            is_malicious=False
        ).filter(
            models.Q(uploaded_by=user) |
            models.Q(course_materials__course__teachers=user)
        ).distinct().order_by('-date_uploaded')
    else:
        # Files uploaded by user or in their enrolled courses
        files = File.objects.filter(
            is_malicious=False
        ).filter(
            models.Q(uploaded_by=user) |
            models.Q(course_materials__course__enrollments__user=user,
                    course_materials__course__enrollments__is_active=True,
                    course_materials__is_visible=True)
        ).distinct().order_by('-date_uploaded')

    return render(request, 'core/file_list.html', {
        'files': files,
    })


@login_required
@csrf_protect
@require_http_methods(["GET", "POST"])
def file_upload(request: HttpRequest) -> HttpResponse:
    """
    Upload submission file (Workflow 1).

    Steps:
    1. Save temp in memory; compute size and SHA-256 checksum
    2. If size > 200MB → reject with message
    3. If size > 5MB → compress before sending to VirusTotal
    4. Call VirusTotal. If malicious → reject submission
    5. Store in DB with checksum & size
    6. Confirm submission stored
    """
    if request.method == 'POST':
        form = FileUploadForm(request.POST, request.FILES)

        if form.is_valid():
            try:
                # Process the uploaded file
                uploaded_file = request.FILES['file']
                file_bytes, metadata = process_uploaded_file(uploaded_file)

                # Check for duplicate by checksum
                existing_file = File.objects.filter(
                    checksum_hash=metadata['checksum']
                ).first()

                if existing_file:
                    messages.warning(
                        request,
                        f"A file with the same content already exists: {existing_file.name}"
                    )
                    return redirect('core:file_detail', file_id=existing_file.id)

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
                            f"Failed to compress file for scanning: {str(e)}"
                        )
                        return render(request, 'core/file_upload.html', {'form': form})

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
                            f"File rejected: VirusTotal detected malware "
                            f"({summary['malicious']} engines flagged it as malicious)"
                        )
                        return render(request, 'core/file_upload.html', {'form': form})

                except VirusTotalError as e:
                    messages.error(
                        request,
                        f"VirusTotal scan failed: {str(e)}. Upload rejected for security."
                    )
                    return render(request, 'core/file_upload.html', {'form': form})

                # Create file record
                file_obj = File.objects.create(
                    name=form.cleaned_data['name'],
                    description=form.cleaned_data['description'],
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

                messages.success(
                    request,
                    f"File '{file_obj.name}' uploaded successfully! "
                    f"VirusTotal scan: Clean ({summary['harmless']} engines approved)"
                )
                return redirect('core:file_detail', file_id=file_obj.id)

            except FileValidationError as e:
                messages.error(request, str(e))
            except Exception as e:
                messages.error(request, f"Upload failed: {str(e)}")

    else:
        form = FileUploadForm()

    return render(request, 'core/file_upload.html', {
        'form': form,
    })


@login_required
def file_detail(request: HttpRequest, file_id: int) -> HttpResponse:
    """Display file details and actions."""
    file_obj = get_object_or_404(File, id=file_id)

    # Check view permission
    if not can_view_file(request.user, file_obj):
        messages.error(request, "You don't have permission to view this file")
        return redirect('core:file_list')

    # Get existing shares
    shares = file_obj.shares.all().order_by('-created_at')

    can_download = can_download_file(request.user, file_obj)
    can_delete = can_delete_file(request.user, file_obj)
    can_share = can_create_share(request.user, file_obj)

    return render(request, 'core/file_detail.html', {
        'file': file_obj,
        'shares': shares,
        'can_download': can_download,
        'can_delete': can_delete,
        'can_share': can_share,
        'size_formatted': format_file_size(file_obj.size),
    })


@login_required
@require_http_methods(["POST"])
def file_view_metadata(request: HttpRequest, file_id: int) -> JsonResponse:
    """
    Post view request (Workflow 4).

    Updates view metadata and returns file information as JSON.
    """
    file_obj = get_object_or_404(File, id=file_id)

    try:
        require_permission(request.user, file_obj, 'view')
    except PermissionDenied as e:
        return JsonResponse({'error': str(e)}, status=403)

    # Update view metadata
    file_obj.update_view_metadata(request.user)

    # Return metadata
    metadata = {
        'id': file_obj.id,
        'name': file_obj.name,
        'description': file_obj.description,
        'extension': file_obj.extension,
        'size': file_obj.size,
        'size_formatted': format_file_size(file_obj.size),
        'checksum': file_obj.checksum_hash,
        'date_uploaded': file_obj.date_uploaded.isoformat(),
        'uploaded_by': file_obj.uploaded_by.username if file_obj.uploaded_by else None,
        'view_count': file_obj.view_count,
        'last_viewed_at': file_obj.last_viewed_at.isoformat() if file_obj.last_viewed_at else None,
        'is_malicious': file_obj.is_malicious,
    }

    return JsonResponse(metadata)


@login_required
@require_http_methods(["GET"])
def file_retrieve(request: HttpRequest, file_id: int) -> HttpResponse:
    """
    Retrieve file (Workflow 5).

    Query parameter 'download' determines behavior:
    - download=true: stream bytes with Content-Disposition: attachment
    - otherwise: return metadata JSON
    """
    file_obj = get_object_or_404(File, id=file_id)

    download = request.GET.get('download', '').lower() == 'true'

    if download:
        # Check download permission
        try:
            require_permission(request.user, file_obj, 'download')
        except PermissionDenied as e:
            messages.error(request, str(e))
            return redirect('core:file_detail', file_id=file_id)

        # Stream file content
        response = HttpResponse(bytes(file_obj.bytes), content_type='application/octet-stream')
        filename = file_obj.original_filename or f"{file_obj.name}.{file_obj.extension}"
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        response['Content-Length'] = file_obj.size

        # Update view metadata
        file_obj.update_view_metadata(request.user)

        return response
    else:
        # Return metadata
        try:
            require_permission(request.user, file_obj, 'view')
        except PermissionDenied as e:
            return JsonResponse({'error': str(e)}, status=403)

        metadata = {
            'id': file_obj.id,
            'name': file_obj.name,
            'description': file_obj.description,
            'extension': file_obj.extension,
            'size': file_obj.size,
            'size_formatted': format_file_size(file_obj.size),
            'checksum': file_obj.checksum_hash,
            'date_uploaded': file_obj.date_uploaded.isoformat(),
            'uploaded_by': file_obj.uploaded_by.username if file_obj.uploaded_by else None,
        }

        return JsonResponse(metadata)


@login_required
@csrf_protect
@require_http_methods(["GET", "POST"])
def file_share_create(request: HttpRequest, file_id: int) -> HttpResponse:
    """
    Generate file share (Workflow 2).

    Creates a shareable UUID link with optional password protection.
    """
    file_obj = get_object_or_404(File, id=file_id)

    # Check permission to create share
    if not can_create_share(request.user, file_obj):
        messages.error(request, "You don't have permission to share this file")
        return redirect('core:file_detail', file_id=file_id)

    if request.method == 'POST':
        form = FileShareCreateForm(request.POST)

        if form.is_valid():
            share = form.save(commit=False)
            share.file = file_obj
            share.created_by = request.user
            share.save()

            messages.success(
                request,
                f"Share link created successfully! "
                f"{'Password protected. ' if share.is_password_protected else ''}"
                f"Link: /s/{share.url_uuid}"
            )
            return redirect('core:file_detail', file_id=file_id)
    else:
        form = FileShareCreateForm()

    return render(request, 'core/file_share_create.html', {
        'form': form,
        'file': file_obj,
    })


@csrf_protect
@require_http_methods(["GET", "POST"])
def share_access(request: HttpRequest, uuid: str) -> HttpResponse:
    """
    Access file through share link.

    Handles password verification if needed.
    """
    share = get_object_or_404(FileShare, url_uuid=uuid)

    # Check if share is expired
    if share.is_expired():
        return render(request, 'core/share_expired.html', {'share': share})

    # Handle password protection
    if share.is_password_protected:
        # Check if password is in session
        session_key = f"share_password_{uuid}"
        if request.session.get(session_key) != 'verified':
            if request.method == 'POST':
                form = SharePasswordForm(request.POST)
                if form.is_valid():
                    password = form.cleaned_data['password']
                    # Verify password
                    full_password = password + share.password_salt
                    if check_password(full_password, share.hashed_password):
                        request.session[session_key] = 'verified'
                        share.increment_access_count()
                        return redirect('core:share_access', uuid=uuid)
                    else:
                        messages.error(request, "Incorrect password")
            else:
                form = SharePasswordForm()

            return render(request, 'core/share_password.html', {
                'form': form,
                'share': share,
            })

    # Check permission
    can_view, reason = can_access_share(request.user, share, 'view')
    if not can_view:
        messages.error(request, reason)
        return render(request, 'core/share_denied.html', {'share': share, 'reason': reason})

    can_dl, _ = can_access_share(request.user, share, 'download')

    # Increment access count
    share.increment_access_count()

    return render(request, 'core/share_view.html', {
        'share': share,
        'file': share.file,
        'can_download': can_dl,
        'size_formatted': format_file_size(share.file.size),
    })


@require_http_methods(["GET"])
def share_download(request: HttpRequest, uuid: str) -> HttpResponse:
    """Download file through share link."""
    share = get_object_or_404(FileShare, url_uuid=uuid)

    # Check if expired
    if share.is_expired():
        messages.error(request, "This share link has expired")
        return redirect('core:share_access', uuid=uuid)

    # Check password verification
    if share.is_password_protected:
        session_key = f"share_password_{uuid}"
        if request.session.get(session_key) != 'verified':
            return redirect('core:share_access', uuid=uuid)

    # Check download permission
    can_dl, reason = can_access_share(request.user, share, 'download')
    if not can_dl:
        messages.error(request, reason)
        return redirect('core:share_access', uuid=uuid)

    # Stream file
    file_obj = share.file
    response = HttpResponse(bytes(file_obj.bytes), content_type='application/octet-stream')
    filename = file_obj.original_filename or f"{file_obj.name}.{file_obj.extension}"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    response['Content-Length'] = file_obj.size

    return response


@login_required
@csrf_protect
@require_http_methods(["GET", "POST"])
def file_delete(request: HttpRequest, file_id: int) -> HttpResponse:
    """
    Delete file (Workflow 3).

    Validates permission and existence before deletion.
    """
    file_obj = get_object_or_404(File, id=file_id)

    # Check delete permission
    if not can_delete_file(request.user, file_obj):
        messages.error(
            request,
            "Reject file deletion: You don't have permission to delete this file"
        )
        return redirect('core:file_detail', file_id=file_id)

    if request.method == 'POST':
        form = FileDeleteForm(request.POST)
        if form.is_valid():
            file_name = file_obj.name
            file_obj.delete()
            messages.success(request, f"File '{file_name}' has been deleted successfully")
            return redirect('core:file_list')
    else:
        form = FileDeleteForm()

    return render(request, 'core/file_delete.html', {
        'form': form,
        'file': file_obj,
    })
