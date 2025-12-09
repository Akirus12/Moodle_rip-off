"""
Permission checking service for file access control.

Implements the permission logic based on user roles and file share settings.
"""
from typing import Optional, Tuple
from django.utils import timezone
from core.models import User, File, FileShare, PermissionLevel, Role


class PermissionDenied(Exception):
    """Exception raised when permission is denied."""
    pass


def check_permission_level(
    user: Optional[User],
    required_level: str
) -> bool:
    """
    Check if user meets the required permission level.

    Permission hierarchy (least to most restrictive):
    PUBLIC < STUDENT < TEACHER < ADMINISTRATOR

    Args:
        user: User object or None for anonymous users
        required_level: Required PermissionLevel value

    Returns:
        True if user meets the permission level
    """
    # Map permission levels to numeric values for comparison
    level_hierarchy = {
        PermissionLevel.PUBLIC: 0,
        PermissionLevel.STUDENT: 1,
        PermissionLevel.TEACHER: 2,
        PermissionLevel.ADMINISTRATOR: 3,
    }

    required_value = level_hierarchy.get(required_level, 999)

    # Anonymous users only have PUBLIC access
    if user is None or not user.is_authenticated:
        user_value = level_hierarchy[PermissionLevel.PUBLIC]
        return user_value >= required_value

    # Map user role to permission level
    if user.is_administrator():
        user_value = level_hierarchy[PermissionLevel.ADMINISTRATOR]
    elif user.is_teacher():
        user_value = level_hierarchy[PermissionLevel.TEACHER]
    elif user.is_student():
        user_value = level_hierarchy[PermissionLevel.STUDENT]
    else:
        user_value = level_hierarchy[PermissionLevel.PUBLIC]

    return user_value >= required_value


def can_view_file(user: Optional[User], file: File) -> bool:
    """
    Check if user can view file metadata.

    Args:
        user: User object or None
        file: File object

    Returns:
        True if user can view the file
    """
    # Administrators can view all files
    if user and user.is_authenticated and user.is_administrator():
        return True

    # File owner can always view
    if user and user.is_authenticated and file.uploaded_by == user:
        return True

    # Teachers can view files in their courses
    if user and user.is_authenticated and user.is_teacher():
        # Check if file is part of any course the teacher teaches
        course_materials = file.course_materials.filter(
            course__teachers=user,
            is_visible=True
        )
        if course_materials.exists():
            return True

    # Students can view files in courses they're enrolled in
    if user and user.is_authenticated and user.is_student():
        course_materials = file.course_materials.filter(
            course__enrollments__user=user,
            course__enrollments__is_active=True,
            is_visible=True
        )
        if course_materials.exists():
            return True

    return False


def can_download_file(user: Optional[User], file: File) -> bool:
    """
    Check if user can download file content.

    Args:
        user: User object or None
        file: File object

    Returns:
        True if user can download the file
    """
    # Same rules as viewing for now
    return can_view_file(user, file)


def can_edit_file(user: Optional[User], file: File) -> bool:
    """
    Check if user can edit file metadata.

    Args:
        user: User object or None
        file: File object

    Returns:
        True if user can edit the file
    """
    if not user or not user.is_authenticated:
        return False

    # Administrators can edit all files
    if user.is_administrator():
        return True

    # File owner can edit
    if file.uploaded_by == user:
        return True

    # Teachers can edit files in their courses
    if user.is_teacher():
        course_materials = file.course_materials.filter(
            course__teachers=user
        )
        if course_materials.exists():
            return True

    return False


def can_delete_file(user: Optional[User], file: File) -> bool:
    """
    Check if user can delete a file.

    Args:
        user: User object or None
        file: File object

    Returns:
        True if user can delete the file
    """
    if not user or not user.is_authenticated:
        return False

    # Administrators can delete all files
    if user.is_administrator():
        return True

    # File owner can delete
    if file.uploaded_by == user:
        return True

    # Teachers can delete files in their courses
    if user.is_teacher():
        course_materials = file.course_materials.filter(
            course__teachers=user
        )
        if course_materials.exists():
            return True

    return False


def can_create_share(user: Optional[User], file: File) -> bool:
    """
    Check if user can create a share link for a file.

    Args:
        user: User object or None
        file: File object

    Returns:
        True if user can create a share
    """
    # Same rules as editing
    return can_edit_file(user, file)


def can_access_share(
    user: Optional[User],
    share: FileShare,
    action: str = 'view'
) -> Tuple[bool, Optional[str]]:
    """
    Check if user can access a file through a share link.

    Args:
        user: User object or None
        share: FileShare object
        action: Action to perform ('view', 'edit', 'download')

    Returns:
        Tuple of (can_access, denial_reason)
    """
    # Check if share is expired
    if share.is_expired():
        return False, "This share link has expired"

    # Determine required permission level based on action
    if action == 'view':
        required_level = share.view_permission_level
    elif action == 'edit':
        required_level = share.edit_permission_level
    elif action == 'download':
        required_level = share.download_permission_level
    else:
        return False, "Invalid action"

    # Check if user meets the permission level
    if not check_permission_level(user, required_level):
        if user and user.is_authenticated:
            return False, "You don't have sufficient permissions to perform this action"
        else:
            return False, "This action requires authentication"

    return True, None


def require_permission(
    user: Optional[User],
    file: File,
    action: str
) -> None:
    """
    Require that user has permission for an action, raise exception if not.

    Args:
        user: User object or None
        file: File object
        action: Action to check ('view', 'download', 'edit', 'delete')

    Raises:
        PermissionDenied: If user doesn't have permission
    """
    permission_checks = {
        'view': can_view_file,
        'download': can_download_file,
        'edit': can_edit_file,
        'delete': can_delete_file,
    }

    check_func = permission_checks.get(action)
    if not check_func:
        raise PermissionDenied(f"Invalid action: {action}")

    if not check_func(user, file):
        if user and user.is_authenticated:
            raise PermissionDenied(
                f"You don't have permission to {action} this file"
            )
        else:
            raise PermissionDenied(
                f"Authentication required to {action} this file"
            )
