"""Admin configuration for core models."""
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from .models import (
    User, Course, UserCourse, CoursePrerequisite,
    CourseMaterial, Assignment, File, FileShare,
    Message, UserMessage
)


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """Custom user admin with role field."""
    list_display = ['username', 'email', 'role', 'is_staff', 'is_active']
    list_filter = ['role', 'is_staff', 'is_active']
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Role Information', {'fields': ('role',)}),
    )
    add_fieldsets = BaseUserAdmin.add_fieldsets + (
        ('Role Information', {'fields': ('role',)}),
    )


@admin.register(Course)
class CourseAdmin(admin.ModelAdmin):
    """Course admin configuration."""
    list_display = ['code', 'name', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['code', 'name', 'description']
    filter_horizontal = ['teachers']
    date_hierarchy = 'created_at'


@admin.register(UserCourse)
class UserCourseAdmin(admin.ModelAdmin):
    """Course enrollment admin."""
    list_display = ['user', 'course', 'enrolled_at', 'is_active']
    list_filter = ['is_active', 'enrolled_at']
    search_fields = ['user__username', 'course__code', 'course__name']
    date_hierarchy = 'enrolled_at'


@admin.register(CoursePrerequisite)
class CoursePrerequisiteAdmin(admin.ModelAdmin):
    """Course prerequisite admin."""
    list_display = ['course', 'prerequisite']
    search_fields = ['course__code', 'prerequisite__code']


@admin.register(File)
class FileAdmin(admin.ModelAdmin):
    """File admin configuration."""
    list_display = ['name', 'extension', 'size', 'uploaded_by', 'is_malicious', 'date_uploaded']
    list_filter = ['is_malicious', 'extension', 'date_uploaded']
    search_fields = ['name', 'original_filename', 'checksum_hash']
    readonly_fields = ['checksum_hash', 'size', 'date_uploaded', 'virustotal_report_id',
                      'virustotal_scan_date', 'virustotal_summary', 'view_count']
    date_hierarchy = 'date_uploaded'

    fieldsets = (
        ('Basic Information', {
            'fields': ('name', 'description', 'original_filename', 'extension')
        }),
        ('File Data', {
            'fields': ('bytes', 'size', 'checksum_hash', 'uploaded_by', 'date_uploaded')
        }),
        ('VirusTotal Scan', {
            'fields': ('is_malicious', 'virustotal_report_id', 'virustotal_scan_date',
                      'virustotal_summary', 'was_compressed', 'original_size')
        }),
        ('View Tracking', {
            'fields': ('view_count', 'last_viewed_at', 'last_viewed_by')
        }),
    )


@admin.register(CourseMaterial)
class CourseMaterialAdmin(admin.ModelAdmin):
    """Course material admin."""
    list_display = ['title', 'course', 'is_visible', 'order', 'uploaded_at']
    list_filter = ['is_visible', 'course', 'uploaded_at']
    search_fields = ['title', 'description', 'course__code']
    date_hierarchy = 'uploaded_at'


@admin.register(Assignment)
class AssignmentAdmin(admin.ModelAdmin):
    """Assignment admin."""
    list_display = ['title', 'course', 'status', 'due_date', 'max_score']
    list_filter = ['status', 'course', 'due_date']
    search_fields = ['title', 'description', 'course__code']
    date_hierarchy = 'due_date'


@admin.register(FileShare)
class FileShareAdmin(admin.ModelAdmin):
    """File share admin."""
    list_display = ['file', 'url_uuid', 'created_by', 'is_password_protected',
                   'expiration_date', 'access_count']
    list_filter = ['is_password_protected', 'expiration_date', 'created_at']
    search_fields = ['file__name', 'url_uuid']
    readonly_fields = ['url_uuid', 'created_at', 'access_count']
    date_hierarchy = 'created_at'

    fieldsets = (
        ('File & Creator', {
            'fields': ('file', 'created_by', 'created_at')
        }),
        ('Sharing Link', {
            'fields': ('url_uuid', 'expiration_date', 'access_count')
        }),
        ('Permission Levels', {
            'fields': ('view_permission_level', 'edit_permission_level',
                      'download_permission_level')
        }),
        ('Password Protection', {
            'fields': ('is_password_protected', 'hashed_password', 'password_salt')
        }),
    )


@admin.register(Message)
class MessageAdmin(admin.ModelAdmin):
    """Message admin."""
    list_display = ['subject', 'created_by', 'is_sent', 'scheduled_for', 'target_role']
    list_filter = ['is_sent', 'target_role', 'created_at', 'scheduled_for']
    search_fields = ['subject', 'body']
    date_hierarchy = 'created_at'


@admin.register(UserMessage)
class UserMessageAdmin(admin.ModelAdmin):
    """User message delivery admin."""
    list_display = ['user', 'message', 'has_read', 'delivered_at']
    list_filter = ['has_read', 'delivered_at']
    search_fields = ['user__username', 'message__subject']
    date_hierarchy = 'delivered_at'
