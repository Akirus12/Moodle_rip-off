"""
Core models for the Moodle rip-off LMS.

Includes User extensions, Course, File, FileShare, and related models.
"""
import uuid
from django.contrib.auth.models import AbstractUser
from django.core.validators import FileExtensionValidator, MinValueValidator
from django.db import models
from django.utils import timezone


class Role(models.TextChoices):
    """User role choices."""
    STUDENT = 'student', 'Student'
    TEACHER = 'teacher', 'Teacher'
    ADMINISTRATOR = 'administrator', 'Administrator'


class PermissionLevel(models.TextChoices):
    """Permission level choices for file sharing."""
    PUBLIC = 'public', 'Public'
    STUDENT = 'student', 'Student'
    TEACHER = 'teacher', 'Teacher'
    ADMINISTRATOR = 'administrator', 'Administrator'


class AssignmentStatus(models.TextChoices):
    """Assignment status choices."""
    ACTIVE = 'active', 'Active'
    DUE = 'due', 'Due'
    ARCHIVED = 'archived', 'Archived'
    HIDDEN = 'hidden', 'Hidden'


class User(AbstractUser):
    """
    Extended user model with role field.

    Extends Django's AbstractUser to add role information.
    """
    role = models.CharField(
        max_length=20,
        choices=Role.choices,
        default=Role.STUDENT,
        db_index=True,
    )

    class Meta:
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        indexes = [
            models.Index(fields=['role', 'is_active']),
        ]

    def __str__(self) -> str:
        return f"{self.username} ({self.get_role_display()})"

    def is_student(self) -> bool:
        return self.role == Role.STUDENT

    def is_teacher(self) -> bool:
        return self.role == Role.TEACHER

    def is_administrator(self) -> bool:
        return self.role == Role.ADMINISTRATOR


class Course(models.Model):
    """
    Course model representing a class or subject.
    """
    name = models.CharField(max_length=200, db_index=True)
    code = models.CharField(max_length=20, unique=True, db_index=True)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True, db_index=True)

    # Many-to-many relationships
    students = models.ManyToManyField(
        User,
        through='UserCourse',
        related_name='enrolled_courses',
    )
    teachers = models.ManyToManyField(
        User,
        related_name='teaching_courses',
        limit_choices_to={'role': Role.TEACHER},
    )
    prerequisites = models.ManyToManyField(
        'self',
        through='CoursePrerequisite',
        symmetrical=False,
        related_name='required_for',
        blank=True,
    )

    class Meta:
        verbose_name = 'Course'
        verbose_name_plural = 'Courses'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['code', 'is_active']),
        ]

    def __str__(self) -> str:
        return f"{self.code} - {self.name}"


class UserCourse(models.Model):
    """
    Enrollment model linking users to courses.
    """
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='course_enrollments',
    )
    course = models.ForeignKey(
        Course,
        on_delete=models.CASCADE,
        related_name='enrollments',
    )
    enrolled_at = models.DateTimeField(auto_now_add=True)
    is_active = models.BooleanField(default=True, db_index=True)

    class Meta:
        verbose_name = 'Course Enrollment'
        verbose_name_plural = 'Course Enrollments'
        unique_together = [['user', 'course']]
        indexes = [
            models.Index(fields=['user', 'course', 'is_active']),
        ]

    def __str__(self) -> str:
        return f"{self.user.username} enrolled in {self.course.code}"


class CoursePrerequisite(models.Model):
    """
    Prerequisites relationship between courses.
    """
    course = models.ForeignKey(
        Course,
        on_delete=models.CASCADE,
        related_name='prerequisite_links',
    )
    prerequisite = models.ForeignKey(
        Course,
        on_delete=models.CASCADE,
        related_name='required_for_links',
    )

    class Meta:
        verbose_name = 'Course Prerequisite'
        verbose_name_plural = 'Course Prerequisites'
        unique_together = [['course', 'prerequisite']]

    def __str__(self) -> str:
        return f"{self.prerequisite.code} is prerequisite for {self.course.code}"


class File(models.Model):
    """
    File model storing files as BLOBs in the database.

    Files are stored with their binary content, checksum, and metadata.
    """
    name = models.CharField(max_length=255, db_index=True)
    description = models.TextField(blank=True)
    bytes = models.BinaryField()
    extension = models.CharField(max_length=10, db_index=True)
    date_uploaded = models.DateTimeField(auto_now_add=True, db_index=True)
    checksum_hash = models.CharField(
        max_length=64,
        db_index=True,
        help_text="SHA-256 checksum of file content"
    )
    size = models.BigIntegerField(
        validators=[MinValueValidator(0)],
        help_text="File size in bytes"
    )

    # Uploader reference
    uploaded_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='uploaded_files',
    )

    # VirusTotal scan results
    virustotal_report_id = models.CharField(max_length=255, blank=True, null=True)
    virustotal_scan_date = models.DateTimeField(null=True, blank=True)
    is_malicious = models.BooleanField(default=False, db_index=True)
    virustotal_summary = models.JSONField(null=True, blank=True)

    # Metadata tracking
    last_viewed_at = models.DateTimeField(null=True, blank=True)
    last_viewed_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='viewed_files',
    )
    view_count = models.IntegerField(default=0)

    # Original filename (before sanitization)
    original_filename = models.CharField(max_length=255)

    # If file was compressed before VT scan
    was_compressed = models.BooleanField(default=False)
    original_size = models.BigIntegerField(null=True, blank=True)

    class Meta:
        verbose_name = 'File'
        verbose_name_plural = 'Files'
        ordering = ['-date_uploaded']
        indexes = [
            models.Index(fields=['checksum_hash', 'is_malicious']),
            models.Index(fields=['uploaded_by', 'date_uploaded']),
            models.Index(fields=['extension', 'is_malicious']),
        ]

    def __str__(self) -> str:
        return f"{self.name} ({self.extension})"

    def update_view_metadata(self, user: User) -> None:
        """Update last viewed metadata."""
        self.last_viewed_at = timezone.now()
        self.last_viewed_by = user
        self.view_count += 1
        self.save(update_fields=['last_viewed_at', 'last_viewed_by', 'view_count'])


class CourseMaterial(models.Model):
    """
    Course material linked to a course and containing a file.
    """
    course = models.ForeignKey(
        Course,
        on_delete=models.CASCADE,
        related_name='materials',
    )
    file = models.ForeignKey(
        File,
        on_delete=models.CASCADE,
        related_name='course_materials',
    )
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    is_visible = models.BooleanField(default=True, db_index=True)
    order = models.IntegerField(default=0)

    class Meta:
        verbose_name = 'Course Material'
        verbose_name_plural = 'Course Materials'
        ordering = ['order', '-uploaded_at']
        indexes = [
            models.Index(fields=['course', 'is_visible', 'order']),
        ]

    def __str__(self) -> str:
        return f"{self.title} - {self.course.code}"


class Assignment(models.Model):
    """
    Assignment model with status and deadline.
    """
    course = models.ForeignKey(
        Course,
        on_delete=models.CASCADE,
        related_name='assignments',
    )
    title = models.CharField(max_length=255)
    description = models.TextField()
    file = models.ForeignKey(
        File,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assignments',
        help_text="Optional assignment file/instructions"
    )

    status = models.CharField(
        max_length=20,
        choices=AssignmentStatus.choices,
        default=AssignmentStatus.ACTIVE,
        db_index=True,
    )

    due_date = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    max_score = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=100.00,
        validators=[MinValueValidator(0)],
    )

    class Meta:
        verbose_name = 'Assignment'
        verbose_name_plural = 'Assignments'
        ordering = ['-due_date', '-created_at']
        indexes = [
            models.Index(fields=['course', 'status', 'due_date']),
        ]

    def __str__(self) -> str:
        return f"{self.title} - {self.course.code}"


class FileShare(models.Model):
    """
    File sharing model with UUID links and permission levels.

    Supports password protection with Argon2 hashing.
    """
    file = models.ForeignKey(
        File,
        on_delete=models.CASCADE,
        related_name='shares',
    )
    url_uuid = models.UUIDField(
        default=uuid.uuid4,
        unique=True,
        editable=False,
        db_index=True,
    )

    # Permission levels for different actions
    view_permission_level = models.CharField(
        max_length=20,
        choices=PermissionLevel.choices,
        default=PermissionLevel.STUDENT,
    )
    edit_permission_level = models.CharField(
        max_length=20,
        choices=PermissionLevel.choices,
        default=PermissionLevel.TEACHER,
    )
    download_permission_level = models.CharField(
        max_length=20,
        choices=PermissionLevel.choices,
        default=PermissionLevel.STUDENT,
    )

    # Password protection
    is_password_protected = models.BooleanField(default=False, db_index=True)
    hashed_password = models.CharField(max_length=255, null=True, blank=True)
    password_salt = models.CharField(max_length=255, null=True, blank=True)

    # Expiration
    expiration_date = models.DateTimeField(null=True, blank=True, db_index=True)

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_shares',
    )
    access_count = models.IntegerField(default=0)

    class Meta:
        verbose_name = 'File Share'
        verbose_name_plural = 'File Shares'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['url_uuid', 'expiration_date']),
            models.Index(fields=['file', 'is_password_protected']),
        ]

    def __str__(self) -> str:
        return f"Share {self.url_uuid} for {self.file.name}"

    def is_expired(self) -> bool:
        """Check if the share link has expired."""
        if self.expiration_date is None:
            return False
        return timezone.now() > self.expiration_date

    def increment_access_count(self) -> None:
        """Increment the access counter."""
        self.access_count += 1
        self.save(update_fields=['access_count'])


class Message(models.Model):
    """
    Message model for system notifications and announcements.
    """
    subject = models.CharField(max_length=255)
    body = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        null=True,
        related_name='created_messages',
    )

    # Scheduling
    scheduled_for = models.DateTimeField(null=True, blank=True, db_index=True)
    is_sent = models.BooleanField(default=False, db_index=True)

    # Target audience
    target_role = models.CharField(
        max_length=20,
        choices=Role.choices,
        null=True,
        blank=True,
        help_text="If set, only users with this role will receive the message"
    )
    target_course = models.ForeignKey(
        Course,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='messages',
        help_text="If set, only users enrolled in this course will receive the message"
    )

    class Meta:
        verbose_name = 'Message'
        verbose_name_plural = 'Messages'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['scheduled_for', 'is_sent']),
        ]

    def __str__(self) -> str:
        return f"{self.subject} (created {self.created_at.date()})"


class UserMessage(models.Model):
    """
    User-specific message delivery tracking.
    """
    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='received_messages',
    )
    message = models.ForeignKey(
        Message,
        on_delete=models.CASCADE,
        related_name='user_messages',
    )

    has_read = models.BooleanField(default=False, db_index=True)
    read_at = models.DateTimeField(null=True, blank=True)
    delivered_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = 'User Message'
        verbose_name_plural = 'User Messages'
        unique_together = [['user', 'message']]
        ordering = ['-delivered_at']
        indexes = [
            models.Index(fields=['user', 'has_read', 'delivered_at']),
        ]

    def __str__(self) -> str:
        return f"{self.message.subject} to {self.user.username}"

    def mark_as_read(self) -> None:
        """Mark message as read."""
        if not self.has_read:
            self.has_read = True
            self.read_at = timezone.now()
            self.save(update_fields=['has_read', 'read_at'])
