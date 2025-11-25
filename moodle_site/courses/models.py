from django.contrib.auth import get_user_model
from django.db import models

User = get_user_model()

class Course(models.Model):
    """Model representing a course."""
    title = models.CharField(max_length=200)
    description = models.TextField()
    instructor = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='courses',
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return self.title

    def get_completion_percentage(self, user):
        """Calculate completion percentage based on assignments with error handling"""
        try:
            from assignments.models import Assignment
            total_assignments = Assignment.objects.filter(course=self).count()
            if total_assignments == 0:
                return 0
            completed_assignments = Assignment.objects.filter(
                course=self,
                submissions__user=user,
                submissions__status='completed'
            ).distinct().count()
            return int((completed_assignments / total_assignments) * 100)
        except ImportError:
            # If assignments app is not implemented, return None or 0
            return None

class CourseMaterial(models.Model):
    """Model representing course materials."""
    MATERIAL_TYPES = [
        ('pdf', 'PDF Document'),
        ('video', 'Video'),
        ('link', 'External Link'),
        ('text', 'Text Content'),
    ]

    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='materials')
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    material_type = models.CharField(max_length=10, choices=MATERIAL_TYPES, default='text')
    content = models.TextField(blank=True, help_text="Text content or URL")
    file = models.FileField(upload_to='course_materials/', blank=True, null=True)
    order = models.IntegerField(default=0, help_text="Order of material in course")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['order', 'created_at']

    def __str__(self):
        return f"{self.course.title} - {self.title}"

class CourseCompletion(models.Model):
    """Model for tracking course completion progress"""
    course = models.ForeignKey(Course, on_delete=models.CASCADE, related_name='completions')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='course_completions')
    completed_materials = models.ManyToManyField(CourseMaterial, blank=True)
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        unique_together = ['course', 'user']

    def get_completion_percentage(self):
        total_materials = self.course.materials.count()
        if total_materials == 0:
            return 0
        completed = self.completed_materials.count()
        return int((completed / total_materials) * 100)