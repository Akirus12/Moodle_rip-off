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
