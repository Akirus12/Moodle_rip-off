from django.db import models
from core.models import Course as CoreCourse

# Remove the Course model entirely and use CoreCourse instead
# Keep only course-specific additions if needed

class CourseMaterial(models.Model):
    """Model representing course materials."""
    MATERIAL_TYPES = [
        ('pdf', 'PDF Document'),
        ('video', 'Video'),
        ('link', 'External Link'),
        ('text', 'Text Content'),
    ]
    
    course = models.ForeignKey(CoreCourse, on_delete=models.CASCADE, related_name='course_materials')
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
        return f"{self.course.code} - {self.title}"