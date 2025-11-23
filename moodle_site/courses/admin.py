from django.contrib import admin
from .models import Course, CourseMaterial


@admin.register(Course)
class CourseAdmin(admin.ModelAdmin):
    list_display = ['title', 'instructor', 'is_active', 'created_at']
    list_filter = ['is_active', 'created_at']
    search_fields = ['title', 'description']
    date_hierarchy = 'created_at'


@admin.register(CourseMaterial)
class CourseMaterialAdmin(admin.ModelAdmin):
    list_display = ['title', 'course', 'material_type', 'order', 'created_at']
    list_filter = ['material_type', 'created_at']
    search_fields = ['title', 'description', 'course__title']
    list_editable = ['order']