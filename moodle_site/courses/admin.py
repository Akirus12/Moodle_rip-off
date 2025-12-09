from django.contrib import admin
from .models import CourseMaterial

@admin.register(CourseMaterial)
class CourseMaterialAdmin(admin.ModelAdmin):
    list_display = ['title', 'course', 'material_type', 'order', 'created_at']
    list_filter = ['material_type', 'created_at']
    search_fields = ['title', 'description', 'course__code', 'course__name']
    fields = ['course', 'title', 'description', 'material_type', 'content', 'file', 'order']

    def formfield_for_dbfield(self, db_field, **kwargs):
        field = super().formfield_for_dbfield(db_field, **kwargs)
        if db_field.name == 'file':
            field.required = False
        return field