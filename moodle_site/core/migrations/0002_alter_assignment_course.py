# Generated migration to change Assignment.course foreign key from core.Course to courses.Course

from django.db import migrations, models
import django.db.models.deletion


def delete_existing_assignments(apps, schema_editor):
    """Delete any existing assignments that reference core.Course."""
    Assignment = apps.get_model('core', 'Assignment')
    # Delete all existing assignments since they reference the wrong Course model
    Assignment.objects.all().delete()


def reverse_delete_assignments(apps, schema_editor):
    """Reverse operation - nothing to do since we deleted the data."""
    pass


class Migration(migrations.Migration):

    dependencies = [
        ('core', '0001_initial'),
        ('courses', '0001_initial'),
    ]

    operations = [
        # First, delete any existing assignments that reference core.Course
        migrations.RunPython(delete_existing_assignments, reverse_delete_assignments),
        # Then, change the foreign key to point to courses.Course
        migrations.AlterField(
            model_name='assignment',
            name='course',
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                related_name='assignments',
                to='courses.course'
            ),
        ),
    ]

