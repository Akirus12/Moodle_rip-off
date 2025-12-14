from django import forms
from django.core.exceptions import ValidationError
from django.contrib.auth import get_user_model
from core.models import Assignment, AssignmentStatus, File, AssignmentSubmission, AssignmentGroup, GroupQuestionnaire

User = get_user_model()


class MultipleFileInput(forms.FileInput):
    """Custom file input widget that supports multiple file selection."""
    
    def __init__(self, attrs=None):
        # Filter out 'multiple' from attrs before passing to parent to avoid ValueError
        filtered_attrs = {}
        if attrs:
            filtered_attrs = {k: v for k, v in attrs.items() if k != 'multiple'}
        super().__init__(filtered_attrs)
    
    def render(self, name, value, attrs=None, renderer=None):
        # Build attrs and add 'multiple' attribute
        if attrs is None:
            attrs = {}
        attrs = self.build_attrs(self.attrs, attrs)
        attrs['multiple'] = True
        return super().render(name, value, attrs, renderer)


class AssignmentForm(forms.ModelForm):
    """Form for creating and editing assignments."""
    
    title = forms.CharField(
        max_length=255,
        required=True,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Enter assignment title'
        })
    )
    
    description = forms.CharField(
        required=True,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 6,
            'placeholder': 'Enter assignment description and instructions'
        })
    )
    
    status = forms.ChoiceField(
        choices=AssignmentStatus.choices,
        initial=AssignmentStatus.ACTIVE,
        required=True,
        widget=forms.Select(attrs={
            'class': 'form-control'
        })
    )
    
    due_date = forms.DateTimeField(
        required=False,
        widget=forms.DateTimeInput(attrs={
            'class': 'form-control',
            'type': 'datetime-local'
        }),
        help_text='Optional: Set a due date and time for this assignment'
    )
    
    max_score = forms.DecimalField(
        max_digits=5,
        decimal_places=2,
        initial=100.00,
        min_value=0,
        required=True,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'step': '0.01',
            'min': '0'
        }),
        help_text='Maximum score for this assignment'
    )
    
    file = forms.ModelChoiceField(
        queryset=File.objects.all(),
        required=False,
        empty_label='No file selected',
        widget=forms.Select(attrs={
            'class': 'form-control'
        }),
        help_text='Optional: Select an existing file to attach to this assignment'
    )
    
    is_group_assignment = forms.BooleanField(
        required=False,
        widget=forms.CheckboxInput(attrs={
            'class': 'form-check-input'
        }),
        help_text='Check if this is a group assignment'
    )
    
    class Meta:
        model = Assignment
        fields = ['title', 'description', 'status', 'due_date', 'max_score', 'file', 'is_group_assignment']
        exclude = ['course', 'created_at', 'updated_at']


class SubmissionForm(forms.Form):
    """Form for submitting assignment files."""
    
    files = forms.FileField(
        required=True,
        widget=MultipleFileInput(attrs={
            'class': 'form-control',
            'accept': '*/*'
        }),
        help_text='Select one or more files to submit. Max size: 200 MB per file.'
    )
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Note: Django's FileField doesn't natively support multiple files
        # We'll handle multiple files in the view
    
    def clean_files(self):
        """Validate uploaded files."""
        files = self.files.getlist('files')
        if not files:
            raise ValidationError("At least one file is required.")
        
        # Check each file
        for file in files:
            if file.size > 200 * 1024 * 1024:  # 200 MB
                raise ValidationError(f"File '{file.name}' exceeds 200 MB limit.")
        
        return files


class GradeSubmissionForm(forms.ModelForm):
    """Form for grading assignment submissions."""
    
    score = forms.DecimalField(
        max_digits=5,
        decimal_places=2,
        required=True,
        min_value=0,
        widget=forms.NumberInput(attrs={
            'class': 'form-control',
            'step': '0.01',
            'min': '0'
        }),
        help_text='Score out of assignment max score'
    )
    
    feedback = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 6,
            'placeholder': 'Enter feedback for the student...'
        }),
        help_text='Optional feedback for the student'
    )
    
    class Meta:
        model = AssignmentSubmission
        fields = ['score', 'feedback']
    
    def __init__(self, *args, **kwargs):
        assignment = kwargs.pop('assignment', None)
        super().__init__(*args, **kwargs)
        if assignment:
            self.assignment = assignment
            # Set max value for score field
            self.fields['score'].widget.attrs['max'] = str(assignment.max_score)
    
    def clean_score(self):
        """Validate score doesn't exceed max_score."""
        score = self.cleaned_data.get('score')
        if hasattr(self, 'assignment') and self.assignment:
            if score > self.assignment.max_score:
                raise ValidationError(
                    f"Score cannot exceed the maximum score of {self.assignment.max_score}."
                )
        return score


class AssignmentGroupForm(forms.ModelForm):
    """Form for creating assignment groups."""
    
    students = forms.ModelMultipleChoiceField(
        queryset=User.objects.filter(role='student'),
        required=True,
        widget=forms.CheckboxSelectMultiple(attrs={
            'class': 'form-check-input'
        }),
        help_text='Select students for this group'
    )
    
    class Meta:
        model = AssignmentGroup
        fields = ['name', 'students']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'placeholder': 'Enter group name (e.g., Group 1, Team A)'
            })
        }
    
    def __init__(self, *args, **kwargs):
        assignment = kwargs.pop('assignment', None)
        course = kwargs.pop('course', None)
        super().__init__(*args, **kwargs)
        
        # Filter students to only those enrolled in the course
        if course:
            # Get students from the course - we'll need to check how students are linked
            # For now, we'll use all students, but this should be filtered by course enrollment
            pass


class GroupQuestionnaireForm(forms.ModelForm):
    """Form for students to complete group assignment questionnaire."""
    
    group_satisfaction = forms.ChoiceField(
        choices=[(i, i) for i in range(1, 6)],
        required=True,
        widget=forms.RadioSelect(attrs={
            'class': 'form-check-input'
        }),
        help_text='Rate your satisfaction with the group work (1 = Very Dissatisfied, 5 = Very Satisfied)'
    )
    
    own_contribution = forms.ChoiceField(
        choices=[(i, i) for i in range(1, 6)],
        required=True,
        widget=forms.RadioSelect(attrs={
            'class': 'form-check-input'
        }),
        help_text='Rate your own contribution to the group (1 = Very Low, 5 = Very High)'
    )
    
    assignment_opinion = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 4,
            'placeholder': 'Briefly share your opinion on the assignment (optional)...'
        }),
        help_text='Optional: Your brief opinion on the assignment'
    )
    
    recommendations = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={
            'class': 'form-control',
            'rows': 4,
            'placeholder': 'Any recommendations you have (optional)...'
        }),
        help_text='Optional: Any recommendations you have'
    )
    
    class Meta:
        model = GroupQuestionnaire
        fields = ['group_satisfaction', 'own_contribution', 'assignment_opinion', 'recommendations']

