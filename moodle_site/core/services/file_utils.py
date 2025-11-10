"""
File utilities for handling uploads, validation, compression, and checksums.
"""
import hashlib
import io
import os
import re
import zipfile
from typing import Tuple, Optional
import magic
from django.conf import settings
from django.core.files.uploadedfile import UploadedFile


class FileValidationError(Exception):
    """Custom exception for file validation errors."""
    pass


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to remove dangerous characters.

    Args:
        filename: Original filename

    Returns:
        Sanitized filename
    """
    # Remove any path components
    filename = os.path.basename(filename)

    # Remove any non-alphanumeric characters except dots, hyphens, and underscores
    filename = re.sub(r'[^\w\s\-\.]', '', filename)

    # Replace spaces with underscores
    filename = filename.replace(' ', '_')

    # Limit length
    name, ext = os.path.splitext(filename)
    if len(name) > 200:
        name = name[:200]

    return f"{name}{ext}".lower()


def get_file_extension(filename: str) -> str:
    """
    Extract file extension from filename.

    Args:
        filename: The filename

    Returns:
        File extension without the dot (e.g., 'pdf', 'docx')
    """
    ext = os.path.splitext(filename)[1]
    return ext.lstrip('.').lower() if ext else ''


def calculate_checksum(file_bytes: bytes) -> str:
    """
    Calculate SHA-256 checksum of file content.

    Args:
        file_bytes: Binary content of the file

    Returns:
        Hexadecimal SHA-256 hash string
    """
    sha256_hash = hashlib.sha256()
    sha256_hash.update(file_bytes)
    return sha256_hash.hexdigest()


def validate_file_size(size: int) -> Tuple[bool, Optional[str]]:
    """
    Validate file size against configured limits.

    Args:
        size: File size in bytes

    Returns:
        Tuple of (is_valid, error_message)
    """
    max_size = settings.MAX_FILE_SIZE

    if size <= 0:
        return False, "File is empty"

    if size > max_size:
        max_mb = max_size / (1024 * 1024)
        return False, f"File exceeds maximum size limit of {max_mb:.0f} MB"

    return True, None


def should_compress_file(size: int) -> bool:
    """
    Determine if file should be compressed for VirusTotal scanning.

    Args:
        size: File size in bytes

    Returns:
        True if file should be compressed
    """
    return size > settings.LARGE_FILE_THRESHOLD


def compress_file(file_bytes: bytes, filename: str) -> bytes:
    """
    Compress file content into a ZIP archive.

    Args:
        file_bytes: Original file content
        filename: Original filename

    Returns:
        Compressed ZIP file as bytes
    """
    zip_buffer = io.BytesIO()

    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
        zip_file.writestr(filename, file_bytes)

    zip_buffer.seek(0)
    return zip_buffer.read()


def get_mime_type(file_bytes: bytes) -> str:
    """
    Detect MIME type of file content using python-magic.

    Args:
        file_bytes: Binary file content

    Returns:
        MIME type string
    """
    try:
        mime = magic.Magic(mime=True)
        return mime.from_buffer(file_bytes)
    except Exception:
        # Fallback to generic binary type
        return 'application/octet-stream'


def validate_file_content(file_bytes: bytes, declared_extension: str) -> Tuple[bool, Optional[str]]:
    """
    Validate file content matches declared extension.

    Performs basic MIME type checking to detect mismatched extensions.

    Args:
        file_bytes: Binary file content
        declared_extension: File extension from filename

    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        mime_type = get_mime_type(file_bytes)

        # Define common extension to MIME type mappings
        extension_mime_map = {
            'pdf': ['application/pdf'],
            'doc': ['application/msword'],
            'docx': [
                'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            ],
            'xls': ['application/vnd.ms-excel'],
            'xlsx': [
                'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
            ],
            'ppt': ['application/vnd.ms-powerpoint'],
            'pptx': [
                'application/vnd.openxmlformats-officedocument.presentationml.presentation'
            ],
            'txt': ['text/plain'],
            'csv': ['text/csv', 'text/plain'],
            'jpg': ['image/jpeg'],
            'jpeg': ['image/jpeg'],
            'png': ['image/png'],
            'gif': ['image/gif'],
            'zip': ['application/zip'],
            'tar': ['application/x-tar'],
            'gz': ['application/gzip', 'application/x-gzip'],
            'mp3': ['audio/mpeg'],
            'mp4': ['video/mp4'],
            'avi': ['video/x-msvideo'],
            'py': ['text/x-python', 'text/plain'],
            'js': ['application/javascript', 'text/javascript', 'text/plain'],
            'html': ['text/html'],
            'css': ['text/css'],
            'json': ['application/json', 'text/plain'],
            'xml': ['application/xml', 'text/xml'],
        }

        # If extension has known MIME types, check for match
        if declared_extension in extension_mime_map:
            expected_mimes = extension_mime_map[declared_extension]
            if mime_type not in expected_mimes:
                # Be lenient with text files and generic types
                if mime_type.startswith('text/') and any(
                    m.startswith('text/') for m in expected_mimes
                ):
                    return True, None

                return False, (
                    f"File content type '{mime_type}' does not match "
                    f"declared extension '.{declared_extension}'"
                )

        # Allow files with unknown extensions (no validation)
        return True, None

    except Exception as e:
        # If MIME detection fails, allow the file but log warning
        print(f"Warning: MIME type detection failed: {e}")
        return True, None


def process_uploaded_file(uploaded_file: UploadedFile) -> Tuple[bytes, dict]:
    """
    Process an uploaded file and extract metadata.

    Args:
        uploaded_file: Django UploadedFile object

    Returns:
        Tuple of (file_bytes, metadata_dict)

    Raises:
        FileValidationError: If file validation fails
    """
    # Read file content
    uploaded_file.seek(0)
    file_bytes = uploaded_file.read()

    # Get original filename
    original_filename = uploaded_file.name
    safe_filename = sanitize_filename(original_filename)
    extension = get_file_extension(original_filename)

    # Validate size
    size = len(file_bytes)
    is_valid, error_msg = validate_file_size(size)
    if not is_valid:
        raise FileValidationError(error_msg)

    # Calculate checksum
    checksum = calculate_checksum(file_bytes)

    # Validate content
    is_valid, error_msg = validate_file_content(file_bytes, extension)
    if not is_valid:
        raise FileValidationError(error_msg)

    # Get MIME type
    mime_type = get_mime_type(file_bytes)

    # Determine if compression is needed
    needs_compression = should_compress_file(size)

    metadata = {
        'original_filename': original_filename,
        'safe_filename': safe_filename,
        'extension': extension,
        'size': size,
        'checksum': checksum,
        'mime_type': mime_type,
        'needs_compression': needs_compression,
    }

    return file_bytes, metadata


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.

    Args:
        size_bytes: Size in bytes

    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024.0:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024.0
    return f"{size_bytes:.1f} TB"
