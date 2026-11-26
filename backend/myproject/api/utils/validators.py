# api/utils/validators.py
import logging
import filetype
from django.conf import settings
from django.core.exceptions import ValidationError

logger = logging.getLogger("account")

MAX_UPLOAD_SIZE_MB = 5
ALLOWED_IMAGE_MIME_TYPES = {"image/jpeg", "image/png", "image/webp"}
ALLOWED_DOCUMENT_MIME_TYPES = ALLOWED_IMAGE_MIME_TYPES | {"application/pdf"}


def validate_file_size(file):
    max_bytes = MAX_UPLOAD_SIZE_MB * 1024 * 1024
    if file.size > max_bytes:
        raise ValidationError(f"File size must be less than {MAX_UPLOAD_SIZE_MB}MB")


def _check_mime(file, allowed: set[str], message: str):
    file.seek(0)
    header = file.read(261)
    file.seek(0)
    kind = filetype.guess(header)
    if kind is None or kind.mime not in allowed:
        raise ValidationError(message)


def validate_image_mime(file):
    _check_mime(
        file,
        ALLOWED_IMAGE_MIME_TYPES,
        "Only JPEG, PNG and WebP image files are allowed. Please upload a valid image file.",
    )


def validate_document_mime(file):
    _check_mime(
        file,
        ALLOWED_DOCUMENT_MIME_TYPES,
        "Only PDF, JPEG, PNG and WebP files are allowed.",
    )


def validate_no_malware(file):
    if not getattr(settings, "ENABLE_MALWARE_SCAN", False):
        return

    fail_closed = getattr(settings, "MALWARE_SCAN_FAIL_CLOSED", True)
    try:
        import pyclamd
    except ImportError:
        logger.error("pyclamd not installed. Malware scan unavailable.")
        if fail_closed:
            raise ValidationError("File scanning is currently unavailable. Please try again later.")
        return

    try:
        cd = pyclamd.ClamdUnixSocket()
        file.seek(0)
        result = cd.scan_stream(file.read())
        file.seek(0)
    except Exception:
        logger.exception("Failed to scan uploaded file for malware.")
        if fail_closed:
            raise ValidationError("Could not scan the file. Please try again later.")
        return

    if result is not None:
        logger.warning("Malware detected in uploaded file: %s", result)
        raise ValidationError("Malware detected in uploaded file. Please upload a valid file.")

