# api/utils/fields.py
import logging
from functools import lru_cache
from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.db import models

logger = logging.getLogger("account")


@lru_cache(maxsize=4)
def _build_fernet(keys: tuple) -> MultiFernet:
    return MultiFernet([Fernet(k) for k in keys])


def _get_fernet() -> MultiFernet:
    keys = getattr(settings, "FIELD_ENCRYPTION_KEYS", None) or getattr(settings, "FIELD_ENCRYPTION_KEY", None)
    if not keys:
        raise ImproperlyConfigured(
            "FIELD_ENCRYPTION_KEY is not set. "
            "python -c \"from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())\""
        )
    if isinstance(keys, (str, bytes)):
        keys = [keys]
    return _build_fernet(tuple(k.encode() if isinstance(k, str) else k for k in keys))


class EncryptedCharField(models.CharField):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("max_length", 500)
        super().__init__(*args, **kwargs)

    def get_prep_value(self, value):
        if value is None or value == "":
            return value
        return _get_fernet().encrypt(str(value).encode()).decode()

    def from_db_value(self, value, expression, connection):
        if value is None or value == "":
            return value
        try:
            return _get_fernet().decrypt(value.encode()).decode()
        except InvalidToken:
            logger.warning("EncryptedCharField: failed to decrypt a value (wrong key or plaintext data).")
            return value

