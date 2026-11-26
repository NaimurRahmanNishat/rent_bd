# api/models/user_models.py
import hmac
import hashlib
import secrets
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from django.db import models, transaction
from api.utils.fields import EncryptedCharField
from django.contrib.auth.models import AbstractUser, BaseUserManager
from api.utils.validators import (
    validate_file_size,
    validate_image_mime,
    validate_document_mime,
    validate_no_malware,
)


# 1. Custom User Manager
class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("The Email field must be set")

        email = self.normalize_email(email)
        extra_fields.setdefault("is_active", False)
        user = self.model(email=email, **extra_fields)
        user.set_password(password) 
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault("is_staff", True)
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("is_verified", True)
        extra_fields.setdefault("is_active", True)
        extra_fields.setdefault("role", User.SUPER_ADMIN)

        if extra_fields.get("is_staff") is not True:
            raise ValueError("Superuser must have is_staff=True.")
        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email, password, **extra_fields)


# 2. Main User Model
class User(AbstractUser):
    TENANT = "tenant"
    LANDLORD = "landlord"
    SUPER_ADMIN = "super_admin"

    ROLE_CHOICES = [
        (TENANT, "Tenant"),
        (LANDLORD, "Landlord"),
        (SUPER_ADMIN, "Super Admin"),
    ]

    # --- Google Auth Provider Choices ---
    AUTH_EMAIL = "email"
    AUTH_GOOGLE = "google"
    AUTH_PROVIDER_CHOICES = [
        (AUTH_EMAIL, "Email/Password"),
        (AUTH_GOOGLE, "Google OAuth"),
    ]

    # Identity fields
    username = None
    email = models.EmailField(unique=True)
    name = models.CharField(max_length=100, null=True, blank=True)
    role = models.CharField(max_length=30, choices=ROLE_CHOICES, default=TENANT, db_index=True)
    phone_number = models.CharField(max_length=20, unique=True, null=True, blank=True)
    avatar = models.ImageField(
        upload_to="profile_pictures/", null=True, blank=True,
        validators=[validate_file_size, validate_image_mime, validate_no_malware],
    )

    # Google OAuth
    auth_provider = models.CharField(max_length=20, choices=AUTH_PROVIDER_CHOICES, default=AUTH_EMAIL)
    google_id = models.CharField(max_length=255, null=True, blank=True, unique=True)

    # KYC Flag (Actual verification records live in KYCVerification model)
    is_identity_verified = models.BooleanField(default=False)

    # Address fields
    street = models.CharField(max_length=255, null=True, blank=True)
    city = models.CharField(max_length=100, null=True, blank=True)
    state = models.CharField(max_length=100, null=True, blank=True)
    zip_code = models.CharField(max_length=20, null=True, blank=True)

    # Status fields
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=False)
    is_staff = models.BooleanField(default=False)
    two_factor_enabled = models.BooleanField(default=False)

    # Suspended & Reactivate
    is_suspended = models.BooleanField(default=False, db_index=True)
    suspended_at = models.DateTimeField(null=True, blank=True)
    suspended_reason = models.TextField(null=True, blank=True)
    suspended_by = models.ForeignKey(
        "self",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="suspended_users",
        help_text="The user who suspended this user.",
    )

    # Timestamps & Last seen
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_seen_at = models.DateTimeField(null=True, blank=True, db_index=True)

    objects = UserManager()
    USERNAME_FIELD = "email"
    REQUIRED_FIELDS = []

    class Meta:
        db_table = "user"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["role", "is_active"]),
            models.Index(fields=["role", "is_suspended"]),
            models.Index(fields=["-created_at", "-id"], name="user_created_id_idx"),
        ]

    def __str__(self):
        return f"{self.email} - {self.name or ''}".strip()

    @property
    def is_online(self) -> bool:
        if not self.last_seen_at:
            return False
        return (timezone.now() - self.last_seen_at) <= timedelta(minutes=5)

    @property
    def can_login(self) -> bool:
        return self.is_active and not self.is_suspended


# 3. User Verification Model (OTP)
class UserVerification(models.Model):

    VERIFICATION_TYPES = (
        ("email_verification", "Email Verification"),
        ("login_2fa", "Login 2FA"),
        ("password_reset", "Password Reset"),
        ("enable_2fa", "Enable 2FA"),
    )

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="verifications")
    otp_hash = models.CharField(max_length=64)
    verification_type = models.CharField(max_length=50, choices=VERIFICATION_TYPES)
    is_used = models.BooleanField(default=False)
    attempt_count = models.PositiveSmallIntegerField(default=0)
    max_attempts = models.PositiveSmallIntegerField(default=5)
    expires_at = models.DateTimeField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "user_verifications"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "verification_type", "is_used"]),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.verification_type}"

    @staticmethod
    def hash_otp(raw_otp: str) -> str:
        return hmac.new(
            settings.SECRET_KEY.encode(), raw_otp.encode(), hashlib.sha256
        ).hexdigest()

    @property
    def is_expired(self) -> bool:
        return timezone.now() > self.expires_at

    @classmethod
    def can_request_new_otp(cls, user, verification_type, cooldown_seconds=60) -> bool:
        window_start = timezone.now() - timedelta(seconds=cooldown_seconds)
        recent = cls.objects.filter(
            user=user, verification_type=verification_type, created_at__gte=window_start
        ).exists()
        return not recent

    @classmethod
    def generate_otp(cls, user, verification_type, minutes=10, length=6):
        raw_otp = "".join(secrets.choice("0123456789") for _ in range(length))
        with transaction.atomic():
            cls.objects.filter(
                user=user, verification_type=verification_type, is_used=False
            ).update(is_used=True, updated_at=timezone.now())

            verification = cls.objects.create(
                user=user,
                otp_hash=cls.hash_otp(raw_otp),
                verification_type=verification_type,
                expires_at=cls.get_expiry(minutes=minutes),
            )
        return raw_otp, verification

    @classmethod
    def get_expiry(cls, minutes=10):
        return timezone.now() + timedelta(minutes=minutes)

    @property
    def is_locked(self) -> bool:
        return self.attempt_count >= self.max_attempts

    def check_otp(self, raw_otp: str) -> bool:
        with transaction.atomic():
            row = type(self).objects.select_for_update().get(pk=self.pk)
            if row.is_used or row.is_expired or row.is_locked:
                return False
            row.attempt_count += 1
            row.save(update_fields=["attempt_count", "updated_at"])
            self.attempt_count = row.attempt_count
            return hmac.compare_digest(row.otp_hash, self.hash_otp(raw_otp))

    def mark_used(self) -> bool:
        updated = type(self).objects.filter(pk=self.pk, is_used=False).update(
            is_used=True, updated_at=timezone.now()
        )
        if updated:
            self.is_used = True
        return bool(updated)


# 4. User Activity Log
class UserActivityLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="activity_logs")
    action = models.CharField(max_length=255)
    path = models.TextField(null=True, blank=True)
    method = models.CharField(max_length=10, null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    location = models.CharField(max_length=255, null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "user_activity_logs"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "-created_at"]),
            models.Index(fields=["-created_at"]),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.action} - {self.created_at}"


# 5. User Suspension Log
class UserSuspensionLog(models.Model):
    SUSPEND = "suspend"
    REACTIVATE = "reactivate"
    ACTION_CHOICES = [
        (SUSPEND, "Suspend"),
        (REACTIVATE, "Reactivate"),
    ]

    user = models.ForeignKey(
        User, on_delete=models.CASCADE, related_name="suspension_logs",
        help_text="The user who was suspended or reactivated.",
    )
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    reason = models.TextField(null=True, blank=True)
    performed_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, related_name="performed_suspension_actions",
        help_text="The user who performed the suspension action.",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "user_suspension_logs"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["user", "-created_at"]),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.action} - {self.created_at}"


# 6. KYC Verification
class KYCVerification(models.Model):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"

    STATUS_CHOICES = [
        (PENDING, "Pending"),
        (APPROVED, "Approved"),
        (REJECTED, "Rejected"),
    ]

    DOCUMENT_NID = "nid"
    DOCUMENT_PASSPORT = "passport"
    DOCUMENT_DRIVING_LICENSE = "driving_license"

    DOCUMENT_TYPES = [
        (DOCUMENT_NID, "NID"),
        (DOCUMENT_PASSPORT, "Passport"),
        (DOCUMENT_DRIVING_LICENSE, "Driving License"),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="kyc")

    document_type = models.CharField(max_length=20, choices=DOCUMENT_TYPES, default=DOCUMENT_NID)
    document_number = EncryptedCharField()
    document_front = models.ImageField(
        upload_to="kyc_docs/front/",
        validators=[validate_file_size, validate_image_mime, validate_no_malware],
    )
    document_back = models.ImageField(
        upload_to="kyc_docs/back/", null=True, blank=True,
        validators=[validate_file_size, validate_image_mime, validate_no_malware],
    )
    user_selfie = models.ImageField(
        upload_to="kyc_docs/selfies/",
        validators=[validate_file_size, validate_image_mime, validate_no_malware],
    )

    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=PENDING, db_index=True)
    rejection_reason = models.TextField(null=True, blank=True)
    reviewed_by = models.ForeignKey(
        User, on_delete=models.SET_NULL, null=True, blank=True, related_name="reviewed_kycs"
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)

    # --- Beneficiary / Secondary KYC Documents (Optional) ---
    has_beneficiary_document = models.BooleanField(default=False)
    beneficiary_document_type = models.CharField(
        max_length=20, choices=DOCUMENT_TYPES, null=True, blank=True
    )
    beneficiary_document_front = models.ImageField(
        upload_to="kyc_docs/beneficiary/front/", null=True, blank=True,
        validators=[validate_file_size, validate_image_mime, validate_no_malware],
    )
    beneficiary_document_back = models.ImageField(
        upload_to="kyc_docs/beneficiary/back/", null=True, blank=True,
        validators=[validate_file_size, validate_image_mime, validate_no_malware],
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "kyc_verifications"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.user.email} - KYC ({self.status})"


# 7. Blocked IP Model
class BlockedIP(models.Model):

    ip_address = models.GenericIPAddressField(unique=True)
    reason = models.CharField(max_length=255, blank=True, null=True)
    blocked_until = models.DateTimeField(
        null=True, blank=True,
        help_text="NULL means indefinitely blocked. Otherwise, the IP will be unblocked after this timestamp.",
    )
    is_active = models.BooleanField(default=True, db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = "security_blocked_ips"

    def __str__(self):
        return f"{self.ip_address} ({'active' if self.is_currently_blocked else 'expired'})"

    @property
    def is_currently_blocked(self) -> bool:
        if not self.is_active:
            return False
        if self.blocked_until and timezone.now() > self.blocked_until:
            return False
        return True

    @classmethod
    def is_ip_blocked(cls, ip_address) -> bool:
        if not ip_address:
            return False
        return (
            cls.objects.filter(ip_address=ip_address, is_active=True)
            .filter(models.Q(blocked_until__isnull=True) | models.Q(blocked_until__gt=timezone.now()))
            .exists()
        )


# 8. Login Attempt Model
class LoginAttempt(models.Model):

    email = models.EmailField(db_index=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    was_successful = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)

    class Meta:
        db_table = "security_login_attempts"
        indexes = [
            models.Index(fields=["email", "-created_at"]),
            models.Index(fields=["ip_address", "-created_at"]),
        ]

    LOCK_WINDOW_MINUTES = 15
    MAX_FAILED_PER_EMAIL = 5
    MAX_FAILED_PER_IP = 20

    @classmethod
    def record(cls, email, ip_address, success: bool):
        return cls.objects.create(
            email=email.lower().strip(), ip_address=ip_address, was_successful=success
        )

    @classmethod
    def is_email_locked(cls, email: str) -> bool:
        window_start = timezone.now() - timedelta(minutes=cls.LOCK_WINDOW_MINUTES)
        failed_count = cls.objects.filter(
            email=email.lower().strip(), was_successful=False, created_at__gte=window_start
        ).count()
        return failed_count >= cls.MAX_FAILED_PER_EMAIL

    @classmethod
    def is_ip_suspicious(cls, ip_address: str) -> bool:
        if not ip_address:
            return False
        window_start = timezone.now() - timedelta(minutes=cls.LOCK_WINDOW_MINUTES)
        failed_count = cls.objects.filter(
            ip_address=ip_address, was_successful=False, created_at__gte=window_start
        ).count()
        return failed_count >= cls.MAX_FAILED_PER_IP


# 9. Tenant Profile Model
class TenantProfile(models.Model):
    EMPLOYMENT_STATUS_CHOICES = [
        ("employed", "Employed"),
        ("self_employed", "Self Employed"),
        ("student", "Student"),
        ("business", "Business"),
        ("other", "Other"),
    ]

    REFUND_METHOD_CHOICES = [
        ("bkash", "bKash"),
        ("nagad", "Nagad"),
        ("rocket", "Rocket"),
        ("bank", "Bank Transfer"),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="tenant_profile")

    # --- Professional & Personal Details ---
    occupation = models.CharField(max_length=100, null=True, blank=True)
    organization_or_institution = models.CharField(max_length=255, null=True, blank=True)
    employment_status = models.CharField(
        max_length=20, choices=EMPLOYMENT_STATUS_CHOICES, default="employed"
    )
    family_members_count = models.PositiveSmallIntegerField(default=1)
    nid_or_passport_number = EncryptedCharField(null=True, blank=True)

    # --- Preferences for Rental Matching ---
    preferred_cities = models.CharField(
        max_length=255, null=True, blank=True, help_text="Comma-separated list of preferred areas/cities"
    )
    max_budget = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)

    # --- Emergency Contact Details ---
    emergency_contact_name = models.CharField(max_length=100, null=True, blank=True)
    emergency_contact_relation = models.CharField(max_length=50, null=True, blank=True)
    emergency_contact_phone = models.CharField(max_length=20, null=True, blank=True)

    #  Documents & Verification 
    income_proof_document = models.FileField(
        upload_to="tenant_docs/income/",
        null=True, blank=True,
        validators=[validate_file_size, validate_document_mime, validate_no_malware],
    )
    previous_landlord_phone = models.CharField(max_length=20, null=True, blank=True)
    is_profile_verified = models.BooleanField(default=False)

    # --- Escrow Refund Account Details ---
    preferred_refund_method = models.CharField(
        max_length=20, choices=REFUND_METHOD_CHOICES, default="bkash"
    )
    refund_mfs_number = models.CharField(
        max_length=20, null=True, blank=True,
        help_text="bKash/Nagad/Rocket number for instant advance refunds",
    )
    refund_bank_account_name = models.CharField(max_length=100, null=True, blank=True)
    refund_bank_account_number = EncryptedCharField(null=True, blank=True)
    refund_bank_routing_number = models.CharField(max_length=50, null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "tenant_profiles"
        verbose_name = "Tenant Profile"
        verbose_name_plural = "Tenant Profiles"

    def __str__(self):
        return f"Tenant Profile: {self.user.email}"


# 10. Landlord Profile Model
class LandlordProfile(models.Model):
    PAYOUT_METHOD_CHOICES = [
        ("bank", "Bank Transfer"),
        ("mfs", "Mobile Financial Service (MFS)"),
    ]

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="landlord_profile")

    company_or_estate_name = models.CharField(max_length=255, null=True, blank=True)
    tin_number = EncryptedCharField(null=True, blank=True)
    trade_license_no = models.CharField(max_length=100, null=True, blank=True)
    is_verified_landlord = models.BooleanField(default=False, db_index=True)

    booking_auto_cancel_hours = models.PositiveSmallIntegerField(
        default=24,
        help_text="Hours before advance payment is automatically refunded if landlord does not confirm.",
    )
    auto_accept_bookings = models.BooleanField(
        default=False,
        help_text="If True, advance booking requests are confirmed automatically.",
    )

    preferred_payout_method = models.CharField(
        max_length=20, choices=PAYOUT_METHOD_CHOICES, default="bank"
    )

    bank_name = models.CharField(max_length=100, null=True, blank=True)
    branch_name = models.CharField(max_length=100, null=True, blank=True)
    account_holder_name = models.CharField(max_length=100, null=True, blank=True)
    account_number = EncryptedCharField(null=True, blank=True)
    routing_number = models.CharField(max_length=50, null=True, blank=True)

    mfs_provider = models.CharField(max_length=20, null=True, blank=True, help_text="e.g. bkash, nagad, rocket")
    mfs_account_number = models.CharField(max_length=20, null=True, blank=True)

    total_earnings_received = models.DecimalField(
        max_digits=14, decimal_places=2, default=0,
        help_text="Lifetime amount received after commission deduction (cache field)",
    )

    total_properties_count = models.PositiveIntegerField(default=0)
    rating = models.DecimalField(max_digits=3, decimal_places=2, default=0)

    # --- Beneficiary (Nominated Person) Fields ---
    is_payout_account_owner = models.BooleanField(
        default=True,
        help_text="Is the payout bank/MFS account in the landlord's own name?",
    )
    beneficiary_name = models.CharField(max_length=100, null=True, blank=True)
    beneficiary_relationship = models.CharField(
        max_length=50, null=True, blank=True, help_text="e.g. Spouse, Son, Father, Manager"
    )
    beneficiary_nid_number = EncryptedCharField(null=True, blank=True)

    is_payout_authorized = models.BooleanField(
        default=False,
        help_text="Landlord agreed that rental payout goes to the beneficiary account.",
    )
    authorized_at = models.DateTimeField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = "landlord_profiles"
        verbose_name = "Landlord Profile"
        verbose_name_plural = "Landlord Profiles"

    def __str__(self):
        return f"Landlord Profile: {self.user.email}"
