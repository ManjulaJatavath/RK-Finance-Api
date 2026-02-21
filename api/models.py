
from django.db import models
from django.contrib.auth.models import AbstractBaseUser, BaseUserManager, PermissionsMixin
from django.utils import timezone


class UserManager(BaseUserManager):
    """Custom user manager"""
    
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('Email is required')
        
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user
    
    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', 'admin')
        
        return self.create_user(email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    """Custom User model"""
    
    ROLE_CHOICES = [
        ('user', 'User'),
        ('admin', 'Admin'),
    ]
    
    first_name = models.CharField(max_length=100)
    last_name = models.CharField(max_length=100)
    email = models.EmailField(unique=True)
    mobile_number = models.CharField(max_length=15, unique=True)
    role = models.CharField(max_length=20, choices=ROLE_CHOICES, default='user')
    profile_img = models.URLField(blank=True, null=True)
    address = models.TextField(blank=True, null=True)
    state = models.CharField(max_length=100, blank=True, null=True)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_active = models.DateTimeField(blank=True, null=True)
    last_login_time = models.DateTimeField(blank=True, null=True)
    last_login_ip = models.GenericIPAddressField(blank=True, null=True)
    last_login_medium = models.CharField(max_length=20, blank=True, null=True)
    last_login_uagent = models.TextField(blank=True, null=True)
    token_updated_at = models.DateTimeField(blank=True, null=True)
    
    objects = UserManager()
    
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name', 'mobile_number']
    
    class Meta:
        db_table = 'users'
        ordering = ['-id']
    
    def __str__(self):
        return f"{self.first_name} {self.last_name} ({self.email})"


class Notification(models.Model):
    """Notification model"""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='notifications')
    title = models.CharField(max_length=255)
    summary = models.TextField()
    read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'notifications'
        ordering = ['-id']
    
    def __str__(self):
        return f"{self.title} - {self.user.email}"


class Agreement(models.Model):
    """Agreement model for document signing"""
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('signed', 'Signed'),
        ('rejected', 'Rejected'),
    ]
    
    template_url = models.URLField()
    user_name = models.CharField(max_length=255)
    user_phone = models.CharField(max_length=15)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    signed_pdf_url = models.URLField(blank=True, null=True)
    signed_at = models.DateTimeField(blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'agreements'
        ordering = ['-id']
    
    def __str__(self):
        return f"Agreement {self.id} - {self.user_name}"


class LoanApplication(models.Model):
    """Loan Application model"""
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
        ('active', 'Active'),
        ('completed', 'Completed'),
    ]
    
    GENDER_CHOICES = [
        ('male', 'Male'),
        ('female', 'Female'),
        ('other', 'Other'),
    ]
    
    INTEREST_TYPE_CHOICES = [
        ('percentage', 'Percentage'),
        ('fixed', 'Fixed'),
    ]
    
    TENURE_TYPE_CHOICES = [
        ('months', 'Months'),
        ('weeks', 'Weeks'),
        ('years', 'Years'),
    ]
    
    # User relationship
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='loan_applications')
    
    # Personal Information
    applicant_name = models.CharField(max_length=255)
    son_daughter_wife_of = models.CharField(max_length=255, blank=True, null=True)
    gender = models.CharField(max_length=10, choices=GENDER_CHOICES, blank=True, null=True)
    date_of_birth = models.DateField(blank=True, null=True)
    
    # Address
    address_line1 = models.CharField(max_length=255, blank=True, null=True)
    address_line2 = models.CharField(max_length=255, blank=True, null=True)
    address_line3 = models.CharField(max_length=255, blank=True, null=True)
    
    # Documents
    aadhaar_number = models.CharField(max_length=20, blank=True, null=True)
    pan_number = models.CharField(max_length=20, blank=True, null=True)
    bank_details = models.TextField(blank=True, null=True)
    
    # Contact
    mobile_number = models.CharField(max_length=15, blank=True, null=True)
    alternate_mobile = models.CharField(max_length=15, blank=True, null=True)
    email_id = models.EmailField(blank=True, null=True)
    photo_url = models.URLField(blank=True, null=True)
    
    # Loan Details
    loan_sanction_date = models.DateField(blank=True, null=True)
    loan_amount = models.DecimalField(max_digits=12, decimal_places=2)
    rate_of_interest = models.DecimalField(max_digits=5, decimal_places=2)
    interest_type = models.CharField(max_length=20, choices=INTEREST_TYPE_CHOICES, default='percentage')
    loan_tenure = models.IntegerField()
    tenure_type = models.CharField(max_length=10, choices=TENURE_TYPE_CHOICES, default='months')
    
    # Payment Information
    first_payment_date = models.DateField()
    first_week_amount = models.DecimalField(max_digits=12, decimal_places=2)
    last_week_payment_date = models.DateField(blank=True, null=True)
    last_week_amount = models.DecimalField(max_digits=12, decimal_places=2, blank=True, null=True)
    total_repayment_amount = models.DecimalField(max_digits=12, decimal_places=2)
    
    # Signatures
    borrower_signature = models.TextField(blank=True, null=True)
    applicant_signature = models.TextField(blank=True, null=True)
    
    # Status
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'loan_applications'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"Loan {self.id} - {self.applicant_name} - ₹{self.loan_amount}"


class LoanPayment(models.Model):
    """Loan Payment model for tracking individual payments"""
    
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('paid', 'Paid'),
        ('overdue', 'Overdue'),
    ]
    
    loan_application = models.ForeignKey(
        LoanApplication, 
        on_delete=models.CASCADE, 
        related_name='payments'
    )
    payment_number = models.IntegerField()  # Week/month number
    payment_amount = models.DecimalField(max_digits=12, decimal_places=2)
    due_date = models.DateField()
    payment_date = models.DateField(blank=True, null=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        db_table = 'loan_payments'
        ordering = ['payment_number']
        unique_together = ['loan_application', 'payment_number']
    
    def __str__(self):
        return f"Payment {self.payment_number} for Loan {self.loan_application.id}"
    
    
    
class GenderChoices(models.TextChoices):
    MALE   = 'Male',   'Male'
    FEMALE = 'Female', 'Female'
    OTHER  = 'Other',  'Other'


class MaritalStatusChoices(models.TextChoices):
    SINGLE   = 'Single',   'Single'
    MARRIED  = 'Married',  'Married'
    WIDOWED  = 'Widowed',  'Widowed'
    DIVORCED = 'Divorced', 'Divorced'


class ReligionChoices(models.TextChoices):
    HINDU     = 'Hindu',     'Hindu'
    MUSLIM    = 'Muslim',    'Muslim'
    CHRISTIAN = 'Christian', 'Christian'
    SIKH      = 'Sikh',      'Sikh'
    BUDDHIST  = 'Buddhist',  'Buddhist'
    JAIN      = 'Jain',      'Jain'
    OTHER     = 'Other',     'Other'


class CasteChoices(models.TextChoices):
    GENERAL = 'General', 'General'
    OBC     = 'OBC',     'OBC'
    SC      = 'SC',      'SC'
    ST      = 'ST',      'ST'


class OccupationChoices(models.TextChoices):
    SALARIED_GOVT      = 'Salaried - Government',        'Salaried - Government'
    SALARIED_PRIVATE   = 'Salaried - Private',           'Salaried - Private'
    SELF_EMPLOYED_BIZ  = 'Self Employed - Business',     'Self Employed - Business'
    SELF_EMPLOYED_PROF = 'Self Employed - Professional', 'Self Employed - Professional'
    AGRICULTURIST      = 'Agriculturist',                'Agriculturist'
    HOUSEWIFE          = 'Housewife',                    'Housewife'
    RETIRED            = 'Retired',                      'Retired'
    STUDENT            = 'Student',                      'Student'
    OTHER              = 'Other',                        'Other'


class ResidenceTypeChoices(models.TextChoices):
    OWNED            = 'Owned',            'Owned'
    RENTED           = 'Rented',           'Rented'
    FAMILY_OWNED     = 'Family Owned',     'Family Owned'
    COMPANY_PROVIDED = 'Company Provided', 'Company Provided'
    OTHERS           = 'Others',           'Others'


class IDProofTypeChoices(models.TextChoices):
    AADHAAR         = 'aadhaar',        'Aadhaar Card'
    PAN             = 'pan',            'PAN Card'
    VOTER_ID        = 'voterId',        'Voter ID Card'
    DRIVING_LICENSE = 'drivingLicense', 'Driving License'
    PASSPORT        = 'passport',       'Passport'
    NREGS           = 'nregs',          'NREGS Job Card'
    OTHER           = 'other',          'Other Government ID'


class OrnamentTypeChoices(models.TextChoices):
    NECKLACE = 'Necklace / Chain', 'Necklace / Chain'
    BANGLES  = 'Bangles / Kadas',  'Bangles / Kadas'
    RING     = 'Ring',             'Ring'
    EARRINGS = 'Earrings',         'Earrings'
    ANKLET   = 'Anklet',           'Anklet'
    COIN_BAR = 'Coin / Bar',       'Coin / Bar'
    BISCUIT  = 'Biscuit',          'Biscuit'
    PENDANT  = 'Pendant',          'Pendant'
    OTHER    = 'Other',            'Other'


class GoldPurityChoices(models.TextChoices):
    K24 = '24', '24 Karat (99.9%)'
    K22 = '22', '22 Karat (91.6%)'
    K20 = '20', '20 Karat (83.3%)'
    K18 = '18', '18 Karat (75%)'
    K14 = '14', '14 Karat (58.3%)'


class LoanTenureChoices(models.TextChoices):
    D30 = '30d', '30 Days'
    D60 = '60d', '60 Days'
    D90 = '90d', '90 Days'
    M6  = '6m',  '6 Months'
    M12 = '12m', '12 Months'
    M24 = '24m', '24 Months'
    M36 = '36m', '36 Months'


class RepaymentModeChoices(models.TextChoices):
    LUMP_SUM      = 'lumpSum',      'Lump Sum'
    EMI           = 'emi',          'EMI (Monthly)'
    INTEREST_ONLY = 'interestOnly', 'Interest Only'
    ON_MATURITY   = 'onMaturity',   'On Maturity'


class InterestFrequencyChoices(models.TextChoices):
    MONTHLY     = 'monthly',    'Monthly'
    QUARTERLY   = 'quarterly',  'Quarterly'
    AT_MATURITY = 'atMaturity', 'At Maturity'


class LoanPurposeChoices(models.TextChoices):
    BUSINESS_WORKING_CAPITAL = 'Business Working Capital',   'Business Working Capital'
    MEDICAL_EMERGENCY        = 'Medical Emergency',          'Medical Emergency'
    EDUCATION                = 'Education',                  'Education'
    AGRICULTURAL_NEEDS       = 'Agricultural Needs',         'Agricultural Needs'
    HOME_RENOVATION          = 'Home Renovation',            'Home Renovation'
    MARRIAGE                 = 'Marriage / Functions',       'Marriage / Functions'
    PERSONAL                 = 'Personal / Household Needs', 'Personal / Household Needs'
    REPAYMENT                = 'Repayment of Other Loans',   'Repayment of Other Loans'
    OTHER                    = 'Other',                      'Other'


class AccountTypeChoices(models.TextChoices):
    SAVINGS   = 'Savings',   'Savings'
    CURRENT   = 'Current',   'Current'
    OVERDRAFT = 'Overdraft', 'Overdraft'


class DisbursementModeChoices(models.TextChoices):
    NEFT_RTGS    = 'NEFT / RTGS to Bank Account', 'NEFT / RTGS to Bank Account'
    DEMAND_DRAFT = 'Demand Draft',                'Demand Draft'
    CASH         = 'Cash (up to ₹20,000)',         'Cash (up to ₹20,000)'


class LoanStatusChoices(models.TextChoices):
    PENDING      = 'pending',      'Pending'
    UNDER_REVIEW = 'under_review', 'Under Review'
    APPROVED     = 'approved',     'Approved'
    REJECTED     = 'rejected',     'Rejected'
    DISBURSED    = 'disbursed',    'Disbursed'
    CLOSED       = 'closed',       'Closed'


class NomineeRelationshipChoices(models.TextChoices):
    SPOUSE   = 'Spouse',   'Spouse'
    SON      = 'Son',      'Son'
    DAUGHTER = 'Daughter', 'Daughter'
    FATHER   = 'Father',   'Father'
    MOTHER   = 'Mother',   'Mother'
    BROTHER  = 'Brother',  'Brother'
    SISTER   = 'Sister',   'Sister'
    OTHER    = 'Other',    'Other'


# ──────────────────────────────────────────────────────────────────────────────
# GOLD LOAN APPLICATION  ← was: LoanApplication
# ──────────────────────────────────────────────────────────────────────────────

class GoldLoanApplication(models.Model):                          # FIX 1: renamed from LoanApplication
    """
    Stores the complete 8-step gold loan application submitted via the frontend.
    Pledged ornaments are stored separately in PledgedOrnament (FK → here).
    """

    user = models.ForeignKey(
        User,
        on_delete=models.CASCADE,
        related_name='gold_loan_applications',                    # FIX 1b: related_name updated
    )

    # ── SECTION 1: Personal Details ──────────────────────────────────────────
    photo_url          = models.URLField(blank=True, null=True)
    applicant_name     = models.CharField(max_length=255)
    father_spouse_name = models.CharField(max_length=255)
    mother_name        = models.CharField(max_length=255, blank=True, default='')
    date_of_birth      = models.DateField()
    gender             = models.CharField(max_length=10, choices=GenderChoices.choices)
    marital_status     = models.CharField(max_length=20, choices=MaritalStatusChoices.choices, blank=True, default='')
    nationality        = models.CharField(max_length=100, default='Indian')
    religion           = models.CharField(max_length=50, choices=ReligionChoices.choices, blank=True, default='')
    caste              = models.CharField(max_length=20, choices=CasteChoices.choices, blank=True, default='')
    occupation         = models.CharField(max_length=60, choices=OccupationChoices.choices)
    annual_income      = models.CharField(max_length=30, blank=True, default='')
    mobile_number      = models.CharField(max_length=10)
    alternate_phone    = models.CharField(max_length=10, blank=True, default='')
    email_id           = models.EmailField()

    # ── SECTION 2: Permanent Address ─────────────────────────────────────────
    perm_house_street      = models.CharField(max_length=500)
    perm_area_village_town = models.CharField(max_length=255, blank=True, default='')
    perm_district          = models.CharField(max_length=100)
    perm_state             = models.CharField(max_length=100)
    perm_pincode           = models.CharField(max_length=6)
    years_at_address       = models.PositiveSmallIntegerField(null=True, blank=True)
    residence_type         = models.CharField(max_length=30, choices=ResidenceTypeChoices.choices, blank=True, default='')

    # ── SECTION 2: Communication Address ─────────────────────────────────────
    comm_same_as_permanent = models.BooleanField(default=True)
    comm_house_street      = models.CharField(max_length=500, blank=True, default='')
    comm_area_village_town = models.CharField(max_length=255, blank=True, default='')
    comm_district          = models.CharField(max_length=100, blank=True, default='')
    comm_state             = models.CharField(max_length=100, blank=True, default='')
    comm_pincode           = models.CharField(max_length=6,   blank=True, default='')

    # ── SECTION 3: KYC ───────────────────────────────────────────────────────
    aadhaar_number       = models.CharField(max_length=14,  blank=True, default='')
    pan_number           = models.CharField(max_length=10,  blank=True, default='')
    id_proof_type        = models.CharField(max_length=30,  choices=IDProofTypeChoices.choices)
    id_number            = models.CharField(max_length=100)
    address_proof_type   = models.CharField(max_length=60,  blank=True, default='')
    address_proof_number = models.CharField(max_length=100, blank=True, default='')
    kyc_verified         = models.BooleanField(default=False)

    # ── SECTION 4: Gold Totals (computed from PledgedOrnaments) ──────────────
    gold_valuation_date   = models.DateField(null=True, blank=True)
    valuator_name         = models.CharField(max_length=255, blank=True, default='')
    total_gross_weight    = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total_net_weight      = models.DecimalField(max_digits=10, decimal_places=2, default=0)
    total_estimated_value = models.DecimalField(max_digits=14, decimal_places=2, default=0)

    # ── SECTION 5: Loan Details ───────────────────────────────────────────────
    loan_amount                = models.DecimalField(max_digits=12, decimal_places=2)
    loan_tenure                = models.CharField(max_length=10, choices=LoanTenureChoices.choices)
    repayment_mode             = models.CharField(max_length=20, choices=RepaymentModeChoices.choices, default='lumpSum')
    interest_payment_frequency = models.CharField(max_length=20, choices=InterestFrequencyChoices.choices, default='monthly')
    loan_purpose               = models.CharField(max_length=60, choices=LoanPurposeChoices.choices)
    processing_fee_consent     = models.BooleanField(default=False)

    # ── SECTION 6: Bank Details ───────────────────────────────────────────────
    account_holder_name = models.CharField(max_length=255, blank=True, default='')
    bank_name           = models.CharField(max_length=255)
    branch_name         = models.CharField(max_length=255, blank=True, default='')
    account_number      = models.CharField(max_length=30)
    ifsc_code           = models.CharField(max_length=11)
    account_type        = models.CharField(max_length=20, choices=AccountTypeChoices.choices, blank=True, default='')
    disbursement_mode   = models.CharField(max_length=40, choices=DisbursementModeChoices.choices)

    # ── SECTION 6: Nominee ────────────────────────────────────────────────────
    nominee_name         = models.CharField(max_length=255)
    nominee_relationship = models.CharField(max_length=20, choices=NomineeRelationshipChoices.choices)
    nominee_age          = models.PositiveSmallIntegerField(null=True, blank=True)
    nominee_phone        = models.CharField(max_length=10, blank=True, default='')

    # ── SECTION 7 & 8: Declarations ──────────────────────────────────────────
    declaration    = models.BooleanField(default=False)
    terms_accepted = models.BooleanField(default=False)
    data_consent   = models.BooleanField(default=False)

    # ── STATUS (admin-managed) ────────────────────────────────────────────────
    status            = models.CharField(max_length=20, choices=LoanStatusChoices.choices, default=LoanStatusChoices.PENDING)
    admin_remarks     = models.TextField(blank=True, default='')
    sanctioned_amount = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    interest_rate     = models.DecimalField(max_digits=5,  decimal_places=2, null=True, blank=True)

    # ── TIMESTAMPS ────────────────────────────────────────────────────────────
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'gold_loan_applications'                       # FIX 1c: db_table updated
        ordering = ['-created_at']
        indexes  = [
            models.Index(fields=['status']),
            models.Index(fields=['user', 'status']),
            models.Index(fields=['mobile_number']),
            models.Index(fields=['aadhaar_number']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"{self.applicant_name} — ₹{self.loan_amount} ({self.get_status_display()})"

    @property
    def reference_number(self) -> str:
        return f"GL{self.created_at.strftime('%Y%m%d')}{self.id:05d}"


# ──────────────────────────────────────────────────────────────────────────────
# PLEDGED ORNAMENT  ← was: GoldItem
# ──────────────────────────────────────────────────────────────────────────────

class PledgedOrnament(models.Model):                              # FIX 2: renamed from GoldItem
    """
    Each individual gold ornament pledged as security for a GoldLoanApplication.
    Net weight is always recomputed as gross_weight − stone_weight on save.
    """

    gold_loan_application = models.ForeignKey(                    # FIX 2b: FK field name updated
        GoldLoanApplication,
        on_delete=models.CASCADE,
        related_name='pledged_ornaments',                         # FIX 2c: related_name matches views
    )
    ornament_description = models.CharField(max_length=500)
    ornament_type        = models.CharField(max_length=30, choices=OrnamentTypeChoices.choices, blank=True, default='')
    no_of_pieces         = models.PositiveSmallIntegerField(default=1)
    gross_weight         = models.DecimalField(max_digits=8, decimal_places=2)
    stone_weight         = models.DecimalField(max_digits=8, decimal_places=2, default=0)
    net_weight           = models.DecimalField(max_digits=8, decimal_places=2)
    purity               = models.CharField(max_length=5, choices=GoldPurityChoices.choices)
    estimated_value      = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)

    class Meta:
        db_table = 'gold_loan_pledged_ornaments'                  # FIX 2d: db_table updated

    def __str__(self):
        return f"{self.ornament_description} ({self.net_weight}g @ {self.purity}K)"

    def save(self, *args, **kwargs):
        # Always recompute net weight: gross − stone
        self.net_weight = max(0, float(self.gross_weight) - float(self.stone_weight))
        super().save(*args, **kwargs)