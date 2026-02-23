from decimal import Decimal

from rest_framework import serializers
from .models import GoldLoanApplication, PledgedOrnament, User, Notification, Agreement, LoanApplication, LoanPayment
import bcrypt


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model"""
    
    class Meta:
        model = User
        fields = [
            'id', 'first_name', 'last_name', 'email', 'mobile_number',
            'role', 'profile_img', 'address', 'state', 'is_active',
            'created_at', 'updated_at', 'last_active',  
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']
        extra_kwargs = {
            'password': {'write_only': True, 'required': False}
        }

        
    def update(self, instance, validated_data):
        password = validated_data.pop('password', None)
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        if password:
            instance.set_password(password)
        instance.save()
        return instance

class UserCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating users"""
    
    password = serializers.CharField(write_only=True, required=True)
    
    class Meta:
        model = User
        fields = [
            'id','first_name', 'last_name', 'email', 'mobile_number',
            'password', 'role', 'profile_img', 'address', 'state'
        ]
    
    def create(self, validated_data):
        password = validated_data.pop('password')
        user = User(**validated_data)
        user.set_password(password)
        user.save()
        return user


class NotificationSerializer(serializers.ModelSerializer):
    """Serializer for Notification model"""
    
    class Meta:
        model = Notification
        fields = ['id', 'user', 'title', 'summary', 'read', 'created_at']
        read_only_fields = ['id', 'created_at']


class AgreementSerializer(serializers.ModelSerializer):
    """Serializer for Agreement model"""
    
    class Meta:
        model = Agreement
        fields = [
            'id', 'template_url', 'user_name', 'user_phone',
            'status', 'signed_pdf_url', 'signed_at', 'created_at'
        ]
        read_only_fields = ['id', 'created_at']


class LoanPaymentSerializer(serializers.ModelSerializer):
    """Serializer for Loan Payment model"""
    
    class Meta:
        model = LoanPayment
        fields = [
            'id', 'loan_application', 'payment_number', 'payment_amount',
            'due_date', 'payment_date', 'status', 'created_at', 'updated_at'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']


class LoanApplicationSerializer(serializers.ModelSerializer):
    """Serializer for Loan Application model"""
    
    user_details = UserSerializer(source='user', read_only=True)
    payments = LoanPaymentSerializer(many=True, read_only=True)
    
    class Meta:
        model = LoanApplication
        fields = [
            'id', 'user', 'user_details', 'applicant_name', 'son_daughter_wife_of',
            'gender', 'date_of_birth', 'address_line1', 'address_line2', 'address_line3',
            'aadhaar_number', 'pan_number', 'bank_details', 'mobile_number',
            'alternate_mobile', 'email_id', 'photo_url', 'loan_sanction_date',
            'loan_amount', 'rate_of_interest', 'interest_type', 'loan_tenure',
            'tenure_type', 'first_payment_date', 'first_week_amount',
            'last_week_payment_date', 'last_week_amount', 'total_repayment_amount',
            'borrower_signature', 'applicant_signature', 'status',
            'created_at', 'updated_at', 'payments'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'user_details', 'payments']


class LoanApplicationCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating loan applications"""
    gender = serializers.CharField(required=False, allow_null=True)

    class Meta:
        model = LoanApplication
        fields = [
            'applicant_name',
            'son_daughter_wife_of',
            'gender',
            'date_of_birth',
            'address_line1',
            'address_line2',
            'address_line3',
            'aadhaar_number',
            'pan_number',
            'bank_details',
            'mobile_number',
            'alternate_mobile',
            'email_id',
            'photo_url',
            'loan_sanction_date',
            'loan_amount',
            'rate_of_interest',
            'interest_type',
            'loan_tenure',
            'tenure_type',
            'first_payment_date',
            'first_week_amount',
            'borrower_signature',
            'applicant_signature',
        ]

    # --------------------------
    # Field Validations
    # --------------------------

    def validate_gender(self, value):
        if value:
            value = value.lower()
            valid_choices = [choice[0] for choice in LoanApplication.GENDER_CHOICES]
            if value not in valid_choices:
                raise serializers.ValidationError("Invalid gender value.")
        return value

    # --------------------------
    # Create Logic
    # --------------------------

    def create(self, validated_data):
        loan_amount = validated_data['loan_amount']
        rate = validated_data['rate_of_interest']
        tenure = validated_data['loan_tenure']
        tenure_type = validated_data.get('tenure_type', 'months')
        interest_type = validated_data.get('interest_type', 'percentage')

        # Convert tenure to months
        tenure_in_months = tenure
        if tenure_type == 'years':
            tenure_in_months = tenure * 12
        elif tenure_type == 'weeks':
            tenure_in_months = (tenure + 3) // 4  # Ceiling division

        # Convert to Decimal (financial safety)
        loan_amount = Decimal(loan_amount)
        rate = Decimal(rate)
        tenure_in_months = Decimal(tenure_in_months)

        # Calculate total repayment
        if interest_type == 'percentage':
            tenure_in_years = tenure_in_months / Decimal(12)
            interest_amount = (loan_amount * rate * tenure_in_years) / Decimal(100)
            total_repayment = loan_amount + interest_amount
        else:  # fixed
            total_interest = (loan_amount / Decimal(100)) * rate * tenure_in_months
            total_repayment = loan_amount + total_interest

        validated_data['total_repayment_amount'] = total_repayment

        return super().create(validated_data)
    
    

class GoldItemSerializer(serializers.ModelSerializer):
    """Read serializer for gold items — includes computed net_weight."""

    class Meta:
        model  = PledgedOrnament
        fields = [
            'id',
            'ornament_description',
            'ornament_type',
            'no_of_pieces',
            'gross_weight',
            'stone_weight',
            'net_weight',
            'purity',
            'estimated_value',
        ]


class GoldItemCreateSerializer(serializers.ModelSerializer):
    """Write serializer for creating gold items (nested inside loan creation)."""

    # Allow frontend to send string floats e.g. "22.50"
    gross_weight  = serializers.DecimalField(max_digits=8, decimal_places=2)
    stone_weight  = serializers.DecimalField(max_digits=8, decimal_places=2, default=0)
    net_weight    = serializers.DecimalField(max_digits=8, decimal_places=2, required=False)
    estimated_value = serializers.DecimalField(max_digits=12, decimal_places=2, required=False, allow_null=True)

    class Meta:
        model  = PledgedOrnament
        fields = [
            'ornament_description',
            'ornament_type',
            'no_of_pieces',
            'gross_weight',
            'stone_weight',
            'net_weight',
            'purity',
            'estimated_value',
        ]

    def validate(self, attrs):
        gross = float(attrs.get('gross_weight', 0))
        stone = float(attrs.get('stone_weight', 0))
        if stone > gross:
            raise serializers.ValidationError(
                {'stone_weight': 'Stone weight cannot exceed gross weight.'}
            )
        # Always recompute net weight from gross - stone
        attrs['net_weight'] = round(max(0, gross - stone), 2)
        return attrs


# ──────────────────────────────────────────────────────────────────────────────
# LOAN APPLICATION READ SERIALIZER
# ──────────────────────────────────────────────────────────────────────────────

class GoldLoanApplicationSerializer(serializers.ModelSerializer):
    """
    Full read serializer — used in GET responses.
    Nests all gold items and adds computed / display fields.
    """

    gold_items        = GoldItemSerializer(many=True, read_only=True)
    reference_number  = serializers.CharField(read_only=True)
    status_display    = serializers.CharField(source='get_status_display', read_only=True)

    # Flatten nested address into camelCase for frontend compatibility
    permanent_address = serializers.SerializerMethodField()
    communication_address = serializers.SerializerMethodField()
    bank_details      = serializers.SerializerMethodField()
    nominee_details   = serializers.SerializerMethodField()

    class Meta:
        model  = GoldLoanApplication
        fields = [
            # meta
            'id', 'reference_number', 'status', 'status_display',
            'admin_remarks', 'sanctioned_amount', 'interest_rate',
            'created_at', 'updated_at',

            # section 1
            'photo_url', 'applicant_name', 'father_spouse_name', 'mother_name',
            'date_of_birth', 'gender', 'marital_status', 'nationality',
            'religion', 'caste', 'occupation', 'annual_income',
            'mobile_number', 'alternate_phone', 'email_id',

            # section 2
            'permanent_address', 'communication_address',
            'years_at_address', 'residence_type',

            # section 3
            'aadhaar_number', 'pan_number', 'id_proof_type', 'id_number',
            'address_proof_type', 'address_proof_number', 'kyc_verified',

            # section 4
            'gold_items', 'gold_valuation_date', 'valuator_name',
            'total_gross_weight', 'total_net_weight', 'total_estimated_value',

            # section 5
            'loan_amount', 'loan_tenure', 'repayment_mode',
            'interest_payment_frequency', 'loan_purpose', 'processing_fee_consent',

            # section 6
            'bank_details', 'nominee_details', 'disbursement_mode',

            # section 7/8
            'declaration', 'terms_accepted', 'data_consent',
        ]

    def get_permanent_address(self, obj):
        return {
            'houseStreet':      obj.perm_house_street,
            'areaVillageTown':  obj.perm_area_village_town,
            'district':         obj.perm_district,
            'state':            obj.perm_state,
            'pincode':          obj.perm_pincode,
        }

    def get_communication_address(self, obj):
        return {
            'sameAsPermanent': obj.comm_same_as_permanent,
            'houseStreet':     obj.comm_house_street,
            'areaVillageTown': obj.comm_area_village_town,
            'district':        obj.comm_district,
            'state':           obj.comm_state,
            'pincode':         obj.comm_pincode,
        }

    def get_bank_details(self, obj):
        return {
            'accountHolderName': obj.account_holder_name,
            'bankName':          obj.bank_name,
            'branchName':        obj.branch_name,
            'accountNumber':     obj.account_number,
            'ifscCode':          obj.ifsc_code,
            'accountType':       obj.account_type,
        }

    def get_nominee_details(self, obj):
        return {
            'nomineeName':  obj.nominee_name,
            'relationship': obj.nominee_relationship,
            'nomineeAge':   obj.nominee_age,
            'nomineePhone': obj.nominee_phone,
        }


# ──────────────────────────────────────────────────────────────────────────────
# LOAN APPLICATION CREATE SERIALIZER
# ──────────────────────────────────────────────────────────────────────────────

class GoldLoanApplicationCreateSerializer(serializers.ModelSerializer):
    """
    Write serializer — accepts the full frontend payload on POST.
    Handles nested gold_items creation in one atomic operation.
    Mirrors the camelCase keys from the React form via source mapping.
    """

    # ── Nested gold items ──────────────────────────────────────────────────────
    gold_items = GoldItemCreateSerializer(many=True)
    
    years_at_address    = serializers.IntegerField(required=False, allow_null=True)
    gold_valuation_date = serializers.DateField(required=False, allow_null=True)
    nominee_age         = serializers.IntegerField(required=False, allow_null=True)

    # ── Permanent address (flat from frontend, mapped to model fields) ─────────
    perm_house_street      = serializers.CharField(max_length=500)
    perm_area_village_town = serializers.CharField(max_length=255, required=False, allow_blank=True, default='')
    perm_district          = serializers.CharField(max_length=100)
    perm_state             = serializers.CharField(max_length=100)
    perm_pincode           = serializers.CharField(max_length=6)

    # ── Communication address ─────────────────────────────────────────────────
    comm_same_as_permanent  = serializers.BooleanField(default=True)
    comm_house_street       = serializers.CharField(max_length=500,  required=False, allow_blank=True, default='')
    comm_area_village_town  = serializers.CharField(max_length=255,  required=False, allow_blank=True, default='')
    comm_district           = serializers.CharField(max_length=100,  required=False, allow_blank=True, default='')
    comm_state              = serializers.CharField(max_length=100,  required=False, allow_blank=True, default='')
    comm_pincode            = serializers.CharField(max_length=6,    required=False, allow_blank=True, default='')

    # ── Bank details ──────────────────────────────────────────────────────────
    account_holder_name = serializers.CharField(max_length=255, required=False, allow_blank=True, default='')
    bank_name           = serializers.CharField(max_length=255)
    branch_name         = serializers.CharField(max_length=255, required=False, allow_blank=True, default='')
    account_number      = serializers.CharField(max_length=30)
    ifsc_code           = serializers.CharField(max_length=11)
    account_type        = serializers.CharField(max_length=20, required=False, allow_blank=True, default='')

    # ── Nominee ───────────────────────────────────────────────────────────────
    nominee_name         = serializers.CharField(max_length=255)
    nominee_relationship = serializers.CharField(max_length=20)
    nominee_age          = serializers.IntegerField(required=False, allow_null=True)
    nominee_phone        = serializers.CharField(max_length=10, required=False, allow_blank=True, default='')

    class Meta:
        model  = GoldLoanApplication
        fields = [
            # section 1
            'photo_url', 'applicant_name', 'father_spouse_name', 'mother_name',
            'date_of_birth', 'gender', 'marital_status', 'nationality',
            'religion', 'caste', 'occupation', 'annual_income',
            'mobile_number', 'alternate_phone', 'email_id',

            # section 2 — permanent
            'perm_house_street', 'perm_area_village_town',
            'perm_district', 'perm_state', 'perm_pincode',
            'years_at_address', 'residence_type',

            # section 2 — communication
            'comm_same_as_permanent', 'comm_house_street', 'comm_area_village_town',
            'comm_district', 'comm_state', 'comm_pincode',

            # section 3
            'aadhaar_number', 'pan_number', 'id_proof_type', 'id_number',
            'address_proof_type', 'address_proof_number',

            # section 4
            'gold_items', 'gold_valuation_date', 'valuator_name',

            # section 5
            'loan_amount', 'loan_tenure', 'repayment_mode',
            'interest_payment_frequency', 'loan_purpose', 'processing_fee_consent',
            'interest_rate',

            # section 6
            'account_holder_name', 'bank_name', 'branch_name',
            'account_number', 'ifsc_code', 'account_type',
            'disbursement_mode',

            # nominee
            'nominee_name', 'nominee_relationship', 'nominee_age', 'nominee_phone',

            # declarations
            'declaration', 'terms_accepted', 'data_consent',
        ]

    # ── Field-level validators ─────────────────────────────────────────────────

    def validate_mobile_number(self, value):
        if not value.isdigit() or len(value) != 10:
            raise serializers.ValidationError('Mobile number must be exactly 10 digits.')
        return value

    def validate_perm_pincode(self, value):
        if not value.isdigit() or len(value) != 6:
            raise serializers.ValidationError('Pincode must be exactly 6 digits.')
        return value

    def validate_pan_number(self, value):
        import re
        if value and not re.match(r'^[A-Z]{5}[0-9]{4}[A-Z]{1}$', value):
            raise serializers.ValidationError('Invalid PAN format. Expected: ABCDE1234F')
        return value.upper() if value else value

    def validate_ifsc_code(self, value):
        import re
        if value and not re.match(r'^[A-Z]{4}0[A-Z0-9]{6}$', value.upper()):
            raise serializers.ValidationError('Invalid IFSC code format.')
        return value.upper()

    def validate_loan_amount(self, value):
        if float(value) < 1000:
            raise serializers.ValidationError('Minimum loan amount is ₹1,000.')
        return value

    def validate_gold_items(self, value):
        if not value:
            raise serializers.ValidationError('At least one gold item is required.')
        return value

    def validate(self, attrs):
        # Declarations must all be True
        if not attrs.get('declaration'):
            raise serializers.ValidationError({'declaration': 'Borrower declaration must be accepted.'})
        if not attrs.get('terms_accepted'):
            raise serializers.ValidationError({'terms_accepted': 'Terms and conditions must be accepted.'})
        if not attrs.get('data_consent'):
            raise serializers.ValidationError({'data_consent': 'Data consent must be given.'})
        return attrs

    def create(self, validated_data):
        from django.db import transaction

        gold_items_data = validated_data.pop('gold_items')

        with transaction.atomic():
            # Compute gold totals before saving
            total_gross = sum(float(i.get('gross_weight', 0)) for i in gold_items_data)
            total_net   = sum(float(i.get('net_weight',   0)) for i in gold_items_data)
            total_value = sum(float(i.get('estimated_value', 0) or 0) for i in gold_items_data)

            loan = GoldLoanApplication.objects.create(
                **validated_data,
                total_gross_weight    = round(total_gross, 2),
                total_net_weight      = round(total_net,   2),
                total_estimated_value = round(total_value, 2),
            )

            PledgedOrnament.objects.bulk_create([
                PledgedOrnament(gold_loan_application=loan, **item)
                for item in gold_items_data
            ])

        return loan