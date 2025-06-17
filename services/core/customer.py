from solar import Table, ColumnDetails
from typing import Optional, List, Dict
from datetime import datetime
import uuid

class Customer(Table):
    __tablename__ = "customers"
    
    id: uuid.UUID = ColumnDetails(default_factory=uuid.uuid4, primary_key=True)
    user_id: uuid.UUID  # Reference to Solar auth user
    
    # Basic Information
    first_name: str
    last_name: str
    email: str
    phone: str
    date_of_birth: datetime
    nationality: str
    
    # KYC Information
    customer_id: str  # Bank's internal customer ID
    bvn: Optional[str] = None  # Bank Verification Number
    nin: Optional[str] = None  # National Identification Number
    kyc_status: str = "pending"  # pending, verified, rejected
    kyc_level: str = "tier1"  # tier1, tier2, tier3
    
    # Address Information
    address_line1: str
    address_line2: Optional[str] = None
    city: str
    state: str
    country: str
    postal_code: Optional[str] = None
    
    # Risk Assessment
    risk_score: float = 0.0  # 0-100 scale
    risk_category: str = "low"  # low, medium, high
    pep_status: bool = False  # Politically Exposed Person
    sanctions_checked: bool = False
    last_risk_assessment: Optional[datetime] = None
    
    # Account Information
    account_numbers: List[str]  # Multiple accounts possible
    account_types: List[str]  # savings, current, loan, etc.
    account_opening_date: datetime
    customer_since: datetime
    
    # Behavioral Flags
    suspicious_activity_count: int = 0
    last_transaction_date: Optional[datetime] = None
    average_monthly_turnover: float = 0.0
    
    # Compliance Flags
    is_blacklisted: bool = False
    blacklist_reason: Optional[str] = None
    requires_enhanced_dd: bool = False  # Enhanced Due Diligence
    
    # Metadata
    created_at: datetime = ColumnDetails(default_factory=datetime.now)
    updated_at: datetime = ColumnDetails(default_factory=datetime.now)
    created_by: uuid.UUID  # User who created the record