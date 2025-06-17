from solar import Table, ColumnDetails
from typing import Optional, Dict
from datetime import datetime
import uuid

class Transaction(Table):
    __tablename__ = "transactions"
    
    id: uuid.UUID = ColumnDetails(default_factory=uuid.uuid4, primary_key=True)
    
    # Transaction Identification
    transaction_id: str  # External system transaction ID
    reference_number: str  # Unique reference for tracking
    batch_id: Optional[str] = None  # For batch transactions
    
    # Basic Transaction Info
    transaction_type: str  # deposit, withdrawal, transfer, remittance, etc.
    transaction_method: str  # card, mobile, internet, atm, branch
    currency: str = "NGN"
    amount: float
    
    # Parties Involved
    customer_id: uuid.UUID  # Reference to Customer table
    account_number: str
    beneficiary_name: Optional[str] = None
    beneficiary_account: Optional[str] = None
    beneficiary_bank: Optional[str] = None
    beneficiary_country: Optional[str] = None
    
    # Transaction Details
    description: str
    purpose_code: Optional[str] = None  # For regulatory reporting
    channel: str  # mobile_app, web, atm, branch, pos
    location: Optional[str] = None  # Transaction location
    ip_address: Optional[str] = None
    device_id: Optional[str] = None
    
    # Timing
    transaction_date: datetime
    value_date: datetime
    processing_date: datetime = ColumnDetails(default_factory=datetime.now)
    
    # Status
    status: str = "pending"  # pending, completed, failed, cancelled, reversed
    failure_reason: Optional[str] = None
    
    # Risk Assessment
    risk_score: float = 0.0  # 0-100 scale
    risk_flags: Dict = {}  # JSON object for various risk indicators
    
    # AML Flags
    is_suspicious: bool = False
    alert_count: int = 0
    structuring_indicator: bool = False  # Breaking large amounts into smaller ones
    velocity_flag: bool = False  # High frequency transactions
    amount_threshold_flag: bool = False  # Above regulatory thresholds
    unusual_pattern_flag: bool = False
    
    # Regulatory Thresholds (CBN specific)
    above_ctr_threshold: bool = False  # Currency Transaction Report threshold
    cross_border: bool = False
    cash_transaction: bool = False
    
    # Additional Data
    metadata: Dict = {}  # Additional transaction-specific data
    external_data: Dict = {}  # Data from external systems
    
    # Audit
    created_at: datetime = ColumnDetails(default_factory=datetime.now)
    updated_at: datetime = ColumnDetails(default_factory=datetime.now)
    processed_by: Optional[uuid.UUID] = None  # System or user who processed