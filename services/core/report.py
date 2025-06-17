from solar import Table, ColumnDetails
from typing import Optional, List, Dict
from datetime import datetime
import uuid

class Report(Table):
    __tablename__ = "reports"
    
    id: uuid.UUID = ColumnDetails(default_factory=uuid.uuid4, primary_key=True)
    
    # Report Identification
    report_number: str  # Unique report identifier
    report_type: str  # STR, CTR, SAR, etc.
    report_category: str  # suspicious_transaction, currency_transaction, suspicious_activity
    
    # Related Entities
    case_id: Optional[uuid.UUID] = None  # Related case
    customer_id: uuid.UUID  # Primary customer
    related_customers: List[uuid.UUID]  # Additional involved customers
    transaction_ids: List[uuid.UUID]  # Transactions being reported
    alert_ids: List[uuid.UUID]  # Alerts that led to this report
    
    # Report Content
    title: str
    narrative: str  # Detailed description of suspicious activity
    summary: str  # Executive summary
    
    # Regulatory Information
    regulatory_authority: str = "NFIU"  # NFIU, CBN, EFCC, etc.
    regulatory_reference: Optional[str] = None  # Reference number from authority
    filing_requirement: str  # mandatory, voluntary, follow_up
    
    # Report Details
    suspicious_activity_type: str  # structuring, money_laundering, terrorism_financing, etc.
    activity_description: str
    timeline_of_events: str
    total_amount: float
    currency: str = "NGN"
    
    # Parties Involved
    subject_information: Dict = {}  # Primary subject details
    involved_parties: List[Dict] = []  # Other parties involved
    financial_institutions: List[Dict] = []  # Other banks/institutions involved
    
    # Supporting Evidence
    supporting_documents: List[str]  # File references or descriptions
    evidence_summary: str
    investigation_notes: str
    
    # Status and Workflow
    status: str = "draft"  # draft, review, approved, filed, acknowledged
    prepared_by: uuid.UUID  # Report preparer
    reviewed_by: Optional[uuid.UUID] = None  # Reviewer
    approved_by: Optional[uuid.UUID] = None  # Final approver
    
    # Timing
    incident_date_from: datetime  # Start of suspicious activity period
    incident_date_to: datetime  # End of suspicious activity period
    detection_date: datetime  # When suspicious activity was detected
    
    # Filing Information
    filed: bool = False
    filing_date: Optional[datetime] = None
    filing_method: Optional[str] = None  # electronic, paper, portal
    filing_reference: Optional[str] = None  # Authority reference number
    filed_by: Optional[uuid.UUID] = None
    
    # Authority Response
    acknowledged: bool = False
    acknowledgment_date: Optional[datetime] = None
    acknowledgment_reference: Optional[str] = None
    
    # Follow-up
    follow_up_required: bool = False
    follow_up_requests: List[Dict] = []  # Additional information requests
    supplementary_reports: List[uuid.UUID]  # Additional reports filed
    
    # Quality Assurance
    qa_reviewed: bool = False
    qa_reviewer: Optional[uuid.UUID] = None
    qa_notes: Optional[str] = None
    qa_approved: bool = False
    
    # Legal and Compliance
    legal_reviewed: bool = False
    legal_reviewer: Optional[uuid.UUID] = None
    legal_notes: Optional[str] = None
    privilege_claimed: bool = False
    
    # Export and Formatting
    export_format: str = "XML"  # XML, PDF, JSON as per NFIU requirements
    export_version: Optional[str] = None
    export_data: Optional[Dict] = None  # Formatted export data
    
    # Performance Metrics
    preparation_time: Optional[int] = None  # Hours taken to prepare
    review_time: Optional[int] = None  # Hours taken to review
    approval_time: Optional[int] = None  # Hours taken to approve
    
    # Metadata
    confidentiality_level: str = "confidential"
    retention_period: int = 5  # Years to retain (CBN requirement)
    tags: List[str]  # For categorization
    
    # System Information
    template_version: Optional[str] = None
    generation_method: str = "manual"  # manual, semi_automated, automated
    
    # Audit
    created_at: datetime = ColumnDetails(default_factory=datetime.now)
    updated_at: datetime = ColumnDetails(default_factory=datetime.now)
    created_by: uuid.UUID