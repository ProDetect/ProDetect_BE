from solar import Table, ColumnDetails
from typing import Optional, List, Dict
from datetime import datetime
import uuid

class Case(Table):
    __tablename__ = "cases"
    
    id: uuid.UUID = ColumnDetails(default_factory=uuid.uuid4, primary_key=True)
    
    # Case Identification
    case_number: str  # Unique case identifier (e.g., CASE-2024-001)
    case_type: str  # suspicious_activity, kyc_review, sanctions_investigation
    case_category: str  # aml, fraud, compliance, regulatory
    
    # Related Entities
    customer_id: uuid.UUID  # Primary customer under investigation
    related_customers: List[uuid.UUID]  # Other involved customers
    alert_ids: List[uuid.UUID]  # Alerts that triggered this case
    transaction_ids: List[uuid.UUID]  # Transactions under investigation
    
    # Case Details
    title: str
    description: str
    summary: Optional[str] = None  # Executive summary
    
    # Priority and Risk
    priority: int = 3  # 1-5 scale (1 = highest priority)
    risk_level: str = "medium"  # low, medium, high, critical
    complexity: str = "standard"  # simple, standard, complex
    
    # Investigation Status
    status: str = "open"  # open, investigating, pending_review, escalated, closed
    investigation_stage: str = "initial"  # initial, evidence_gathering, analysis, decision, reporting
    
    # Assignment and Workflow
    assigned_to: uuid.UUID  # Primary investigator
    reviewer: Optional[uuid.UUID] = None  # Senior reviewer
    approver: Optional[uuid.UUID] = None  # Final approver for actions
    team_members: List[uuid.UUID]  # Additional team members
    
    # Timing and SLA
    opened_at: datetime = ColumnDetails(default_factory=datetime.now)
    assigned_at: Optional[datetime] = None
    investigation_started_at: Optional[datetime] = None
    review_started_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    
    # SLA Management
    sla_deadline: Optional[datetime] = None
    sla_extended: bool = False
    sla_extension_reason: Optional[str] = None
    sla_breached: bool = False
    
    # Investigation Progress
    investigation_notes: str = ""
    evidence_collected: Dict = {}  # Documents, screenshots, data exports
    interviews_conducted: List[Dict] = []  # Customer interactions
    external_inquiries: List[Dict] = []  # Queries to other institutions
    
    # Analysis and Findings
    findings: Optional[str] = None
    recommendations: Optional[str] = None
    risk_assessment: Optional[str] = None
    regulatory_implications: bool = False
    
    # Decision and Actions
    decision: Optional[str] = None  # no_action, continue_monitoring, file_str, close_account, escalate
    actions_taken: List[str]  # List of actions performed
    
    # Regulatory Reporting
    str_required: bool = False  # Suspicious Transaction Report required
    str_filed: bool = False
    str_reference: Optional[str] = None
    str_filed_date: Optional[datetime] = None
    
    ctr_required: bool = False  # Currency Transaction Report required
    ctr_filed: bool = False
    ctr_reference: Optional[str] = None
    ctr_filed_date: Optional[datetime] = None
    
    # External Reporting
    reported_to_authorities: bool = False
    authority_reference: Optional[str] = None
    authority_response: Optional[str] = None
    
    # Quality Assurance
    qa_reviewed: bool = False
    qa_reviewer: Optional[uuid.UUID] = None
    qa_notes: Optional[str] = None
    qa_approved: bool = False
    
    # Closure
    closure_reason: Optional[str] = None  # resolved, false_positive, insufficient_evidence, regulatory_action
    closure_notes: Optional[str] = None
    closed_by: Optional[uuid.UUID] = None
    
    # Follow-up
    follow_up_required: bool = False
    follow_up_date: Optional[datetime] = None
    follow_up_notes: Optional[str] = None
    
    # Metadata
    tags: List[str]  # For categorization and search
    confidentiality_level: str = "internal"  # internal, restricted, confidential
    
    # Audit
    created_at: datetime = ColumnDetails(default_factory=datetime.now)
    updated_at: datetime = ColumnDetails(default_factory=datetime.now)
    created_by: uuid.UUID