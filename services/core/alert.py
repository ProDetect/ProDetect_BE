from solar import Table, ColumnDetails
from typing import Optional, List, Dict
from datetime import datetime
import uuid

class Alert(Table):
    __tablename__ = "alerts"
    
    id: uuid.UUID = ColumnDetails(default_factory=uuid.uuid4, primary_key=True)
    
    # Alert Identification
    alert_id: str  # Unique alert identifier
    alert_type: str  # transaction_monitoring, kyc_update, sanctions_hit, etc.
    alert_category: str  # aml, fraud, compliance, operational
    
    # Related Entities
    customer_id: uuid.UUID  # Reference to Customer table
    transaction_id: Optional[uuid.UUID] = None  # Reference to Transaction table
    rule_id: Optional[uuid.UUID] = None  # Reference to Rule that triggered alert
    
    # Alert Details
    title: str
    description: str
    severity: str = "medium"  # low, medium, high, critical
    priority: int = 3  # 1-5 scale (1 = highest priority)
    
    # Risk Assessment
    risk_score: float = 0.0  # 0-100 scale
    risk_factors: List[str]  # List of contributing risk factors
    
    # Alert Content
    triggered_rules: List[str]  # Names of rules that triggered the alert
    threshold_values: Dict = {}  # Actual vs threshold values
    pattern_matched: Optional[str] = None  # Pattern or typology matched
    
    # Investigation Status
    status: str = "open"  # open, investigating, escalated, closed, false_positive
    assigned_to: Optional[uuid.UUID] = None  # User assigned for investigation
    investigation_notes: Optional[str] = None
    
    # Case Management
    case_id: Optional[uuid.UUID] = None  # Reference to Case if escalated
    escalation_level: int = 1  # 1-3 (1=analyst, 2=senior, 3=compliance_officer)
    
    # Timing
    triggered_at: datetime = ColumnDetails(default_factory=datetime.now)
    acknowledged_at: Optional[datetime] = None
    investigated_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    
    # Resolution
    resolution: Optional[str] = None  # closed_no_action, false_positive, escalated_to_case, reported_to_authorities
    resolution_notes: Optional[str] = None
    resolved_by: Optional[uuid.UUID] = None
    
    # Compliance Tracking
    sla_deadline: Optional[datetime] = None  # When alert must be resolved
    sla_breached: bool = False
    regulatory_significance: bool = False  # Whether this could lead to regulatory reporting
    
    # Additional Data
    evidence: Dict = {}  # Supporting evidence and documentation
    external_references: List[str]  # References to external systems or reports
    related_alerts: List[uuid.UUID]  # Other related alerts
    
    # System Information
    detection_method: str  # rule_based, ml_model, manual, external_feed
    model_version: Optional[str] = None  # If ML model was used
    confidence_score: Optional[float] = None  # Model confidence (0-1)
    
    # Audit
    created_at: datetime = ColumnDetails(default_factory=datetime.now)
    updated_at: datetime = ColumnDetails(default_factory=datetime.now)
    created_by: Optional[uuid.UUID] = None