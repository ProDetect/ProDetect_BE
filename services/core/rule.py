from solar import Table, ColumnDetails
from typing import Optional, List, Dict
from datetime import datetime
import uuid

class Rule(Table):
    __tablename__ = "rules"
    
    id: uuid.UUID = ColumnDetails(default_factory=uuid.uuid4, primary_key=True)
    
    # Rule Identification
    rule_name: str
    rule_code: str  # Unique code for the rule (e.g., AML-001, STRUCT-001)
    rule_type: str  # transaction_monitoring, customer_screening, behavioral_analysis
    category: str  # aml, fraud, compliance, kyc
    
    # Rule Definition
    description: str
    business_justification: str
    regulatory_reference: Optional[str] = None  # CBN regulation reference
    
    # Rule Logic
    conditions: Dict = {}  # JSON object defining rule conditions
    thresholds: Dict = {}  # Threshold values for triggering
    parameters: Dict = {}  # Configurable parameters
    
    # Scope and Applicability
    applies_to: str = "all"  # all, individuals, corporates, specific_segments
    customer_segments: List[str]  # If applies to specific segments
    transaction_types: List[str]  # Types of transactions this rule monitors
    channels: List[str]  # Channels where rule applies (mobile, web, atm, etc.)
    
    # Risk Settings
    risk_weight: float = 1.0  # Multiplier for risk scoring
    severity_level: str = "medium"  # low, medium, high, critical
    alert_priority: int = 3  # 1-5 scale for generated alerts
    
    # Status and Lifecycle
    status: str = "draft"  # draft, testing, active, inactive, deprecated
    version: str = "1.0"
    effective_date: Optional[datetime] = None
    expiry_date: Optional[datetime] = None
    
    # Testing and Validation
    test_results: Dict = {}  # Results from rule testing
    false_positive_rate: Optional[float] = None
    effectiveness_score: Optional[float] = None
    last_tested: Optional[datetime] = None
    
    # Configuration
    auto_approve: bool = False  # Auto-approve low-risk matches
    requires_review: bool = True  # Requires human review
    escalation_threshold: Optional[float] = None  # Auto-escalate above this score
    
    # Frequency and Limits
    execution_frequency: str = "real_time"  # real_time, batch_hourly, batch_daily
    max_alerts_per_day: Optional[int] = None  # Limit alerts to prevent flooding
    cooling_period: Optional[int] = None  # Minutes before re-triggering for same customer
    
    # Performance Metrics
    total_triggers: int = 0
    true_positives: int = 0
    false_positives: int = 0
    alerts_generated: int = 0
    cases_created: int = 0
    strs_filed: int = 0
    
    # Monitoring
    last_triggered: Optional[datetime] = None
    performance_reviewed: Optional[datetime] = None
    tuning_required: bool = False
    
    # Documentation
    implementation_notes: Optional[str] = None
    known_limitations: Optional[str] = None
    related_rules: List[uuid.UUID]  # Other rules that work together
    
    # Compliance
    regulatory_approval: bool = False
    approved_by: Optional[uuid.UUID] = None
    approval_date: Optional[datetime] = None
    compliance_notes: Optional[str] = None
    
    # System Information
    rule_engine_version: Optional[str] = None
    code_implementation: Optional[str] = None  # Actual rule code/logic
    dependencies: List[str]  # External data sources or systems required
    
    # Audit
    created_at: datetime = ColumnDetails(default_factory=datetime.now)
    updated_at: datetime = ColumnDetails(default_factory=datetime.now)
    created_by: uuid.UUID
    last_modified_by: Optional[uuid.UUID] = None