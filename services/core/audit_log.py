from solar import Table, ColumnDetails
from typing import Optional, Dict
from datetime import datetime
import uuid

class AuditLog(Table):
    __tablename__ = "audit_logs"
    
    id: uuid.UUID = ColumnDetails(default_factory=uuid.uuid4, primary_key=True)
    
    # Event Identification
    event_id: str  # Unique event identifier
    event_type: str  # user_action, system_event, data_change, alert_generated, etc.
    event_category: str  # authentication, transaction, case_management, reporting, system
    
    # User Information
    user_id: Optional[uuid.UUID] = None  # User who performed the action
    user_email: Optional[str] = None  # Email of the user
    user_role: Optional[str] = None  # Role at time of action
    impersonated_by: Optional[uuid.UUID] = None  # If action was impersonated
    
    # Action Details
    action: str  # login, logout, create, update, delete, view, export, approve, etc.
    resource_type: str  # customer, transaction, alert, case, rule, report, etc.
    resource_id: Optional[uuid.UUID] = None  # ID of the affected resource
    resource_identifier: Optional[str] = None  # Human-readable identifier
    
    # Context Information
    description: str  # Human-readable description of the action
    details: Dict = {}  # Additional structured details
    
    # System Information
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    
    # Before/After State (for data changes)
    old_values: Optional[Dict] = None  # Previous state
    new_values: Optional[Dict] = None  # New state
    changed_fields: Optional[Dict] = None  # Fields that changed
    
    # Risk and Security
    risk_score: Optional[float] = None  # Risk score of the action
    security_flags: Optional[Dict] = None  # Security-related flags
    suspicious_activity: bool = False
    
    # Compliance
    regulatory_significance: bool = False  # Whether this affects compliance
    retention_period: int = 5  # Years to retain (CBN requirement)
    data_classification: str = "internal"  # public, internal, confidential, restricted
    
    # Processing Information
    processing_time: Optional[float] = None  # Time taken to process (milliseconds)
    status: str = "success"  # success, failure, partial, timeout
    error_message: Optional[str] = None
    error_code: Optional[str] = None
    
    # Geographic Information
    country: Optional[str] = None
    region: Optional[str] = None
    timezone: Optional[str] = None
    
    # Workflow Context
    workflow_id: Optional[str] = None  # If part of a workflow
    workflow_step: Optional[str] = None  # Step in the workflow
    parent_event_id: Optional[uuid.UUID] = None  # Parent event if this is a sub-event
    
    # Data Access
    data_accessed: Optional[Dict] = None  # What data was accessed
    export_format: Optional[str] = None  # If data was exported
    records_affected: Optional[int] = None  # Number of records affected
    
    # Timing
    timestamp: datetime = ColumnDetails(default_factory=datetime.now)
    event_date: datetime = ColumnDetails(default_factory=datetime.now)
    
    # Metadata
    tags: Optional[Dict] = None  # Additional tags for categorization
    correlation_id: Optional[str] = None  # For correlating related events
    
    # System Metadata
    application_version: Optional[str] = None
    environment: str = "production"  # production, staging, development
    server_name: Optional[str] = None
    
    # Compliance Flags
    requires_review: bool = False
    reviewed: bool = False
    reviewed_by: Optional[uuid.UUID] = None
    review_date: Optional[datetime] = None
    review_notes: Optional[str] = None