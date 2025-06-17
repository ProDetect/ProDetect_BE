from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uuid

from core.case import Case
from core.alert import Alert
from core.customer import Customer
from core.transaction import Transaction
from core.audit_log import AuditLog
from solar.access import User, authenticated

@authenticated
def create_case_from_alerts(
    user: User,
    alert_ids: List[uuid.UUID],
    case_type: str,
    title: str,
    description: str,
    priority: int = 3
) -> Case:
    \"\"\"Create a new investigation case from one or more alerts.\"\"\"
    
    # Validate alerts exist and get customer info
    alerts = []
    customer_ids = set()
    transaction_ids = []
    
    for alert_id in alert_ids:
        alert_results = Alert.sql(
            "SELECT * FROM alerts WHERE id = %(alert_id)s",
            {"alert_id": alert_id}
        )
        
        if not alert_results:
            raise ValueError(f"Alert {alert_id} not found")
        
        alert = Alert(**alert_results[0])
        alerts.append(alert)
        customer_ids.add(alert.customer_id)
        
        if alert.transaction_id:
            transaction_ids.append(alert.transaction_id)
    
    if len(customer_ids) > 1:
        primary_customer = list(customer_ids)[0]
        related_customers = list(customer_ids)[1:]
    else:
        primary_customer = list(customer_ids)[0]
        related_customers = []
    
    # Generate case number
    case_number = generate_case_number()
    
    # Determine SLA deadline based on priority and type
    sla_deadline = calculate_sla_deadline(priority, case_type)
    
    # Create case
    case = Case(
        case_number=case_number,
        case_type=case_type,
        case_category="aml",
        customer_id=primary_customer,
        related_customers=related_customers,
        alert_ids=alert_ids,
        transaction_ids=transaction_ids,
        title=title,
        description=description,
        priority=priority,
        risk_level=determine_case_risk_level(alerts),
        assigned_to=user.id,
        sla_deadline=sla_deadline,
        investigation_notes="Case created from alerts. Investigation pending.",
        created_by=user.id
    )
    
    case.sync()
    
    # Update alerts to reference this case
    for alert_id in alert_ids:
        Alert.sql(
            \"\"\"UPDATE alerts 
               SET case_id = %(case_id)s, status = 'escalated', escalated_at = %(now)s
               WHERE id = %(alert_id)s\"\"\",
            {
                "case_id": case.id,
                "alert_id": alert_id,
                "now": datetime.now()
            }
        )
    
    # Log case creation
    log_audit_event(
        user_id=user.id,
        event_type="case_created",
        action="create",
        resource_type="case",
        resource_id=case.id,
        description=f"Case {case.case_number} created from {len(alert_ids)} alerts",
        details={"alert_ids": [str(aid) for aid in alert_ids]}
    )
    
    return case

@authenticated
def assign_case(user: User, case_id: uuid.UUID, assigned_to: uuid.UUID, notes: Optional[str] = None) -> Case:
    \"\"\"Assign a case to a different investigator.\"\"\"
    
    # Get case
    case_results = Case.sql(
        "SELECT * FROM cases WHERE id = %(case_id)s",
        {"case_id": case_id}
    )
    
    if not case_results:
        raise ValueError("Case not found")
    
    case = Case(**case_results[0])
    old_assignee = case.assigned_to
    
    # Update assignment
    case.assigned_to = assigned_to
    case.assigned_at = datetime.now()
    case.updated_at = datetime.now()
    
    if notes:
        case.investigation_notes += f"\\n[{datetime.now()}] Assignment change: {notes}"
    
    case.sync()
    
    # Log assignment change
    log_audit_event(
        user_id=user.id,
        event_type="case_assigned",
        action="update",
        resource_type="case",
        resource_id=case.id,
        description=f"Case {case.case_number} reassigned",
        old_values={"assigned_to": str(old_assignee)},
        new_values={"assigned_to": str(assigned_to)}
    )
    
    return case

@authenticated
def update_case_status(
    user: User,
    case_id: uuid.UUID,
    new_status: str,
    notes: Optional[str] = None
) -> Case:
    \"\"\"Update case status and add investigation notes.\"\"\"
    
    # Get case
    case_results = Case.sql(
        "SELECT * FROM cases WHERE id = %(case_id)s",
        {"case_id": case_id}
    )
    
    if not case_results:
        raise ValueError("Case not found")
    
    case = Case(**case_results[0])
    old_status = case.status
    
    # Update status
    case.status = new_status
    case.updated_at = datetime.now()
    
    # Update stage-specific timestamps
    if new_status == "investigating" and not case.investigation_started_at:
        case.investigation_started_at = datetime.now()
    elif new_status == "pending_review" and not case.review_started_at:
        case.review_started_at = datetime.now()
    elif new_status == "closed" and not case.closed_at:
        case.closed_at = datetime.now()
        case.closed_by = user.id
    
    # Add notes
    if notes:
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        case.investigation_notes += f"\\n[{timestamp}] Status changed to {new_status}: {notes}"
    
    case.sync()
    
    # Log status change
    log_audit_event(
        user_id=user.id,
        event_type="case_status_updated",
        action="update",
        resource_type="case",
        resource_id=case.id,
        description=f"Case {case.case_number} status changed from {old_status} to {new_status}",
        old_values={"status": old_status},
        new_values={"status": new_status}
    )
    
    return case

@authenticated
def add_case_evidence(
    user: User,
    case_id: uuid.UUID,
    evidence_type: str,
    evidence_description: str,
    evidence_data: Dict[str, Any]
) -> Case:
    \"\"\"Add evidence to a case investigation.\"\"\"
    
    # Get case
    case_results = Case.sql(
        "SELECT * FROM cases WHERE id = %(case_id)s",
        {"case_id": case_id}
    )
    
    if not case_results:
        raise ValueError("Case not found")
    
    case = Case(**case_results[0])
    
    # Add evidence
    evidence_id = str(uuid.uuid4())
    evidence_entry = {
        "id": evidence_id,
        "type": evidence_type,
        "description": evidence_description,
        "data": evidence_data,
        "added_by": str(user.id),
        "added_at": datetime.now().isoformat()
    }
    
    current_evidence = case.evidence_collected or {}
    current_evidence[evidence_id] = evidence_entry
    
    case.evidence_collected = current_evidence
    case.updated_at = datetime.now()
    
    # Add to investigation notes
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    case.investigation_notes += f"\\n[{timestamp}] Evidence added: {evidence_type} - {evidence_description}"
    
    case.sync()
    
    # Log evidence addition
    log_audit_event(
        user_id=user.id,
        event_type="case_evidence_added",
        action="update",
        resource_type="case",
        resource_id=case.id,
        description=f"Evidence added to case {case.case_number}: {evidence_type}",
        details=evidence_entry
    )
    
    return case

@authenticated
def conduct_customer_interview(
    user: User,
    case_id: uuid.UUID,
    customer_id: uuid.UUID,
    interview_method: str,
    interview_notes: str,
    outcome: str
) -> Case:
    \"\"\"Record a customer interview for a case.\"\"\"
    
    # Get case
    case_results = Case.sql(
        "SELECT * FROM cases WHERE id = %(case_id)s",
        {"case_id": case_id}
    )
    
    if not case_results:
        raise ValueError("Case not found")
    
    case = Case(**case_results[0])
    
    # Add interview record
    interview_record = {
        "id": str(uuid.uuid4()),
        "customer_id": str(customer_id),
        "interviewer": str(user.id),
        "interview_date": datetime.now().isoformat(),
        "method": interview_method,  # phone, email, in_person, video
        "notes": interview_notes,
        "outcome": outcome  # cooperative, uncooperative, no_response, additional_info_needed
    }
    
    current_interviews = case.interviews_conducted or []
    current_interviews.append(interview_record)
    
    case.interviews_conducted = current_interviews
    case.updated_at = datetime.now()
    
    # Add to investigation notes
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    case.investigation_notes += f"\\n[{timestamp}] Customer interview conducted via {interview_method}. Outcome: {outcome}"
    
    case.sync()
    
    # Log interview
    log_audit_event(
        user_id=user.id,
        event_type="customer_interview",
        action="interview",
        resource_type="case",
        resource_id=case.id,
        description=f"Customer interview conducted for case {case.case_number}",
        details=interview_record
    )
    
    return case

@authenticated
def close_case(
    user: User,
    case_id: uuid.UUID,
    closure_reason: str,
    closure_notes: str,
    decision: str,
    actions_taken: List[str]
) -> Case:
    \"\"\"Close a case with final decision and actions.\"\"\"
    
    # Get case
    case_results = Case.sql(
        "SELECT * FROM cases WHERE id = %(case_id)s",
        {"case_id": case_id}
    )
    
    if not case_results:
        raise ValueError("Case not found")
    
    case = Case(**case_results[0])
    
    # Update case closure information
    case.status = "closed"
    case.closed_at = datetime.now()
    case.closed_by = user.id
    case.closure_reason = closure_reason
    case.closure_notes = closure_notes
    case.decision = decision
    case.actions_taken = actions_taken
    case.updated_at = datetime.now()
    
    # Add final notes
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    case.investigation_notes += f"\\n[{timestamp}] Case closed. Decision: {decision}. Reason: {closure_reason}"
    
    case.sync()
    
    # Update related alerts
    for alert_id in case.alert_ids:
        Alert.sql(
            \"\"\"UPDATE alerts 
               SET status = 'closed', resolved_at = %(now)s, resolved_by = %(user_id)s,
                   resolution = %(resolution)s, resolution_notes = %(notes)s
               WHERE id = %(alert_id)s\"\"\",
            {
                "alert_id": alert_id,
                "now": datetime.now(),
                "user_id": user.id,
                "resolution": decision,
                "notes": closure_notes
            }
        )
    
    # Log case closure
    log_audit_event(
        user_id=user.id,
        event_type="case_closed",
        action="close",
        resource_type="case",
        resource_id=case.id,
        description=f"Case {case.case_number} closed with decision: {decision}",
        details={
            "closure_reason": closure_reason,
            "decision": decision,
            "actions_taken": actions_taken
        }
    )
    
    return case

@authenticated
def get_assigned_cases(user: User, status: Optional[str] = None) -> List[Case]:
    \"\"\"Get cases assigned to the current user.\"\"\"
    
    query = \"SELECT * FROM cases WHERE assigned_to = %(user_id)s\"
    params = {"user_id": user.id}
    
    if status:
        query += " AND status = %(status)s"
        params["status"] = status
    
    query += " ORDER BY priority ASC, sla_deadline ASC"
    
    results = Case.sql(query, params)
    cases = [Case(**result) for result in results]
    
    # Log access
    log_audit_event(
        user_id=user.id,
        event_type="assigned_cases_accessed",
        action="view",
        resource_type="case",
        description=f"Accessed {len(cases)} assigned cases",
        records_affected=len(cases)
    )
    
    return cases

@authenticated
def get_overdue_cases(user: User) -> List[Case]:
    \"\"\"Get cases that are past their SLA deadline.\"\"\"
    
    results = Case.sql(
        \"\"\"SELECT * FROM cases 
           WHERE sla_deadline < %(now)s 
           AND status NOT IN ('closed') 
           ORDER BY sla_deadline ASC\"\"\",
        {"now": datetime.now()}
    )
    
    cases = [Case(**result) for result in results]
    
    # Mark as SLA breached
    for case in cases:
        if not case.sla_breached:
            Case.sql(
                "UPDATE cases SET sla_breached = true WHERE id = %(case_id)s",
                {"case_id": case.id}
            )
    
    # Log access
    log_audit_event(
        user_id=user.id,
        event_type="overdue_cases_accessed",
        action="view",
        resource_type="case",
        description=f"Accessed {len(cases)} overdue cases",
        records_affected=len(cases)
    )
    
    return cases

def generate_case_number() -> str:
    \"\"\"Generate a unique case number.\"\"\"
    year = datetime.now().year
    month = datetime.now().month
    
    # Get count of cases this month
    count_result = Case.sql(
        \"\"\"SELECT COUNT(*) as count FROM cases 
           WHERE EXTRACT(YEAR FROM created_at) = %(year)s 
           AND EXTRACT(MONTH FROM created_at) = %(month)s\"\"\",
        {"year": year, "month": month}
    )
    
    count = count_result[0]["count"] + 1 if count_result else 1
    
    return f"CASE-{year}{month:02d}-{count:04d}"

def calculate_sla_deadline(priority: int, case_type: str) -> datetime:
    \"\"\"Calculate SLA deadline based on priority and type.\"\"\"
    
    # SLA hours based on priority
    sla_hours = {
        1: 4,   # Critical - 4 hours
        2: 24,  # High - 1 day
        3: 72,  # Medium - 3 days
        4: 168, # Low - 1 week
        5: 336  # Very Low - 2 weeks
    }
    
    hours = sla_hours.get(priority, 72)
    
    # Adjust for case type
    if case_type in ["sanctions_investigation", "terrorism_financing"]:
        hours = max(4, hours // 2)  # More urgent
    
    return datetime.now() + timedelta(hours=hours)

def determine_case_risk_level(alerts: List[Alert]) -> str:
    \"\"\"Determine case risk level based on associated alerts.\"\"\"
    
    max_risk_score = max(alert.risk_score for alert in alerts)
    alert_count = len(alerts)
    
    if max_risk_score >= 80 or alert_count >= 5:
        return "critical"
    elif max_risk_score >= 60 or alert_count >= 3:
        return "high"
    elif max_risk_score >= 40 or alert_count >= 2:
        return "medium"
    else:
        return "low"

def log_audit_event(
    user_id: uuid.UUID,
    event_type: str,
    action: str,
    resource_type: str,
    description: str,
    resource_id: Optional[uuid.UUID] = None,
    details: Optional[Dict] = None,
    old_values: Optional[Dict] = None,
    new_values: Optional[Dict] = None,
    records_affected: Optional[int] = None
):
    \"\"\"Log an audit event for compliance tracking.\"\"\"
    
    audit_log = AuditLog(
        event_id=str(uuid.uuid4()),
        event_type=event_type,
        event_category="case_management",
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        description=description,
        details=details or {},
        old_values=old_values,
        new_values=new_values,
        records_affected=records_affected,
        regulatory_significance=True
    )
    
    audit_log.sync()