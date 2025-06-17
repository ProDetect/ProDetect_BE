from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uuid
import json

from core.report import Report
from core.case import Case
from core.customer import Customer
from core.transaction import Transaction
from core.alert import Alert
from core.audit_log import AuditLog
from solar.access import User, authenticated

@authenticated
def create_str_report(
    user: User,
    case_id: uuid.UUID,
    narrative: str,
    suspicious_activity_type: str,
    activity_description: str,
    timeline_of_events: str,
    incident_date_from: datetime,
    incident_date_to: datetime
) -> Report:
    \"\"\"Create a Suspicious Transaction Report (STR).\"\"\"
    
    # Get case information
    case_results = Case.sql(
        "SELECT * FROM cases WHERE id = %(case_id)s",
        {"case_id": case_id}
    )
    
    if not case_results:
        raise ValueError("Case not found")
    
    case = Case(**case_results[0])
    
    # Get customer information
    customer_results = Customer.sql(
        "SELECT * FROM customers WHERE id = %(customer_id)s",
        {"customer_id": case.customer_id}
    )
    
    if not customer_results:
        raise ValueError("Customer not found")
    
    customer = Customer(**customer_results[0])
    
    # Get related transactions
    transaction_results = Transaction.sql(
        \"\"\"SELECT * FROM transactions WHERE id = ANY(%(transaction_ids)s)\"\"\",
        {"transaction_ids": case.transaction_ids}
    )
    
    transactions = [Transaction(**txn) for txn in transaction_results]
    total_amount = sum(txn.amount for txn in transactions)
    
    # Generate report number
    report_number = generate_report_number("STR")
    
    # Prepare subject information
    subject_info = {
        "customer_id": customer.customer_id,
        "full_name": f"{customer.first_name} {customer.last_name}",
        "email": customer.email,
        "phone": customer.phone,
        "date_of_birth": customer.date_of_birth.isoformat(),
        "nationality": customer.nationality,
        "bvn": customer.bvn,
        "nin": customer.nin,
        "address": {
            "line1": customer.address_line1,
            "line2": customer.address_line2,
            "city": customer.city,
            "state": customer.state,
            "country": customer.country,
            "postal_code": customer.postal_code
        },
        "account_numbers": customer.account_numbers,
        "risk_score": customer.risk_score,
        "pep_status": customer.pep_status
    }
    
    # Create STR report
    report = Report(
        report_number=report_number,
        report_type="STR",
        report_category="suspicious_transaction",
        case_id=case_id,
        customer_id=case.customer_id,
        related_customers=case.related_customers,
        transaction_ids=case.transaction_ids,
        alert_ids=case.alert_ids,
        title=f"Suspicious Transaction Report - {customer.first_name} {customer.last_name}",
        narrative=narrative,
        summary=f"STR filed for {suspicious_activity_type} involving {len(transactions)} transactions totaling {total_amount:,.2f} NGN",
        suspicious_activity_type=suspicious_activity_type,
        activity_description=activity_description,
        timeline_of_events=timeline_of_events,
        total_amount=total_amount,
        subject_information=subject_info,
        incident_date_from=incident_date_from,
        incident_date_to=incident_date_to,
        detection_date=datetime.now(),
        prepared_by=user.id,
        evidence_summary=prepare_evidence_summary(case, transactions),
        investigation_notes=case.investigation_notes or "",
        created_by=user.id
    )
    
    report.sync()
    
    # Update case to indicate STR required and created
    Case.sql(
        \"\"\"UPDATE cases 
           SET str_required = true, str_filed = false, updated_at = %(now)s
           WHERE id = %(case_id)s\"\"\",
        {"case_id": case_id, "now": datetime.now()}
    )
    
    # Log STR creation
    log_audit_event(
        user_id=user.id,
        event_type="str_report_created",
        action="create",
        resource_type="report",
        resource_id=report.id,
        description=f"STR report {report.report_number} created for case {case.case_number}",
        details={"case_id": str(case_id), "total_amount": total_amount}
    )
    
    return report

@authenticated
def create_ctr_report(
    user: User,
    customer_id: uuid.UUID,
    transaction_ids: List[uuid.UUID],
    reporting_period_start: datetime,
    reporting_period_end: datetime
) -> Report:
    \"\"\"Create a Currency Transaction Report (CTR).\"\"\"
    
    # Get customer information
    customer_results = Customer.sql(
        "SELECT * FROM customers WHERE id = %(customer_id)s",
        {"customer_id": customer_id}
    )
    
    if not customer_results:
        raise ValueError("Customer not found")
    
    customer = Customer(**customer_results[0])
    
    # Get transactions above CTR threshold
    transaction_results = Transaction.sql(
        \"\"\"SELECT * FROM transactions 
           WHERE id = ANY(%(transaction_ids)s) 
           AND above_ctr_threshold = true\"\"\",
        {"transaction_ids": transaction_ids}
    )
    
    transactions = [Transaction(**txn) for txn in transaction_results]
    total_amount = sum(txn.amount for txn in transactions)
    
    if not transactions:
        raise ValueError("No CTR-eligible transactions found")
    
    # Generate report number
    report_number = generate_report_number("CTR")
    
    # Prepare subject information
    subject_info = {
        "customer_id": customer.customer_id,
        "full_name": f"{customer.first_name} {customer.last_name}",
        "email": customer.email,
        "phone": customer.phone,
        "date_of_birth": customer.date_of_birth.isoformat(),
        "nationality": customer.nationality,
        "address": {
            "line1": customer.address_line1,
            "line2": customer.address_line2,
            "city": customer.city,
            "state": customer.state,
            "country": customer.country
        },
        "account_numbers": customer.account_numbers
    }
    
    # Create CTR report
    report = Report(
        report_number=report_number,
        report_type="CTR",
        report_category="currency_transaction",
        customer_id=customer_id,
        transaction_ids=transaction_ids,
        title=f"Currency Transaction Report - {customer.first_name} {customer.last_name}",
        narrative=f"Currency transactions above reporting threshold for period {reporting_period_start.date()} to {reporting_period_end.date()}",
        summary=f"CTR for {len(transactions)} transactions totaling {total_amount:,.2f} NGN",
        suspicious_activity_type="currency_transaction",
        activity_description=f"Large currency transactions requiring regulatory reporting",
        timeline_of_events=f"Transactions occurred between {reporting_period_start.date()} and {reporting_period_end.date()}",
        total_amount=total_amount,
        subject_information=subject_info,
        incident_date_from=reporting_period_start,
        incident_date_to=reporting_period_end,
        detection_date=datetime.now(),
        prepared_by=user.id,
        filing_requirement="mandatory",
        created_by=user.id
    )
    
    report.sync()
    
    # Log CTR creation
    log_audit_event(
        user_id=user.id,
        event_type="ctr_report_created",
        action="create",
        resource_type="report",
        resource_id=report.id,
        description=f"CTR report {report.report_number} created for customer {customer.customer_id}",
        details={"customer_id": str(customer_id), "total_amount": total_amount, "transaction_count": len(transactions)}
    )
    
    return report

@authenticated
def review_report(user: User, report_id: uuid.UUID, review_notes: str, approved: bool) -> Report:
    \"\"\"Review a report before filing.\"\"\"
    
    # Get report
    report_results = Report.sql(
        "SELECT * FROM reports WHERE id = %(report_id)s",
        {"report_id": report_id}
    )
    
    if not report_results:
        raise ValueError("Report not found")
    
    report = Report(**report_results[0])
    
    # Update review status
    report.status = "approved" if approved else "review"
    report.reviewed_by = user.id
    report.qa_reviewed = True
    report.qa_reviewer = user.id
    report.qa_notes = review_notes
    report.qa_approved = approved
    report.updated_at = datetime.now()
    
    report.sync()
    
    # Log review
    log_audit_event(
        user_id=user.id,
        event_type="report_reviewed",
        action="review",
        resource_type="report",
        resource_id=report.id,
        description=f"Report {report.report_number} reviewed - {'Approved' if approved else 'Rejected'}",
        details={"approved": approved, "review_notes": review_notes}
    )
    
    return report

@authenticated
def file_report_with_authorities(user: User, report_id: uuid.UUID, filing_method: str = "electronic") -> Report:
    \"\"\"File a report with regulatory authorities.\"\"\"
    
    # Get report
    report_results = Report.sql(
        "SELECT * FROM reports WHERE id = %(report_id)s",
        {"report_id": report_id}
    )
    
    if not report_results:
        raise ValueError("Report not found")
    
    report = Report(**report_results[0])
    
    if not report.qa_approved:
        raise ValueError("Report must be approved before filing")
    
    # Generate export data based on NFIU requirements
    export_data = generate_nfiu_export_data(report)
    
    # Simulate filing with authorities (in real implementation, integrate with NFIU API)
    filing_reference = f"NFIU-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8]}"
    
    # Update report
    report.filed = True
    report.filing_date = datetime.now()
    report.filing_method = filing_method
    report.filing_reference = filing_reference
    report.filed_by = user.id
    report.status = "filed"
    report.export_data = export_data
    report.updated_at = datetime.now()
    
    report.sync()
    
    # Update related case if STR
    if report.case_id and report.report_type == "STR":
        Case.sql(
            \"\"\"UPDATE cases 
               SET str_filed = true, str_reference = %(reference)s, str_filed_date = %(date)s
               WHERE id = %(case_id)s\"\"\",
            {
                "case_id": report.case_id,
                "reference": filing_reference,
                "date": datetime.now()
            }
        )
    
    # Log filing
    log_audit_event(
        user_id=user.id,
        event_type="report_filed",
        action="file",
        resource_type="report",
        resource_id=report.id,
        description=f"Report {report.report_number} filed with {report.regulatory_authority}",
        details={"filing_reference": filing_reference, "filing_method": filing_method}
    )
    
    return report

@authenticated
def get_pending_reports(user: User, report_type: Optional[str] = None) -> List[Report]:
    \"\"\"Get reports pending review or filing.\"\"\"
    
    query = \"SELECT * FROM reports WHERE status IN ('draft', 'review', 'approved') AND filed = false\"
    params = {}
    
    if report_type:
        query += " AND report_type = %(report_type)s"
        params["report_type"] = report_type
    
    query += " ORDER BY created_at DESC"
    
    results = Report.sql(query, params)
    reports = [Report(**result) for result in results]
    
    # Log access
    log_audit_event(
        user_id=user.id,
        event_type="pending_reports_accessed",
        action="view",
        resource_type="report",
        description=f"Accessed {len(reports)} pending reports",
        records_affected=len(reports)
    )
    
    return reports

@authenticated
def get_filed_reports(user: User, days: int = 30) -> List[Report]:
    \"\"\"Get recently filed reports.\"\"\"
    
    results = Report.sql(
        \"\"\"SELECT * FROM reports 
           WHERE filed = true 
           AND filing_date >= %(start_date)s
           ORDER BY filing_date DESC\"\"\",
        {"start_date": datetime.now() - timedelta(days=days)}
    )
    
    reports = [Report(**result) for result in results]
    
    # Log access
    log_audit_event(
        user_id=user.id,
        event_type="filed_reports_accessed",
        action="view",
        resource_type="report",
        description=f"Accessed {len(reports)} filed reports from last {days} days",
        records_affected=len(reports)
    )
    
    return reports

@authenticated
def generate_compliance_statistics(user: User, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
    \"\"\"Generate compliance statistics for reporting period.\"\"\"
    
    # STR statistics
    str_stats = Report.sql(
        \"\"\"SELECT COUNT(*) as total_strs, 
                  COUNT(CASE WHEN filed = true THEN 1 END) as filed_strs,
                  AVG(EXTRACT(EPOCH FROM (filing_date - created_at))/3600) as avg_filing_time_hours
           FROM reports 
           WHERE report_type = 'STR' 
           AND created_at BETWEEN %(start_date)s AND %(end_date)s\"\"\",
        {"start_date": start_date, "end_date": end_date}
    )
    
    # CTR statistics
    ctr_stats = Report.sql(
        \"\"\"SELECT COUNT(*) as total_ctrs,
                  COUNT(CASE WHEN filed = true THEN 1 END) as filed_ctrs
           FROM reports 
           WHERE report_type = 'CTR' 
           AND created_at BETWEEN %(start_date)s AND %(end_date)s\"\"\",
        {"start_date": start_date, "end_date": end_date}
    )
    
    # Alert statistics
    alert_stats = Alert.sql(
        \"\"\"SELECT COUNT(*) as total_alerts,
                  COUNT(CASE WHEN case_id IS NOT NULL THEN 1 END) as escalated_alerts,
                  AVG(risk_score) as avg_risk_score
           FROM alerts 
           WHERE triggered_at BETWEEN %(start_date)s AND %(end_date)s\"\"\",
        {"start_date": start_date, "end_date": end_date}
    )
    
    # Case statistics
    case_stats = Case.sql(
        \"\"\"SELECT COUNT(*) as total_cases,
                  COUNT(CASE WHEN status = 'closed' THEN 1 END) as closed_cases,
                  COUNT(CASE WHEN sla_breached = true THEN 1 END) as sla_breached_cases
           FROM cases 
           WHERE created_at BETWEEN %(start_date)s AND %(end_date)s\"\"\",
        {"start_date": start_date, "end_date": end_date}
    )
    
    statistics = {
        "reporting_period": {
            "start_date": start_date.isoformat(),
            "end_date": end_date.isoformat()
        },
        "str_reports": str_stats[0] if str_stats else {},
        "ctr_reports": ctr_stats[0] if ctr_stats else {},
        "alerts": alert_stats[0] if alert_stats else {},
        "cases": case_stats[0] if case_stats else {},
        "generated_at": datetime.now().isoformat()
    }
    
    # Log statistics generation
    log_audit_event(
        user_id=user.id,
        event_type="compliance_statistics_generated",
        action="generate",
        resource_type="report",
        description=f"Compliance statistics generated for period {start_date.date()} to {end_date.date()}",
        details=statistics
    )
    
    return statistics

def generate_report_number(report_type: str) -> str:
    \"\"\"Generate a unique report number.\"\"\"
    year = datetime.now().year
    month = datetime.now().month
    
    # Get count of reports of this type this month
    count_result = Report.sql(
        \"\"\"SELECT COUNT(*) as count FROM reports 
           WHERE report_type = %(report_type)s
           AND EXTRACT(YEAR FROM created_at) = %(year)s 
           AND EXTRACT(MONTH FROM created_at) = %(month)s\"\"\",
        {"report_type": report_type, "year": year, "month": month}
    )
    
    count = count_result[0]["count"] + 1 if count_result else 1
    
    return f"{report_type}-{year}{month:02d}-{count:04d}"

def prepare_evidence_summary(case: Case, transactions: List[Transaction]) -> str:
    \"\"\"Prepare evidence summary for report.\"\"\"
    
    evidence_points = []
    
    # Transaction evidence
    evidence_points.append(f"Analysis of {len(transactions)} transactions")
    
    total_amount = sum(txn.amount for txn in transactions)
    evidence_points.append(f"Total transaction amount: {total_amount:,.2f} NGN")
    
    # Suspicious patterns
    suspicious_count = len([txn for txn in transactions if txn.is_suspicious])
    if suspicious_count > 0:
        evidence_points.append(f"{suspicious_count} transactions flagged as suspicious")
    
    # Additional evidence from case
    if case.evidence_collected:
        evidence_points.append(f"{len(case.evidence_collected)} pieces of additional evidence collected")
    
    if case.interviews_conducted:
        evidence_points.append(f"{len(case.interviews_conducted)} customer interviews conducted")
    
    return "; ".join(evidence_points)

def generate_nfiu_export_data(report: Report) -> Dict[str, Any]:
    \"\"\"Generate export data in NFIU-compliant format.\"\"\"
    
    # This would be the actual NFIU XML/JSON format in production
    export_data = {
        "report_header": {
            "report_number": report.report_number,
            "report_type": report.report_type,
            "filing_institution": "ProDetect Bank",
            "filing_date": report.filing_date.isoformat() if report.filing_date else None,
            "reporting_period": {
                "from": report.incident_date_from.isoformat(),
                "to": report.incident_date_to.isoformat()
            }
        },
        "subject_information": report.subject_information,
        "transaction_details": {
            "transaction_count": len(report.transaction_ids),
            "total_amount": report.total_amount,
            "currency": report.currency
        },
        "narrative": report.narrative,
        "suspicious_activity": {
            "type": report.suspicious_activity_type,
            "description": report.activity_description
        },
        "compliance_officer": {
            "prepared_by": str(report.prepared_by),
            "reviewed_by": str(report.reviewed_by) if report.reviewed_by else None,
            "approved_by": str(report.approved_by) if report.approved_by else None
        }
    }
    
    return export_data

def log_audit_event(
    user_id: uuid.UUID,
    event_type: str,
    action: str,
    resource_type: str,
    description: str,
    resource_id: Optional[uuid.UUID] = None,
    details: Optional[Dict] = None,
    records_affected: Optional[int] = None
):
    \"\"\"Log an audit event for compliance tracking.\"\"\"
    
    audit_log = AuditLog(
        event_id=str(uuid.uuid4()),
        event_type=event_type,
        event_category="reporting",
        user_id=user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        description=description,
        details=details or {},
        records_affected=records_affected,
        regulatory_significance=True
    )
    
    audit_log.sync()