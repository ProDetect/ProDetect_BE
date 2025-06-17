from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uuid

from core.audit_log import AuditLog
from solar.access import User, authenticated

@authenticated
def search_audit_logs(
    user: User,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    event_type: Optional[str] = None,
    event_category: Optional[str] = None,
    user_email: Optional[str] = None,
    resource_type: Optional[str] = None,
    resource_id: Optional[uuid.UUID] = None,
    action: Optional[str] = None,
    limit: int = 100
) -> List[AuditLog]:
    \"\"\"Search audit logs with various filters.\"\"\"
    
    # Build dynamic query
    query = "SELECT * FROM audit_logs WHERE 1=1"
    params = {}
    
    if start_date:
        query += " AND timestamp >= %(start_date)s"
        params["start_date"] = start_date
    
    if end_date:
        query += " AND timestamp <= %(end_date)s"
        params["end_date"] = end_date
    
    if event_type:
        query += " AND event_type = %(event_type)s"
        params["event_type"] = event_type
    
    if event_category:
        query += " AND event_category = %(event_category)s"
        params["event_category"] = event_category
    
    if user_email:
        query += " AND user_email = %(user_email)s"
        params["user_email"] = user_email
    
    if resource_type:
        query += " AND resource_type = %(resource_type)s"
        params["resource_type"] = resource_type
    
    if resource_id:
        query += " AND resource_id = %(resource_id)s"
        params["resource_id"] = resource_id
    
    if action:
        query += " AND action = %(action)s"
        params["action"] = action
    
    query += " ORDER BY timestamp DESC LIMIT %(limit)s"
    params["limit"] = limit
    
    results = AuditLog.sql(query, params)
    audit_logs = [AuditLog(**result) for result in results]
    
    # Log audit search
    search_audit_event(
        user_id=user.id,
        description=f"Audit log search performed with {len([k for k, v in params.items() if v and k != 'limit'])} filters",
        details={
            "filters": {k: str(v) if v else None for k, v in params.items()},
            "results_count": len(audit_logs)
        }
    )
    
    return audit_logs

@authenticated
def get_user_activity_summary(user: User, target_user_id: uuid.UUID, days: int = 30) -> Dict[str, Any]:
    \"\"\"Get activity summary for a specific user.\"\"\"
    
    start_date = datetime.now() - timedelta(days=days)
    
    # Get activity statistics
    activity_stats = AuditLog.sql(
        \"\"\"SELECT 
               event_category,
               action,
               COUNT(*) as count,
               MAX(timestamp) as last_activity
           FROM audit_logs 
           WHERE user_id = %(user_id)s 
           AND timestamp >= %(start_date)s
           GROUP BY event_category, action
           ORDER BY count DESC\"\"\",
        {"user_id": target_user_id, "start_date": start_date}
    )
    
    # Get login statistics
    login_stats = AuditLog.sql(
        \"\"\"SELECT 
               COUNT(CASE WHEN action = 'login' THEN 1 END) as total_logins,
               COUNT(CASE WHEN action = 'logout' THEN 1 END) as total_logouts,
               MAX(CASE WHEN action = 'login' THEN timestamp END) as last_login,
               COUNT(DISTINCT DATE(timestamp)) as active_days
           FROM audit_logs 
           WHERE user_id = %(user_id)s 
           AND timestamp >= %(start_date)s
           AND event_category = 'authentication'\"\"\",
        {"user_id": target_user_id, "start_date": start_date}
    )
    
    # Get high-risk activities
    high_risk_activities = AuditLog.sql(
        \"\"\"SELECT *
           FROM audit_logs 
           WHERE user_id = %(user_id)s 
           AND timestamp >= %(start_date)s
           AND (regulatory_significance = true OR suspicious_activity = true)
           ORDER BY timestamp DESC
           LIMIT 20\"\"\",
        {"user_id": target_user_id, "start_date": start_date}
    )
    
    summary = {
        "user_id": str(target_user_id),
        "analysis_period_days": days,
        "activity_breakdown": activity_stats,
        "login_summary": login_stats[0] if login_stats else {},
        "high_risk_activities": [AuditLog(**activity).__dict__ for activity in high_risk_activities],
        "total_activities": sum(stat["count"] for stat in activity_stats),
        "generated_at": datetime.now().isoformat()
    }
    
    # Log summary generation
    search_audit_event(
        user_id=user.id,
        description=f"User activity summary generated for user {target_user_id}",
        details={"target_user": str(target_user_id), "period_days": days}
    )
    
    return summary

@authenticated
def get_system_activity_report(user: User, days: int = 7) -> Dict[str, Any]:
    \"\"\"Generate system-wide activity report.\"\"\"
    
    start_date = datetime.now() - timedelta(days=days)
    
    # Overall activity statistics
    overall_stats = AuditLog.sql(
        \"\"\"SELECT 
               COUNT(*) as total_events,
               COUNT(DISTINCT user_id) as active_users,
               COUNT(CASE WHEN regulatory_significance = true THEN 1 END) as regulatory_significant_events,
               COUNT(CASE WHEN suspicious_activity = true THEN 1 END) as suspicious_events
           FROM audit_logs 
           WHERE timestamp >= %(start_date)s\"\"\",
        {"start_date": start_date}
    )
    
    # Activity by category
    category_stats = AuditLog.sql(
        \"\"\"SELECT 
               event_category,
               COUNT(*) as event_count,
               COUNT(DISTINCT user_id) as unique_users
           FROM audit_logs 
           WHERE timestamp >= %(start_date)s
           GROUP BY event_category
           ORDER BY event_count DESC\"\"\",
        {"start_date": start_date}
    )
    
    # Daily activity trend
    daily_trend = AuditLog.sql(
        \"\"\"SELECT 
               DATE(timestamp) as activity_date,
               COUNT(*) as event_count,
               COUNT(DISTINCT user_id) as unique_users
           FROM audit_logs 
           WHERE timestamp >= %(start_date)s
           GROUP BY DATE(timestamp)
           ORDER BY activity_date\"\"\",
        {"start_date": start_date}
    )
    
    # Top active users
    top_users = AuditLog.sql(
        \"\"\"SELECT 
               user_id,
               user_email,
               COUNT(*) as activity_count,
               MAX(timestamp) as last_activity
           FROM audit_logs 
           WHERE timestamp >= %(start_date)s
           AND user_id IS NOT NULL
           GROUP BY user_id, user_email
           ORDER BY activity_count DESC
           LIMIT 10\"\"\",
        {"start_date": start_date}
    )
    
    # Failed operations
    failed_operations = AuditLog.sql(
        \"\"\"SELECT 
               action,
               resource_type,
               COUNT(*) as failure_count
           FROM audit_logs 
           WHERE timestamp >= %(start_date)s
           AND status = 'failure'
           GROUP BY action, resource_type
           ORDER BY failure_count DESC\"\"\",
        {"start_date": start_date}
    )
    
    report = {
        "report_period_days": days,
        "generated_at": datetime.now().isoformat(),
        "overall_statistics": overall_stats[0] if overall_stats else {},
        "activity_by_category": category_stats,
        "daily_activity_trend": daily_trend,
        "top_active_users": top_users,
        "failed_operations": failed_operations,
        "report_generated_by": str(user.id)
    }
    
    # Log report generation
    search_audit_event(
        user_id=user.id,
        description=f"System activity report generated for {days} days",
        details={"report_period": days, "total_events": report["overall_statistics"].get("total_events", 0)}
    )
    
    return report

@authenticated
def get_compliance_audit_trail(user: User, resource_type: str, resource_id: uuid.UUID) -> List[AuditLog]:
    \"\"\"Get complete audit trail for a specific resource for compliance purposes.\"\"\"
    
    results = AuditLog.sql(
        \"\"\"SELECT * FROM audit_logs 
           WHERE resource_type = %(resource_type)s 
           AND resource_id = %(resource_id)s
           ORDER BY timestamp ASC\"\"\",
        {"resource_type": resource_type, "resource_id": resource_id}
    )
    
    audit_trail = [AuditLog(**result) for result in results]
    
    # Log audit trail access
    search_audit_event(
        user_id=user.id,
        description=f"Compliance audit trail accessed for {resource_type} {resource_id}",
        details={
            "resource_type": resource_type,
            "resource_id": str(resource_id),
            "trail_entries": len(audit_trail)
        }
    )
    
    return audit_trail

@authenticated
def detect_suspicious_patterns(user: User, days: int = 30) -> Dict[str, Any]:
    \"\"\"Detect suspicious user activity patterns.\"\"\"
    
    start_date = datetime.now() - timedelta(days=days)
    
    # Unusual login times (outside business hours)
    unusual_logins = AuditLog.sql(
        \"\"\"SELECT 
               user_id,
               user_email,
               COUNT(*) as unusual_login_count
           FROM audit_logs 
           WHERE timestamp >= %(start_date)s
           AND action = 'login'
           AND (EXTRACT(HOUR FROM timestamp) < 6 OR EXTRACT(HOUR FROM timestamp) > 22)
           GROUP BY user_id, user_email
           HAVING COUNT(*) > 5
           ORDER BY unusual_login_count DESC\"\"\",
        {"start_date": start_date}
    )
    
    # High volume data access
    high_volume_access = AuditLog.sql(
        \"\"\"SELECT 
               user_id,
               user_email,
               SUM(records_affected) as total_records_accessed
           FROM audit_logs 
           WHERE timestamp >= %(start_date)s
           AND action = 'view'
           AND records_affected IS NOT NULL
           GROUP BY user_id, user_email
           HAVING SUM(records_affected) > 1000
           ORDER BY total_records_accessed DESC\"\"\",
        {"start_date": start_date}
    )
    
    # Failed authentication attempts
    failed_auth_attempts = AuditLog.sql(
        \"\"\"SELECT 
               user_email,
               ip_address,
               COUNT(*) as failed_attempts
           FROM audit_logs 
           WHERE timestamp >= %(start_date)s
           AND event_category = 'authentication'
           AND status = 'failure'
           GROUP BY user_email, ip_address
           HAVING COUNT(*) > 10
           ORDER BY failed_attempts DESC\"\"\",
        {"start_date": start_date}
    )
    
    # Rapid successive operations
    rapid_operations = AuditLog.sql(
        \"\"\"SELECT 
               user_id,
               user_email,
               COUNT(*) as operation_count,
               MIN(timestamp) as first_operation,
               MAX(timestamp) as last_operation
           FROM audit_logs 
           WHERE timestamp >= %(start_date)s
           GROUP BY user_id, user_email, DATE(timestamp), EXTRACT(HOUR FROM timestamp)
           HAVING COUNT(*) > 100
           ORDER BY operation_count DESC\"\"\",
        {"start_date": start_date}
    )
    
    suspicious_patterns = {
        "analysis_period_days": days,
        "unusual_login_times": unusual_logins,
        "high_volume_data_access": high_volume_access,
        "failed_authentication_attempts": failed_auth_attempts,
        "rapid_successive_operations": rapid_operations,
        "detection_timestamp": datetime.now().isoformat()
    }
    
    # Mark suspicious activities
    total_suspicious = (len(unusual_logins) + len(high_volume_access) + 
                       len(failed_auth_attempts) + len(rapid_operations))
    
    if total_suspicious > 0:
        # Create alert for suspicious patterns
        search_audit_event(
            user_id=user.id,
            description=f"Suspicious activity patterns detected: {total_suspicious} potential issues",
            details=suspicious_patterns,
            suspicious_activity=True
        )
    
    return suspicious_patterns

@authenticated
def export_audit_logs(
    user: User,
    start_date: datetime,
    end_date: datetime,
    export_format: str = "json",
    filters: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    \"\"\"Export audit logs for external compliance systems.\"\"\"
    
    # Build query with filters
    query = \"SELECT * FROM audit_logs WHERE timestamp BETWEEN %(start_date)s AND %(end_date)s\"
    params = {"start_date": start_date, "end_date": end_date}
    
    if filters:
        if filters.get("event_category"):
            query += " AND event_category = %(event_category)s"
            params["event_category"] = filters["event_category"]
        
        if filters.get("regulatory_significance"):
            query += " AND regulatory_significance = true"
    
    query += " ORDER BY timestamp"
    
    results = AuditLog.sql(query, params)
    audit_logs = [AuditLog(**result) for result in results]
    
    # Prepare export data
    export_data = {
        "export_metadata": {
            "export_date": datetime.now().isoformat(),
            "exported_by": str(user.id),
            "period_start": start_date.isoformat(),
            "period_end": end_date.isoformat(),
            "format": export_format,
            "total_records": len(audit_logs),
            "filters_applied": filters or {}
        },
        "audit_logs": [log.__dict__ for log in audit_logs]
    }
    
    # Log export activity
    search_audit_event(
        user_id=user.id,
        description=f"Audit logs exported: {len(audit_logs)} records from {start_date.date()} to {end_date.date()}",
        details={
            "export_format": export_format,
            "record_count": len(audit_logs),
            "filters": filters
        },
        regulatory_significance=True
    )
    
    return export_data

def search_audit_event(
    user_id: uuid.UUID,
    description: str,
    details: Optional[Dict] = None,
    suspicious_activity: bool = False
):
    \"\"\"Log an audit search/access event.\"\"\"
    
    audit_log = AuditLog(
        event_id=str(uuid.uuid4()),
        event_type="audit_access",
        event_category="audit_management",
        user_id=user_id,
        action="search",
        resource_type="audit_log",
        description=description,
        details=details or {},
        suspicious_activity=suspicious_activity,
        regulatory_significance=True
    )
    
    audit_log.sync()