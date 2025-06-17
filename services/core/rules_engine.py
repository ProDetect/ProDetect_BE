from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uuid
import json

from core.rule import Rule
from core.audit_log import AuditLog
from solar.access import User, authenticated

@authenticated
def create_aml_rule(
    user: User,
    rule_name: str,
    rule_code: str,
    rule_type: str,
    category: str,
    description: str,
    business_justification: str,
    conditions: Dict[str, Any],
    thresholds: Dict[str, Any],
    applies_to: str = "all",
    customer_segments: Optional[List[str]] = None,
    transaction_types: Optional[List[str]] = None,
    channels: Optional[List[str]] = None,
    risk_weight: float = 1.0,
    severity_level: str = "medium",
    alert_priority: int = 3,
    regulatory_reference: Optional[str] = None
) -> Rule:
    \"\"\"Create a new AML monitoring rule.\"\"\"
    
    # Validate rule code is unique
    existing_rules = Rule.sql(
        "SELECT COUNT(*) as count FROM rules WHERE rule_code = %(rule_code)s",
        {"rule_code": rule_code}
    )
    
    if existing_rules and existing_rules[0]["count"] > 0:
        raise ValueError(f"Rule code {rule_code} already exists")
    
    # Create rule
    rule = Rule(
        rule_name=rule_name,
        rule_code=rule_code,
        rule_type=rule_type,
        category=category,
        description=description,
        business_justification=business_justification,
        regulatory_reference=regulatory_reference,
        conditions=conditions,
        thresholds=thresholds,
        applies_to=applies_to,
        customer_segments=customer_segments or [],
        transaction_types=transaction_types or [],
        channels=channels or [],
        risk_weight=risk_weight,
        severity_level=severity_level,
        alert_priority=alert_priority,
        status="draft",
        created_by=user.id
    )
    
    rule.sync()
    
    # Log rule creation
    log_audit_event(
        user_id=user.id,
        event_type="rule_created",
        action="create",
        resource_type="rule",
        resource_id=rule.id,
        description=f"AML rule {rule.rule_name} ({rule.rule_code}) created",
        details={"rule_type": rule_type, "category": category}
    )
    
    return rule

@authenticated
def test_rule_against_historical_data(user: User, rule_id: uuid.UUID, test_period_days: int = 30) -> Dict[str, Any]:
    \"\"\"Test a rule against historical transaction data to evaluate effectiveness.\"\"\"
    
    # Get rule
    rule_results = Rule.sql(
        "SELECT * FROM rules WHERE id = %(rule_id)s",
        {"rule_id": rule_id}
    )
    
    if not rule_results:
        raise ValueError("Rule not found")
    
    rule = Rule(**rule_results[0])
    
    # Import required modules for testing
    from core.transaction import Transaction
    from core.customer import Customer
    from core.transaction_monitoring import apply_monitoring_rule
    
    # Get historical transactions for testing
    test_start_date = datetime.now() - timedelta(days=test_period_days)
    
    transactions_query = \"\"\"
        SELECT t.*, c.* FROM transactions t
        JOIN customers c ON t.customer_id = c.id
        WHERE t.transaction_date >= %(start_date)s
    \"\"\"
    
    # Apply rule filters if specified
    params = {"start_date": test_start_date}
    
    if rule.applies_to != "all":
        if rule.customer_segments:
            transactions_query += " AND c.risk_category = ANY(%(segments)s)"
            params["segments"] = rule.customer_segments
    
    if rule.transaction_types:
        transactions_query += " AND t.transaction_type = ANY(%(types)s)"
        params["types"] = rule.transaction_types
    
    if rule.channels:
        transactions_query += " AND t.channel = ANY(%(channels)s)"
        params["channels"] = rule.channels
    
    transactions_query += " ORDER BY t.transaction_date DESC LIMIT 1000"
    
    test_data = Transaction.sql(transactions_query, params)
    
    # Test rule against each transaction
    true_positives = 0
    false_positives = 0
    total_triggers = 0
    
    for row in test_data:
        # Create transaction and customer objects
        transaction = Transaction(**{k: v for k, v in row.items() if k in Transaction.__annotations__})
        customer = Customer(**{k: v for k, v in row.items() if k in Customer.__annotations__})
        
        # Apply rule
        result = apply_monitoring_rule(transaction, customer, rule)
        
        if result["triggered"]:
            total_triggers += 1
            
            # Simple heuristic: if transaction was already marked suspicious, it's likely a true positive
            if transaction.is_suspicious:
                true_positives += 1
            else:
                false_positives += 1
    
    # Calculate metrics
    total_transactions = len(test_data)
    trigger_rate = (total_triggers / total_transactions * 100) if total_transactions > 0 else 0
    false_positive_rate = (false_positives / total_triggers * 100) if total_triggers > 0 else 0
    precision = (true_positives / total_triggers) if total_triggers > 0 else 0
    
    test_results = {
        "test_period_days": test_period_days,
        "total_transactions_tested": total_transactions,
        "total_triggers": total_triggers,
        "true_positives": true_positives,
        "false_positives": false_positives,
        "trigger_rate_percent": round(trigger_rate, 2),
        "false_positive_rate_percent": round(false_positive_rate, 2),
        "precision": round(precision, 3),
        "effectiveness_score": round(precision * (1 - false_positive_rate/100), 3),
        "test_date": datetime.now().isoformat()
    }
    
    # Update rule with test results
    Rule.sql(
        \"\"\"UPDATE rules 
           SET test_results = %(test_results)s, 
               false_positive_rate = %(fpr)s,
               effectiveness_score = %(effectiveness)s,
               last_tested = %(now)s
           WHERE id = %(rule_id)s\"\"\",
        {
            "rule_id": rule_id,
            "test_results": json.dumps(test_results),
            "fpr": false_positive_rate,
            "effectiveness": test_results["effectiveness_score"],
            "now": datetime.now()
        }
    )
    
    # Log testing
    log_audit_event(
        user_id=user.id,
        event_type="rule_tested",
        action="test",
        resource_type="rule",
        resource_id=rule.id,
        description=f"Rule {rule.rule_name} tested against {total_transactions} historical transactions",
        details=test_results
    )
    
    return test_results

@authenticated
def activate_rule(user: User, rule_id: uuid.UUID) -> Rule:
    \"\"\"Activate a rule for production monitoring.\"\"\"
    
    # Get rule
    rule_results = Rule.sql(
        "SELECT * FROM rules WHERE id = %(rule_id)s",
        {"rule_id": rule_id}
    )
    
    if not rule_results:
        raise ValueError("Rule not found")
    
    rule = Rule(**rule_results[0])
    
    if rule.status == "active":
        raise ValueError("Rule is already active")
    
    # Validate rule has been tested
    if not rule.last_tested:
        raise ValueError("Rule must be tested before activation")
    
    # Update rule status
    old_status = rule.status
    rule.status = "active"
    rule.effective_date = datetime.now()
    rule.updated_at = datetime.now()
    rule.last_modified_by = user.id
    
    Rule.sql(
        \"\"\"UPDATE rules 
           SET status = 'active', effective_date = %(now)s, updated_at = %(now)s, last_modified_by = %(user_id)s
           WHERE id = %(rule_id)s\"\"\",
        {"rule_id": rule_id, "now": datetime.now(), "user_id": user.id}
    )
    
    # Log activation
    log_audit_event(
        user_id=user.id,
        event_type="rule_activated",
        action="activate",
        resource_type="rule",
        resource_id=rule.id,
        description=f"Rule {rule.rule_name} activated for production monitoring",
        old_values={"status": old_status},
        new_values={"status": "active"}
    )
    
    return rule

@authenticated
def deactivate_rule(user: User, rule_id: uuid.UUID, reason: str) -> Rule:
    \"\"\"Deactivate a rule from production monitoring.\"\"\"
    
    # Get rule
    rule_results = Rule.sql(
        "SELECT * FROM rules WHERE id = %(rule_id)s",
        {"rule_id": rule_id}
    )
    
    if not rule_results:
        raise ValueError("Rule not found")
    
    rule = Rule(**rule_results[0])
    
    if rule.status != "active":
        raise ValueError("Rule is not currently active")
    
    # Update rule status
    old_status = rule.status
    rule.status = "inactive"
    rule.updated_at = datetime.now()
    rule.last_modified_by = user.id
    
    Rule.sql(
        \"\"\"UPDATE rules 
           SET status = 'inactive', updated_at = %(now)s, last_modified_by = %(user_id)s
           WHERE id = %(rule_id)s\"\"\",
        {"rule_id": rule_id, "now": datetime.now(), "user_id": user.id}
    )
    
    # Log deactivation
    log_audit_event(
        user_id=user.id,
        event_type="rule_deactivated",
        action="deactivate",
        resource_type="rule",
        resource_id=rule.id,
        description=f"Rule {rule.rule_name} deactivated. Reason: {reason}",
        old_values={"status": old_status},
        new_values={"status": "inactive"},
        details={"deactivation_reason": reason}
    )
    
    return rule

@authenticated
def update_rule_thresholds(
    user: User,
    rule_id: uuid.UUID,
    new_thresholds: Dict[str, Any],
    reason: str
) -> Rule:
    \"\"\"Update rule thresholds for fine-tuning.\"\"\"
    
    # Get rule
    rule_results = Rule.sql(
        "SELECT * FROM rules WHERE id = %(rule_id)s",
        {"rule_id": rule_id}
    )
    
    if not rule_results:
        raise ValueError("Rule not found")
    
    rule = Rule(**rule_results[0])
    old_thresholds = rule.thresholds
    
    # Update thresholds
    rule.thresholds = new_thresholds
    rule.updated_at = datetime.now()
    rule.last_modified_by = user.id
    rule.version = increment_version(rule.version)
    rule.tuning_required = False  # Reset tuning flag
    
    Rule.sql(
        \"\"\"UPDATE rules 
           SET thresholds = %(thresholds)s, 
               updated_at = %(now)s, 
               last_modified_by = %(user_id)s,
               version = %(version)s,
               tuning_required = false
           WHERE id = %(rule_id)s\"\"\",
        {
            "rule_id": rule_id,
            "thresholds": json.dumps(new_thresholds),
            "now": datetime.now(),
            "user_id": user.id,
            "version": rule.version
        }
    )
    
    # Log threshold update
    log_audit_event(
        user_id=user.id,
        event_type="rule_thresholds_updated",
        action="update",
        resource_type="rule",
        resource_id=rule.id,
        description=f"Rule {rule.rule_name} thresholds updated. Reason: {reason}",
        old_values={"thresholds": old_thresholds},
        new_values={"thresholds": new_thresholds},
        details={"update_reason": reason}
    )
    
    return rule

@authenticated
def get_active_rules(user: User, rule_type: Optional[str] = None) -> List[Rule]:
    \"\"\"Get all active monitoring rules.\"\"\"
    
    query = "SELECT * FROM rules WHERE status = 'active'"
    params = {}
    
    if rule_type:
        query += " AND rule_type = %(rule_type)s"
        params["rule_type"] = rule_type
    
    query += " ORDER BY rule_code"
    
    results = Rule.sql(query, params)
    rules = [Rule(**result) for result in results]
    
    # Log access
    log_audit_event(
        user_id=user.id,
        event_type="active_rules_accessed",
        action="view",
        resource_type="rule",
        description=f"Accessed {len(rules)} active rules",
        records_affected=len(rules)
    )
    
    return rules

@authenticated
def get_rule_performance_metrics(user: User, rule_id: uuid.UUID, days: int = 30) -> Dict[str, Any]:
    \"\"\"Get performance metrics for a rule over a specified period.\"\"\"
    
    # Get rule
    rule_results = Rule.sql(
        "SELECT * FROM rules WHERE id = %(rule_id)s",
        {"rule_id": rule_id}
    )
    
    if not rule_results:
        raise ValueError("Rule not found")
    
    rule = Rule(**rule_results[0])
    
    # Import Alert for metrics
    from core.alert import Alert
    
    # Get alerts generated by this rule in the specified period
    start_date = datetime.now() - timedelta(days=days)
    
    alert_metrics = Alert.sql(
        \"\"\"SELECT 
               COUNT(*) as total_alerts,
               AVG(risk_score) as avg_risk_score,
               COUNT(CASE WHEN status = 'closed' THEN 1 END) as resolved_alerts,
               COUNT(CASE WHEN resolution = 'false_positive' THEN 1 END) as false_positives,
               COUNT(CASE WHEN case_id IS NOT NULL THEN 1 END) as escalated_alerts
           FROM alerts 
           WHERE rule_id = %(rule_id)s 
           AND triggered_at >= %(start_date)s\"\"\",
        {"rule_id": rule_id, "start_date": start_date}
    )
    
    metrics = alert_metrics[0] if alert_metrics else {}
    
    # Calculate derived metrics
    total_alerts = metrics.get("total_alerts", 0)
    false_positives = metrics.get("false_positives", 0)
    resolved_alerts = metrics.get("resolved_alerts", 0)
    escalated_alerts = metrics.get("escalated_alerts", 0)
    
    false_positive_rate = (false_positives / total_alerts * 100) if total_alerts > 0 else 0
    escalation_rate = (escalated_alerts / total_alerts * 100) if total_alerts > 0 else 0
    resolution_rate = (resolved_alerts / total_alerts * 100) if total_alerts > 0 else 0
    
    performance_metrics = {
        "rule_id": str(rule_id),
        "rule_name": rule.rule_name,
        "rule_code": rule.rule_code,
        "measurement_period_days": days,
        "total_alerts_generated": total_alerts,
        "average_risk_score": round(float(metrics.get("avg_risk_score", 0) or 0), 2),
        "false_positive_count": false_positives,
        "false_positive_rate_percent": round(false_positive_rate, 2),
        "escalated_alerts": escalated_alerts,
        "escalation_rate_percent": round(escalation_rate, 2),
        "resolved_alerts": resolved_alerts,
        "resolution_rate_percent": round(resolution_rate, 2),
        "effectiveness_score": round((1 - false_positive_rate/100) * (escalation_rate/100), 3),
        "requires_tuning": false_positive_rate > 70 or escalation_rate < 10,
        "generated_at": datetime.now().isoformat()
    }
    
    # Update rule performance data
    Rule.sql(
        \"\"\"UPDATE rules 
           SET performance_reviewed = %(now)s,
               tuning_required = %(tuning_required)s
           WHERE id = %(rule_id)s\"\"\",
        {
            "rule_id": rule_id,
            "now": datetime.now(),
            "tuning_required": performance_metrics["requires_tuning"]
        }
    )
    
    # Log metrics access
    log_audit_event(
        user_id=user.id,
        event_type="rule_performance_reviewed",
        action="review",
        resource_type="rule",
        resource_id=rule.id,
        description=f"Performance metrics reviewed for rule {rule.rule_name}",
        details=performance_metrics
    )
    
    return performance_metrics

@authenticated
def create_standard_cbn_rules(user: User) -> List[Rule]:
    \"\"\"Create standard CBN-compliant AML rules.\"\"\"
    
    standard_rules = [
        {
            "rule_name": "High Value Cash Transaction",
            "rule_code": "CBN-CASH-001",
            "rule_type": "transaction_monitoring",
            "category": "aml",
            "description": "Monitor cash transactions above CBN reporting threshold",
            "business_justification": "CBN requires reporting of cash transactions above 5M NGN",
            "regulatory_reference": "CBN AML/CFT Guidelines Section 4.2",
            "conditions": {"amount_threshold": True, "cash_monitoring": True},
            "thresholds": {"amount": 5000000, "cash_amount": 5000000},
            "transaction_types": ["deposit", "withdrawal"],
            "risk_weight": 1.5,
            "severity_level": "high",
            "alert_priority": 2
        },
        {
            "rule_name": "Rapid Transaction Velocity",
            "rule_code": "CBN-VEL-001",
            "rule_type": "transaction_monitoring",
            "category": "aml",
            "description": "Detect rapid succession of transactions indicating possible structuring",
            "business_justification": "High frequency transactions may indicate structuring to avoid reporting",
            "regulatory_reference": "CBN AML/CFT Guidelines Section 3.1",
            "conditions": {"velocity_check": True, "structuring_detection": True},
            "thresholds": {"transaction_count_24h": 20, "amount_24h": 10000000},
            "risk_weight": 1.2,
            "severity_level": "medium",
            "alert_priority": 3
        },
        {
            "rule_name": "Cross-Border High Risk Country",
            "rule_code": "CBN-CB-001",
            "rule_type": "transaction_monitoring",
            "category": "aml",
            "description": "Monitor transactions to/from high-risk countries",
            "business_justification": "Transactions with high-risk jurisdictions require enhanced monitoring",
            "regulatory_reference": "CBN AML/CFT Guidelines Section 5.3",
            "conditions": {"cross_border": True, "high_risk_country": True},
            "thresholds": {"amount": 1000000},
            "risk_weight": 2.0,
            "severity_level": "high",
            "alert_priority": 1
        },
        {
            "rule_name": "PEP Transaction Monitoring",
            "rule_code": "CBN-PEP-001",
            "rule_type": "transaction_monitoring",
            "category": "aml",
            "description": "Enhanced monitoring of Politically Exposed Persons",
            "business_justification": "PEPs require enhanced due diligence and monitoring",
            "regulatory_reference": "CBN AML/CFT Guidelines Section 6.1",
            "conditions": {"customer_risk": True, "pep_monitoring": True},
            "thresholds": {"amount": 500000},
            "applies_to": "individuals",
            "risk_weight": 1.8,
            "severity_level": "high",
            "alert_priority": 2
        }
    ]
    
    created_rules = []
    
    for rule_data in standard_rules:
        try:
            rule = create_aml_rule(
                user=user,
                rule_name=rule_data["rule_name"],
                rule_code=rule_data["rule_code"],
                rule_type=rule_data["rule_type"],
                category=rule_data["category"],
                description=rule_data["description"],
                business_justification=rule_data["business_justification"],
                conditions=rule_data["conditions"],
                thresholds=rule_data["thresholds"],
                applies_to=rule_data.get("applies_to", "all"),
                transaction_types=rule_data.get("transaction_types", []),
                risk_weight=rule_data["risk_weight"],
                severity_level=rule_data["severity_level"],
                alert_priority=rule_data["alert_priority"],
                regulatory_reference=rule_data["regulatory_reference"]
            )
            created_rules.append(rule)
        except ValueError as e:
            # Rule might already exist, continue with others
            continue
    
    # Log standard rules creation
    log_audit_event(
        user_id=user.id,
        event_type="standard_rules_created",
        action="create",
        resource_type="rule",
        description=f"Created {len(created_rules)} standard CBN-compliant AML rules",
        records_affected=len(created_rules)
    )
    
    return created_rules

def increment_version(current_version: str) -> str:
    \"\"\"Increment rule version number.\"\"\"
    try:
        major, minor = current_version.split(".")
        return f"{major}.{int(minor) + 1}"
    except:
        return "1.1"

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
        event_category="rules_management",
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