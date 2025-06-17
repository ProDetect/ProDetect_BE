from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
import uuid
import json

from core.transaction import Transaction
from core.customer import Customer
from core.alert import Alert
from core.rule import Rule
from core.audit_log import AuditLog
from solar.access import User, authenticated, public

@authenticated
def process_transaction(
    user: User,
    transaction_id: str,
    customer_id: uuid.UUID,
    transaction_type: str,
    amount: float,
    currency: str,
    account_number: str,
    description: str,
    transaction_method: str = "mobile",
    channel: str = "mobile_app",
    beneficiary_name: Optional[str] = None,
    beneficiary_account: Optional[str] = None,
    beneficiary_bank: Optional[str] = None,
    beneficiary_country: Optional[str] = None,
    location: Optional[str] = None,
    ip_address: Optional[str] = None,
    device_id: Optional[str] = None
) -> Transaction:
    \"\"\"Process a new transaction and perform AML monitoring.\"\"\"
    
    # Create transaction record
    transaction = Transaction(
        transaction_id=transaction_id,
        reference_number=f"REF-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8]}",
        customer_id=customer_id,
        transaction_type=transaction_type,
        transaction_method=transaction_method,
        currency=currency,
        amount=amount,
        account_number=account_number,
        beneficiary_name=beneficiary_name,
        beneficiary_account=beneficiary_account,
        beneficiary_bank=beneficiary_bank,
        beneficiary_country=beneficiary_country,
        description=description,
        channel=channel,
        location=location,
        ip_address=ip_address,
        device_id=device_id,
        transaction_date=datetime.now(),
        value_date=datetime.now(),
        status="completed",
        cross_border=beneficiary_country is not None and beneficiary_country != "NG",
        cash_transaction=transaction_method.lower() in ["cash", "atm_withdrawal"],
        above_ctr_threshold=amount >= 5000000  # 5M NGN CTR threshold
    )
    
    # Perform real-time AML monitoring
    monitoring_results = perform_aml_monitoring(transaction)
    
    # Update transaction with monitoring results
    transaction.risk_score = monitoring_results["risk_score"]
    transaction.risk_flags = monitoring_results["risk_flags"]
    transaction.is_suspicious = monitoring_results["is_suspicious"]
    transaction.alert_count = len(monitoring_results["alerts_generated"])
    
    # Set specific flags based on monitoring
    transaction.structuring_indicator = monitoring_results["risk_flags"].get("structuring", False)
    transaction.velocity_flag = monitoring_results["risk_flags"].get("velocity", False)
    transaction.amount_threshold_flag = monitoring_results["risk_flags"].get("amount_threshold", False)
    transaction.unusual_pattern_flag = monitoring_results["risk_flags"].get("unusual_pattern", False)
    
    transaction.sync()
    
    # Generate alerts if necessary
    for alert_data in monitoring_results["alerts_generated"]:
        create_alert_from_transaction(user, transaction, alert_data)
    
    # Log transaction processing
    log_audit_event(
        user_id=user.id,
        event_type="transaction_processed",
        action="create",
        resource_type="transaction",
        resource_id=transaction.id,
        description=f"Transaction {transaction.transaction_id} processed for amount {amount} {currency}",
        details=monitoring_results
    )
    
    return transaction

@authenticated
def perform_aml_monitoring(transaction: Transaction) -> Dict[str, Any]:
    \"\"\"Perform comprehensive AML monitoring on a transaction.\"\"\"
    
    risk_score = 0.0
    risk_flags = {}
    alerts_generated = []
    
    # Get customer information
    customer_results = Customer.sql(
        "SELECT * FROM customers WHERE id = %(customer_id)s",
        {"customer_id": transaction.customer_id}
    )
    
    if not customer_results:
        raise ValueError("Customer not found")
    
    customer = Customer(**customer_results[0])
    
    # Get active monitoring rules
    active_rules = Rule.sql(
        "SELECT * FROM rules WHERE status = 'active' AND rule_type = 'transaction_monitoring'"
    )
    
    rules = [Rule(**rule) for rule in active_rules]
    
    # Apply each rule
    for rule in rules:
        rule_result = apply_monitoring_rule(transaction, customer, rule)
        
        if rule_result["triggered"]:
            risk_score += rule_result["risk_contribution"]
            risk_flags[rule.rule_code.lower()] = True
            
            # Generate alert if rule threshold exceeded
            if rule_result["alert_required"]:
                alerts_generated.append({
                    "rule_id": rule.id,
                    "rule_name": rule.rule_name,
                    "risk_score": rule_result["risk_contribution"],
                    "threshold_exceeded": rule_result["threshold_values"],
                    "severity": rule.severity_level
                })
    
    # Additional pattern analysis
    pattern_results = detect_transaction_patterns(transaction, customer)
    risk_score += pattern_results["risk_contribution"]
    risk_flags.update(pattern_results["flags"])
    
    if pattern_results["alerts"]:
        alerts_generated.extend(pattern_results["alerts"])
    
    # Normalize risk score
    risk_score = min(100.0, max(0.0, risk_score))
    
    return {
        "risk_score": risk_score,
        "risk_flags": risk_flags,
        "is_suspicious": risk_score >= 60.0,
        "alerts_generated": alerts_generated,
        "rules_triggered": len([flag for flag in risk_flags.values() if flag]),
        "monitoring_timestamp": datetime.now().isoformat()
    }

def apply_monitoring_rule(transaction: Transaction, customer: Customer, rule: Rule) -> Dict[str, Any]:
    \"\"\"Apply a specific monitoring rule to a transaction.\"\"\"
    
    result = {
        "triggered": False,
        "risk_contribution": 0.0,
        "alert_required": False,
        "threshold_values": {}
    }
    
    conditions = rule.conditions
    thresholds = rule.thresholds
    
    # Amount-based rules
    if "amount_threshold" in conditions:
        threshold = thresholds.get("amount", 1000000)  # Default 1M NGN
        if transaction.amount >= threshold:
            result["triggered"] = True
            result["risk_contribution"] = rule.risk_weight * 20.0
            result["alert_required"] = True
            result["threshold_values"]["amount"] = {
                "actual": transaction.amount,
                "threshold": threshold
            }
    
    # Velocity rules (transaction frequency)
    if "velocity_check" in conditions:
        velocity_result = check_transaction_velocity(transaction, customer)
        if velocity_result["threshold_exceeded"]:
            result["triggered"] = True
            result["risk_contribution"] = rule.risk_weight * 15.0
            result["alert_required"] = True
            result["threshold_values"]["velocity"] = velocity_result
    
    # Structuring detection
    if "structuring_detection" in conditions:
        structuring_result = detect_structuring(transaction, customer)
        if structuring_result["likely_structuring"]:
            result["triggered"] = True
            result["risk_contribution"] = rule.risk_weight * 25.0
            result["alert_required"] = True
            result["threshold_values"]["structuring"] = structuring_result
    
    # Cross-border rules
    if "cross_border" in conditions and transaction.cross_border:
        result["triggered"] = True
        result["risk_contribution"] = rule.risk_weight * 10.0
        
        # High-risk countries get additional score
        if transaction.beneficiary_country in ["AF", "IR", "KP", "SY"]:
            result["risk_contribution"] += rule.risk_weight * 20.0
            result["alert_required"] = True
    
    # Cash transaction rules
    if "cash_monitoring" in conditions and transaction.cash_transaction:
        cash_threshold = thresholds.get("cash_amount", 500000)  # 500K NGN
        if transaction.amount >= cash_threshold:
            result["triggered"] = True
            result["risk_contribution"] = rule.risk_weight * 15.0
            result["alert_required"] = True
    
    # Customer risk-based rules
    if "customer_risk" in conditions:
        if customer.risk_category == "high":
            result["triggered"] = True
            result["risk_contribution"] = rule.risk_weight * 10.0
        elif customer.pep_status:
            result["triggered"] = True
            result["risk_contribution"] = rule.risk_weight * 15.0
            result["alert_required"] = True
    
    return result

def check_transaction_velocity(transaction: Transaction, customer: Customer) -> Dict[str, Any]:
    \"\"\"Check transaction velocity for potential suspicious activity.\"\"\"
    
    # Get transactions in last 24 hours
    recent_transactions = Transaction.sql(
        \"\"\"SELECT COUNT(*) as count, SUM(amount) as total_amount
           FROM transactions 
           WHERE customer_id = %(customer_id)s 
           AND transaction_date >= %(start_time)s\"\"\",
        {
            "customer_id": customer.id,
            "start_time": datetime.now() - timedelta(hours=24)
        }
    )
    
    if not recent_transactions:
        return {"threshold_exceeded": False}
    
    count = recent_transactions[0]["count"]
    total_amount = recent_transactions[0]["total_amount"] or 0
    
    # Velocity thresholds
    count_threshold = 50  # 50 transactions per day
    amount_threshold = 10000000  # 10M NGN per day
    
    return {
        "threshold_exceeded": count >= count_threshold or total_amount >= amount_threshold,
        "transaction_count": count,
        "total_amount": total_amount,
        "thresholds": {
            "count_threshold": count_threshold,
            "amount_threshold": amount_threshold
        }
    }

def detect_structuring(transaction: Transaction, customer: Customer) -> Dict[str, Any]:
    \"\"\"Detect potential structuring patterns.\"\"\"
    
    # Look for multiple transactions just below reporting thresholds
    threshold_amount = 5000000  # CTR threshold in NGN
    pattern_window = timedelta(days=1)
    
    # Get recent transactions near threshold
    recent_transactions = Transaction.sql(
        \"\"\"SELECT * FROM transactions 
           WHERE customer_id = %(customer_id)s 
           AND transaction_date >= %(start_time)s
           AND amount BETWEEN %(min_amount)s AND %(max_amount)s
           ORDER BY transaction_date DESC\"\"\",
        {
            "customer_id": customer.id,
            "start_time": datetime.now() - pattern_window,
            "min_amount": threshold_amount * 0.8,  # 80% of threshold
            "max_amount": threshold_amount * 0.99  # Just below threshold
        }
    )
    
    pattern_indicators = {
        "transaction_count": len(recent_transactions),
        "total_amount": sum(float(txn["amount"]) for txn in recent_transactions),
        "likely_structuring": False
    }
    
    # Structuring indicators
    if len(recent_transactions) >= 3:  # Multiple transactions
        total_amount = pattern_indicators["total_amount"]
        if total_amount > threshold_amount:  # Would exceed threshold if combined
            pattern_indicators["likely_structuring"] = True
    
    return pattern_indicators

def detect_transaction_patterns(transaction: Transaction, customer: Customer) -> Dict[str, Any]:
    \"\"\"Detect additional suspicious transaction patterns.\"\"\"
    
    risk_contribution = 0.0
    flags = {}
    alerts = []
    
    # Unusual time patterns
    transaction_hour = transaction.transaction_date.hour
    if transaction_hour < 6 or transaction_hour > 22:  # Outside normal hours
        risk_contribution += 5.0
        flags["unusual_time"] = True
    
    # Round number analysis
    if transaction.amount % 1000000 == 0 and transaction.amount >= 1000000:  # Exact millions
        risk_contribution += 8.0
        flags["round_amount"] = True
    
    # Frequency analysis
    customer_avg_result = Transaction.sql(
        \"\"\"SELECT AVG(amount) as avg_amount, COUNT(*) as transaction_count
           FROM transactions 
           WHERE customer_id = %(customer_id)s 
           AND transaction_date >= %(start_date)s\"\"\",
        {
            "customer_id": customer.id,
            "start_date": datetime.now() - timedelta(days=30)
        }
    )
    
    if customer_avg_result and customer_avg_result[0]["avg_amount"]:
        avg_amount = float(customer_avg_result[0]["avg_amount"])
        if transaction.amount > avg_amount * 10:  # 10x higher than average
            risk_contribution += 15.0
            flags["unusual_amount"] = True
            alerts.append({
                "rule_name": "Unusual Amount Pattern",
                "risk_score": 15.0,
                "severity": "medium",
                "description": f"Transaction amount {transaction.amount} is 10x higher than customer average"
            })
    
    return {
        "risk_contribution": risk_contribution,
        "flags": flags,
        "alerts": alerts
    }

def create_alert_from_transaction(user: User, transaction: Transaction, alert_data: Dict):
    \"\"\"Create an alert from transaction monitoring results.\"\"\"
    
    alert = Alert(
        alert_id=f"TXN-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8]}",
        alert_type="transaction_monitoring",
        alert_category="aml",
        customer_id=transaction.customer_id,
        transaction_id=transaction.id,
        rule_id=alert_data.get("rule_id"),
        title=f"Suspicious Transaction: {alert_data['rule_name']}",
        description=f"Transaction {transaction.transaction_id} triggered AML rule: {alert_data['rule_name']}",
        severity=alert_data.get("severity", "medium"),
        risk_score=alert_data["risk_score"],
        triggered_rules=[alert_data["rule_name"]],
        threshold_values=alert_data.get("threshold_exceeded", {}),
        detection_method="rule_based",
        regulatory_significance=True
    )
    
    alert.sync()
    
    # Log alert creation
    log_audit_event(
        user_id=user.id,
        event_type="alert_generated",
        action="create",
        resource_type="alert",
        resource_id=alert.id,
        description=f"Alert generated for transaction {transaction.transaction_id}",
        details=alert_data
    )

@authenticated
def get_suspicious_transactions(user: User, days: int = 7, limit: int = 100) -> List[Transaction]:
    \"\"\"Get suspicious transactions for review.\"\"\"
    
    results = Transaction.sql(
        \"\"\"SELECT * FROM transactions 
           WHERE is_suspicious = true 
           AND transaction_date >= %(start_date)s
           ORDER BY risk_score DESC, transaction_date DESC
           LIMIT %(limit)s\"\"\",
        {
            "start_date": datetime.now() - timedelta(days=days),
            "limit": limit
        }
    )
    
    transactions = [Transaction(**result) for result in results]
    
    # Log access
    log_audit_event(
        user_id=user.id,
        event_type="suspicious_transactions_accessed",
        action="view",
        resource_type="transaction",
        description=f"Accessed {len(transactions)} suspicious transactions from last {days} days",
        records_affected=len(transactions)
    )
    
    return transactions

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
        event_category="transaction_monitoring",
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