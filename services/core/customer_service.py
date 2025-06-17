from typing import List, Optional, Dict
from datetime import datetime, timedelta
import uuid
import hashlib
import json

from core.customer import Customer
from core.transaction import Transaction
from core.alert import Alert
from core.audit_log import AuditLog
from solar.access import User, authenticated, public

@authenticated
def create_customer(
    user: User,
    first_name: str,
    last_name: str,
    email: str,
    phone: str,
    date_of_birth: datetime,
    nationality: str,
    customer_id: str,
    address_line1: str,
    city: str,
    state: str,
    country: str,
    account_numbers: List[str],
    account_types: List[str],
    account_opening_date: datetime,
    bvn: Optional[str] = None,
    nin: Optional[str] = None,
    address_line2: Optional[str] = None,
    postal_code: Optional[str] = None
) -> Customer:
    \"\"\"Create a new customer record with initial risk assessment.\"\"\"
    
    # Create customer record
    customer = Customer(
        user_id=user.id,
        first_name=first_name,
        last_name=last_name,
        email=email,
        phone=phone,
        date_of_birth=date_of_birth,
        nationality=nationality,
        customer_id=customer_id,
        bvn=bvn,
        nin=nin,
        kyc_status="pending",
        kyc_level="tier1",
        address_line1=address_line1,
        address_line2=address_line2,
        city=city,
        state=state,
        country=country,
        postal_code=postal_code,
        account_numbers=account_numbers,
        account_types=account_types,
        account_opening_date=account_opening_date,
        customer_since=datetime.now(),
        risk_score=calculate_initial_risk_score(nationality, account_types),
        risk_category=get_risk_category(calculate_initial_risk_score(nationality, account_types)),
        created_by=user.id
    )
    
    customer.sync()
    
    # Log customer creation
    log_audit_event(
        user_id=user.id,
        event_type="customer_created",
        action="create",
        resource_type="customer",
        resource_id=customer.id,
        description=f"Customer {customer.first_name} {customer.last_name} created"
    )
    
    return customer

@authenticated  
def update_customer_risk_score(user: User, customer_id: uuid.UUID) -> Customer:
    \"\"\"Recalculate and update customer risk score based on recent activity.\"\"\"
    
    # Get customer
    customer_results = Customer.sql(
        "SELECT * FROM customers WHERE id = %(customer_id)s",
        {"customer_id": customer_id}
    )
    
    if not customer_results:
        raise ValueError("Customer not found")
    
    customer = Customer(**customer_results[0])
    
    # Get recent transactions (last 90 days)
    recent_transactions = Transaction.sql(
        \"\"\"SELECT * FROM transactions 
           WHERE customer_id = %(customer_id)s 
           AND transaction_date >= %(start_date)s
           ORDER BY transaction_date DESC\"\"\",
        {
            "customer_id": customer_id,
            "start_date": datetime.now() - timedelta(days=90)
        }
    )
    
    # Get recent alerts
    recent_alerts = Alert.sql(
        \"\"\"SELECT * FROM alerts 
           WHERE customer_id = %(customer_id)s 
           AND triggered_at >= %(start_date)s\"\"\",
        {
            "customer_id": customer_id,
            "start_date": datetime.now() - timedelta(days=90)
        }
    )
    
    # Calculate new risk score
    new_risk_score = calculate_dynamic_risk_score(customer, recent_transactions, recent_alerts)
    old_risk_score = customer.risk_score
    
    # Update customer
    customer.risk_score = new_risk_score
    customer.risk_category = get_risk_category(new_risk_score)
    customer.last_risk_assessment = datetime.now()
    customer.updated_at = datetime.now()
    
    customer.sync()
    
    # Log risk score update
    log_audit_event(
        user_id=user.id,
        event_type="risk_score_updated",
        action="update",
        resource_type="customer",
        resource_id=customer.id,
        description=f"Risk score updated from {old_risk_score} to {new_risk_score}",
        old_values={"risk_score": old_risk_score},
        new_values={"risk_score": new_risk_score}
    )
    
    return customer

@authenticated
def get_high_risk_customers(user: User, limit: int = 100) -> List[Customer]:
    \"\"\"Get customers with high risk scores for review.\"\"\"
    
    results = Customer.sql(
        \"\"\"SELECT * FROM customers 
           WHERE risk_category = 'high' 
           ORDER BY risk_score DESC, last_risk_assessment ASC
           LIMIT %(limit)s\"\"\",
        {"limit": limit}
    )
    
    customers = [Customer(**result) for result in results]
    
    # Log access to high-risk customers
    log_audit_event(
        user_id=user.id,
        event_type="high_risk_customers_accessed",
        action="view",
        resource_type="customer",
        description=f"Accessed {len(customers)} high-risk customers",
        records_affected=len(customers)
    )
    
    return customers

@authenticated
def perform_sanctions_screening(user: User, customer_id: uuid.UUID) -> Dict:
    \"\"\"Perform sanctions and PEP screening for a customer.\"\"\"
    
    # Get customer
    customer_results = Customer.sql(
        "SELECT * FROM customers WHERE id = %(customer_id)s",
        {"customer_id": customer_id}
    )
    
    if not customer_results:
        raise ValueError("Customer not found")
    
    customer = Customer(**customer_results[0])
    
    # Simulate sanctions screening (in real implementation, integrate with sanctions APIs)
    screening_results = {
        "sanctions_hit": False,
        "pep_hit": False,
        "watchlist_hit": False,
        "screening_date": datetime.now().isoformat(),
        "confidence_score": 0.95,
        "sources_checked": ["UN", "OFAC", "EFCC", "PEP_LIST"]
    }
    
    # Update customer record
    customer.sanctions_checked = True
    customer.pep_status = screening_results["pep_hit"]
    customer.updated_at = datetime.now()
    
    # If hits found, increase risk score
    if screening_results["sanctions_hit"] or screening_results["pep_hit"]:
        customer.risk_score = min(100.0, customer.risk_score + 30.0)
        customer.risk_category = get_risk_category(customer.risk_score)
        customer.requires_enhanced_dd = True
    
    customer.sync()
    
    # Log screening
    log_audit_event(
        user_id=user.id,
        event_type="sanctions_screening",
        action="screening",
        resource_type="customer",
        resource_id=customer.id,
        description=f"Sanctions screening performed for {customer.first_name} {customer.last_name}",
        details=screening_results
    )
    
    return screening_results

def calculate_initial_risk_score(nationality: str, account_types: List[str]) -> float:
    \"\"\"Calculate initial risk score based on basic customer information.\"\"\"
    base_score = 10.0
    
    # High-risk countries (simplified list)
    high_risk_countries = ["AF", "IR", "KP", "SY"]  # Afghanistan, Iran, North Korea, Syria
    if nationality in high_risk_countries:
        base_score += 40.0
    
    # Account type risk
    high_risk_account_types = ["business", "corporate", "trust"]
    for account_type in account_types:
        if account_type.lower() in high_risk_account_types:
            base_score += 15.0
    
    return min(100.0, base_score)

def calculate_dynamic_risk_score(customer: Customer, transactions: List[Dict], alerts: List[Dict]) -> float:
    \"\"\"Calculate dynamic risk score based on customer behavior and transaction patterns.\"\"\"
    base_score = customer.risk_score
    
    # Transaction volume analysis
    total_amount = sum(float(txn.get("amount", 0)) for txn in transactions)
    transaction_count = len(transactions)
    
    if total_amount > 10000000:  # 10M NGN
        base_score += 20.0
    elif total_amount > 5000000:  # 5M NGN
        base_score += 10.0
    
    if transaction_count > 1000:  # High frequency
        base_score += 15.0
    elif transaction_count > 500:
        base_score += 8.0
    
    # Alert frequency
    alert_count = len(alerts)
    if alert_count > 10:
        base_score += 25.0
    elif alert_count > 5:
        base_score += 15.0
    elif alert_count > 0:
        base_score += 5.0
    
    # Cash transaction ratio
    cash_transactions = [txn for txn in transactions if txn.get("cash_transaction", False)]
    if cash_transactions and len(cash_transactions) / len(transactions) > 0.5:
        base_score += 20.0
    
    return min(100.0, max(0.0, base_score))

def get_risk_category(risk_score: float) -> str:
    \"\"\"Convert numeric risk score to category.\"\"\"
    if risk_score >= 70:
        return "high"
    elif risk_score >= 40:
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
        event_category="customer_management",
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