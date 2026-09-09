from app import create_app, db
from app.models import SecurityEvent
from app.risk import calculate_risk_score

app = create_app()

sample_events = [
    {
        "event_type": "brute_force",
        "severity": "high",
        "description": "Repeated failed login attempts detected",
        "source_ip": "192.168.1.10",
    },
    {
        "event_type": "malware",
        "severity": "critical",
        "description": "Malware signature detected on endpoint",
        "source_ip": "10.0.0.15",
    },
    {
        "event_type": "unauthorized_access",
        "severity": "medium",
        "description": "Access attempt outside approved permissions",
        "source_ip": "172.16.0.4",
    },
]


with app.app_context():

    # reset database for testing demos
    db.drop_all()
    db.create_all()
    
    for data in sample_events:
        event = SecurityEvent(
            event_type=data["event_type"],
            severity=data["severity"],
            description=data["description"],
            source_ip=data["source_ip"],
            risk_score=calculate_risk_score(
                data["severity"],
                data["event_type"],
            ),
        )
        db.session.add(event)

    db.session.commit()

    print("Database seeded successfully.")
