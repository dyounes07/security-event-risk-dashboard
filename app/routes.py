from flask import Blueprint, jsonify, render_template, request

from . import db
from .models import SecurityEvent
from .risk import calculate_risk_score

main = Blueprint("main", __name__)

# the dashboard page 
@main.route("/")
def dashboard():

    # query all events from database (newest first, descending order)
    events = SecurityEvent.query.order_by(
        SecurityEvent.created_at.desc()
    ).all()

    # render visual dashboard
    return render_template("dashboard.html", events=events)

# REST GET - fetch events with optional filtering
@main.route("/api/events", methods=["GET"])
def get_events():
    severity = request.args.get("severity")

    # optional URL query parameter
    query = SecurityEvent.query

    if severity:
        query = query.filter_by(severity=severity.lower())

    events = query.order_by(SecurityEvent.created_at.desc()).all()

    # convert to plain dict to send back as json
    return jsonify([event.to_dict() for event in events])


# REST POST - create a  new event
@main.route("/api/events", methods=["POST"])
def create_event():
    data = request.get_json(silent=True)
    
    # request file is invalid json
    if not data:
        return jsonify({"error": "Request body must contain JSON"}), 400

    # make sure each required field is present and NOT empty
    required_fields = ["event_type", "severity", "description"]
    for field in required_fields:
        if not data.get(field):
            return jsonify({"error": f"Missing field: {field}"}), 400

    event_type = str(data["event_type"]).strip()
    severity = str(data["severity"]).strip().lower()
    description = str(data["description"]).strip()
    source_ip = data.get("source_ip")

    # invalid severity
    if severity not in {"low", "medium", "high", "critical"}:
        return jsonify({"error": "Invalid severity"}), 400

    # description too long
    if len(description) > 500:
        return jsonify({"error": "Description is too long"}), 400

    # handle ValueErrors when calculating risk score
    try:
        risk_score = calculate_risk_score(severity, event_type)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    event = SecurityEvent(
        event_type=event_type,
        severity=severity,
        description=description,
        source_ip=source_ip,
        risk_score=risk_score,
    )
    
    db.session.add(event)
    db.session.commit()

    # status code 201 - "new resource successfully created"
    return jsonify(event.to_dict()), 201
