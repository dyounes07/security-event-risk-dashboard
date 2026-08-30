def test_empty_events_list(client):
    response = client.get("/api/events")

    assert response.status_code == 200
    assert response.get_json() == []


def test_create_event(client):
    response = client.post(
        "/api/events",
        json={
            "event_type": "brute_force",
            "severity": "high",
            "description": "Multiple failed login attempts",
            "source_ip": "192.168.1.20",
        },
    )

    assert response.status_code == 201

    data = response.get_json()

    assert data["event_type"] == "brute_force"
    assert data["severity"] == "high"
    assert data["risk_score"] == 85


def test_rejects_missing_field(client):
    response = client.post(
        "/api/events",
        json={
            "event_type": "malware",
            "severity": "critical",
        },
    )

    assert response.status_code == 400


def test_rejects_invalid_severity(client):
    response = client.post(
        "/api/events",
        json={
            "event_type": "malware",
            "severity": "extreme",
            "description": "Invalid severity test",
        },
    )

    assert response.status_code == 400


def test_filter_by_severity(client):
    client.post(
        "/api/events",
        json={
            "event_type": "malware",
            "severity": "critical",
            "description": "Critical malware event",
        },
    )

    client.post(
        "/api/events",
        json={
            "event_type": "login",
            "severity": "low",
            "description": "Low-risk login event",
        },
    )

    response = client.get("/api/events?severity=critical")

    assert response.status_code == 200
    assert len(response.get_json()) == 1
    assert response.get_json()[0]["severity"] == "critical"
