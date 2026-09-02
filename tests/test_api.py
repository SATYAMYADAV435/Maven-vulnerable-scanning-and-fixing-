from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_api_health():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["offline_db_available"] is True


def test_api_scan_directory(sample_project_dir):
    response = client.post(
        "/api/scan",
        data={
            "path": sample_project_dir,
            "mode": "offline",
            "fail_on": "critical",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "COMPLETED"
    assert "scan_id" in data
    scan_id = data["scan_id"]

    # Test GET /scans/{id}
    scan_resp = client.get(f"/api/scans/{scan_id}")
    assert scan_resp.status_code == 200
    scan_detail = scan_resp.json()
    assert scan_detail["scan_id"] == scan_id

    # Test GET /report/{id}?format=json
    json_rep = client.get(f"/api/report/{scan_id}?format=json")
    assert json_rep.status_code == 200
    assert "section_1_executive_summary" in json_rep.json()

    # Test GET /report/{id}?format=html
    html_rep = client.get(f"/api/report/{scan_id}?format=html")
    assert html_rep.status_code == 200
    assert "1. Executive Summary" in html_rep.text
