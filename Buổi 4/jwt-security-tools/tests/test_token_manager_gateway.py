from api_gateway import APIGateway
from jwt_validator import JWTValidator
from token_manager import TokenManager
import pytest

def test_gateway_accepts_valid_bearer():
    manager = TokenManager("g" * 48)
    pair = manager.issue_tokens("alice")
    response = APIGateway(manager.validator).create_app().test_client().get("/protected", headers={"Authorization": f"Bearer {pair.access_token}"})
    assert response.status_code == 200 and response.json["subject"] == "alice"

def test_gateway_rejects_missing_and_malformed_bearer():
    client = APIGateway(JWTValidator("g" * 48)).create_app().test_client()
    for headers in ({}, {"Authorization": "Token secret"}, {"Authorization": "Bearer not.a.jwt"}):
        response = client.get("/protected", headers=headers)
        assert response.status_code == 401 and "token" not in response.get_data(as_text=True).lower()

def test_gateway_binds_loopback_by_default():
    from api_gateway.gateway import run
    with pytest.raises(ValueError): run(host="0.0.0.0")
