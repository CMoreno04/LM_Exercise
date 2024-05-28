
import pytest
from src.check_compliance import get_rules, verify_compliance


def test_get_rules():
    assert get_rules("url") == "get rules"


def test_verify_compliance():
    assert verify_compliance("rule") == "verify compliance"
    
    
if __name__ == "__main__":
    pytest.main()