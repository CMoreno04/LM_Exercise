
import pytest
from src.check_compliance import get_rules, verify_compliance

#Test get rules
def test_get_rules():
    rules = get_rules()
    
    #assert that object returned is an instance of list
    assert isinstance(rules, list)
    
    #assert that the list is not empty
    assert len(rules) > 0 


def test_verify_compliance():
   
    compliant_rule = {
        "RuleId": "1",
        "FromPort": 100,
        "ToPort": 200,
        "IpRanges": ["192.168.1.1/32"],
        "Action": "Allow",
        "Direction": "Ingress"
    }
    
    non_compliant_rule = {
        "RuleId": "2",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": ["236.216.246.119/32"],
        "Action": "Allow",
        "Direction": "Ingress"
    }
    
    compliant_rule_non_ingress = {
        "RuleId": "3",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": ["236.216.246.119/32"],
        "Action": "Allow",
        "Direction": "Egress"
    }
    
    compliant_rule_deny = {
        "RuleId": "4",
        "FromPort": 80,
        "ToPort": 80,
        "IpRanges": ["236.216.246.119/32"],
        "Action": "Deny",
        "Direction": "Ingress"
    }

    #assert if rule is compliant by port number
    assert verify_compliance(compliant_rule) == "COMPLIANT"
    
    #assert if rule is non compliant by port number
    assert verify_compliance(non_compliant_rule) == "NON_COMPLIANT"
    
    #assert if rule is compliant by Direction
    assert verify_compliance(compliant_rule_non_ingress) == "COMPLIANT"
    
    
if __name__ == "__main__":
    pytest.main()