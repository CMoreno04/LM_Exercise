
import pytest
from src.check_compliance import get_rules, verify_compliance

#test get rules
def test_get_rules():
    rules = get_rules()
    
    #assert that object returned is an instance of list
    assert isinstance(rules, list)
    
    #assert that the list is not empty
    assert len(rules) > 0 

#test verify compliance
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
        "FromPort": 22,
        "IpRanges": [
            "91.172.88.105"
        ],
        "ToPort": 22,
        "Action": "Allow",
        "Direction": "Ingress",
        "RuleId": "9"
    }
    
    compliant_rule_non_ingress = {
        "FromPort": 80,
        "IpRanges": [
            "67.44.208.193/30"
        ],
        "ToPort": 80,
        "Action": "Deny",
        "Direction": "Egress",
        "RuleId": "99"
    }
    
    compliant_rule_deny = {
        "RuleId": "4",
        "FromPort": 80,
        "ToPort": 80,
        "IpRanges": ["236.216.246.119/32"],
        "Action": "Deny",
        "Direction": "Ingress"
    }
    
    port_is_minus_one_non_compliant = {
        "FromPort": -1,
        "IpRanges": [
            "91.172.88.105"
        ],
        "ToPort": -1,
        "Action": "Allow",
        "Direction": "Ingress",
        "RuleId": "9"
    }

    port_is_minus_one_compliant = {
            "FromPort": -1,
            "IpRanges": [
                "92.172.88.105"
            ],
            "ToPort": -1,
            "Action": "Allow",
            "Direction": "Ingress",
            "RuleId": "9"
        }
    
    #assert if rule is compliant by port number
    assert verify_compliance(compliant_rule) == "COMPLIANT"
    
    #assert if rule is non compliant by port number
    assert verify_compliance(non_compliant_rule) == "NON_COMPLIANT"
    
    #assert if rule is compliant by Direction
    assert verify_compliance(compliant_rule_non_ingress) == "COMPLIANT"
    
    #assert if rule is compliant by Action
    assert verify_compliance(compliant_rule_deny) == "COMPLIANT"
    
    #assert if rule is non compliant with -1 port number
    assert verify_compliance(port_is_minus_one_non_compliant) == "NON_COMPLIANT"
    
    #assert if rule is non compliant with -1 port number
    assert verify_compliance(port_is_minus_one_compliant) == "COMPLIANT"
    
if __name__ == "__main__":
    pytest.main()