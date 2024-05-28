
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
   
    assert 1 == 0
    
    
if __name__ == "__main__":
    pytest.main()