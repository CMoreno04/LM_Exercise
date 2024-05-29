# Imports
import requests
import json
import ipaddress

#Constants 
NON_COMPLIANT_IPS = [
    "236.216.246.119",
    "109.3.194.189",
    "36.229.68.87",
    "21.90.154.237",
    "91.172.88.105"
]

NON_COMPLIANT_PORTS = [22, 80, 443, -1]

API_URL = "https://g326av89lk.execute-api.us-east-1.amazonaws.com/prod/rules"

#function to verify rule compliance
def verify_compliance(rule):
    
    #verify Direction for Engress and Action Deny 
    if rule['Direction'] != "Ingress" or rule['Action'] != 'Allow':
        return "COMPLIANT"
    
    #if Direction is Ingress and Action is Allow.
        # extract ip from rule and verify against provided ip list
            # if the ip is within the addreses provided then proceed to validate From and To Port
                # finally, if ports match 22, 80 or 443 then such rule is NON_COMPLIANT
    for ip_range in rule['IpRanges']:
       ip_network = ipaddress.ip_network(ip_range, strict=False)
       for non_compliant_ip in NON_COMPLIANT_IPS:  
           if ipaddress.ip_address(non_compliant_ip) in ip_network:
            if rule['FromPort']in NON_COMPLIANT_PORTS or rule['ToPort'] in NON_COMPLIANT_PORTS:
                    return "NON_COMPLIANT"
    return "COMPLIANT"  
    

#function to fetch firewall rules
def get_rules():
    
    #set variables to save rules responses and manage last eval key for pagination purposes. 
    rules = []
    last_eval_key = None
    
    #request all available pages and return fetched firewall rules
    while True: 
        params = {}
        
        #if LastEvaluatedKey is present, set ExclusiveStartKey param to request next page
        if last_eval_key:
            params["ExclusiveStartKey"] = json.dumps(last_eval_key)
        
        #perfom GET API call with current params
        response = requests.get(API_URL,params=params)
       
        #if response is not succesful, log error and set response as HTTPError
        if response.status_code != 200:
            print(f"Error fetching data: {response.status_code}")
            print(response.text)
            response.raise_for_status()

        #try/catch to handle any json parsing errors
        try:
            data = response.json()
        except requests.exceptions.JSONDecodeError as e:
            print(f"Error decoding JSON: {e}")
            print(response.text)
            raise
        
        #get values in Items within response, and add them to the rules list
        rules.extend(data.get("Items",[]))
  
        #get LastEvaluatedKey for pagination
        last_eval_key = data.get("LastEvaluatedKey")
        
        #should no LastEvaluatedKey be present, finish iterations and return the rules 
        if not last_eval_key:
            break
        
    #return list with rules obtained from api call
    return rules
        
        
def main():
    print("Collecting Rules...")
    
    #collect rules
    rules = get_rules()
    result = []
     
    #verify compliance for each rule and add them to result
    for rule in rules: 
        compliance = verify_compliance(rule)
        result.append({"RuleId":rule["RuleId"], "Compliance": compliance})
    
    #save result in .json file
    with open('compliance_verification_result.json','w') as f: 
        json.dump(result, f, indent=4)
        
    print("Compliance Verification has been completed! See \'compliance_verification_result.json\' for results.")
    
    
if __name__ == "__main__":
    main()