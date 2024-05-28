import requests
import urllib.parse
import json

API_URL = "https://g326av89lk.execute-api.us-east-1.amazonaws.com/prod/rules"

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
        
        
def verify_compliance(rule):
    print("verifies compliance")
    return "verify compliance"


def main():
    print("initialize process")
    get_rules()
    verify_compliance("")
    return "main"
    
    
if __name__ == "__main__":
    main()