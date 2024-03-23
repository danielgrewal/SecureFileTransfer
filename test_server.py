# from uuid import uuid4
# import requests

# def test_endSession():

#     session_id = 3
        
#     access_token = uuid4() # generating fake token
        
#     headers = {"Accept": "application/json",
#                 "Authorization": f"Bearer {access_token}"}
    
#     SERVER_URL_BASE = "https://localhost"
#     response = requests.post(f'{SERVER_URL_BASE}/endsession',
#                              json={"session_id": session_id}, headers=headers, verify=False)

#     print(response.json().get("status"))

#     assert response.json().get("status") is not "Success"