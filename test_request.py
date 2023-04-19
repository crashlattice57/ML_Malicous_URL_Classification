import requests
import json

url = 'http://localhost:5000/predict'
input_data = {'url': 'https://github.com/crashlattice57/ML_Malicous_URL_Classification'}

response = requests.post(url, json=input_data)
print(response.status_code)
response.raise_for_status()
print("Im here")
preprocessed_input = response.json()
print("Whats going on here")
print(preprocessed_input)
