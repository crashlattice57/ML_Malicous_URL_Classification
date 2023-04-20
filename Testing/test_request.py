import requests
import json
import sys

url_request = input("What url would you like to test: ")

url = 'http://localhost:5000/predict'
input_data = {'url': url_request}

response = requests.post(url, json=input_data)

response.raise_for_status()

preprocessed_input = response.json()

print(preprocessed_input)
