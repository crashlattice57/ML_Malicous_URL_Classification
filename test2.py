# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""

import URL_Classification
import pandas as pd
from sklearn.utils import resample
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.model_selection import GridSearchCV
from urllib.parse import urlparse
from sklearn.metrics import confusion_matrix,classification_report,plot_confusion_matrix,accuracy_score

df = pd.read_csv("malicious_phish.csv")

"""
# Define the value to use as the reference for the number of samples
reference_value = "malware"
num_samples = df["type"].value_counts()[reference_value]

# Initialize an empty dataframe to store the resampled data
df_resampled = pd.DataFrame()

# Loop through each unique value in the "type" column and oversample to match the number of samples in the reference value
for value in df["type"].unique():
    df_value = df[df["type"] == value]
    if value == reference_value:
        # Skip oversampling the reference value
        df_resampled = pd.concat([df_resampled, df_value])
    else:
        # Oversample the other values to match the number of samples in the reference value
        df_value_oversampled = resample(df_value, replace=True, n_samples=num_samples, random_state=42)
        df_resampled = pd.concat([df_resampled, df_value_oversampled])




df = df_resampled
"""

df['type'] = df['type'].apply(lambda x: 'benign' if x == 'benign' else 'malicious')
df["url_len"] = df["url"].apply(lambda x: len(x))
df["url_parts"] = df["url"].apply(lambda x: len(x.split(".")))
df["suffix_len"] = df["url"].apply(lambda x: len(x.split(".")[-1]))
df["domain_len"] = df["url"].apply(URL_Classification.query_domain_length)
df['digit_count'] = df['url'].apply(lambda s: sum(c.isdigit() for c in s))
df['alpha_count'] = df['url'].apply(lambda s: sum(c.isalpha() for c in s))
df["ip_present"] = df["url"].apply(URL_Classification.is_ip_address_present)
df["file_extension"] = df["url"].apply(URL_Classification.has_malicious_file_extension)
df["shorted_link"] = df["url"].apply(URL_Classification.has_shortened_link)
special_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', '[', ']', '{', '}', '|', '\\', ';', ':', '\'', '\"', ',', '.', '<', '>', '/', '?']

special_char_counts = []
for url in df['url']:
    counts = {}
    for special in special_chars:
        counts[f'{special}_count'] = url.count(special)
    counts['special_chars_count'] = sum([1 for char in url if char in special_chars])
    special_char_counts.append(counts)

for special in special_chars:
    df[f'{special}_count'] = [counts[f'{special}_count'] for counts in special_char_counts]
df['special_chars_count'] = [counts['special_chars_count'] for counts in special_char_counts]



def extract_url_attributes(url):
    attributes = ['scheme', 'netloc', 'path', 'params', 'query', 'fragment']
    parsed = urlparse(url)
    result = {}
    for attribute in attributes:
        result[f"{attribute}_present"] = 1 if getattr(parsed, attribute) != '' else 0
    return result
for attribute in ['scheme', 'netloc', 'path', 'params', 'query', 'fragment']:
    df[f"{attribute}_present"] = df['url'].apply(lambda x: extract_url_attributes(x)[f"{attribute}_present"])


X = df.drop(["type","url"],axis=1)
y = df["type"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=101)


    
rfc = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)

rfc.fit(X_train, y_train)




def preprocess_input(input_data):
    """
    Takes in a string url as input and does preprocessing of all steps to get ready for prediction
    """
    df = pd.DataFrame({"url": [input_data]})
    
    df["type"] = df["url"].apply(lambda x: 0)
    df["url_len"] = df["url"].apply(lambda x: len(x))
    df["url_parts"] = df["url"].apply(lambda x: len(x.split(".")))
    df["suffix_len"] = df["url"].apply(lambda x: len(x.split(".")[-1]))
    df["domain_len"] = df["url"].apply(URL_Classification.query_domain_length)
    df['digit_count'] = df['url'].apply(lambda s: sum(c.isdigit() for c in s))
    df['alpha_count'] = df['url'].apply(lambda s: sum(c.isalpha() for c in s))
    df["ip_present"] = df["url"].apply(URL_Classification.is_ip_address_present)
    df["file_extension"] = df["url"].apply(URL_Classification.has_malicious_file_extension)
    df["shorted_link"] = df["url"].apply(URL_Classification.has_shortened_link)

    special_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', '[', ']', '{', '}', '|', '\\', ';', ':', '\'', '\"', ',', '.', '<', '>', '/', '?']
    
    special_char_counts = []
    for url in df['url']:
        counts = {}
        for special in special_chars:
            counts[f'{special}_count'] = url.count(special)
        counts['special_chars_count'] = sum([1 for char in url if char in special_chars])
        special_char_counts.append(counts)
    
    for special in special_chars:
        df[f'{special}_count'] = [counts[f'{special}_count'] for counts in special_char_counts]
    df['special_chars_count'] = [counts['special_chars_count'] for counts in special_char_counts]
    def extract_url_attributes(url):
        attributes = ['scheme', 'netloc', 'path', 'params', 'query', 'fragment']
        parsed = urlparse(url)
        result = {}
        for attribute in attributes:
            result[f"{attribute}_present"] = 1 if getattr(parsed, attribute) != '' else 0
        return result
    for attribute in ['scheme', 'netloc', 'path', 'params', 'query', 'fragment']:
        df[f"{attribute}_present"] = df['url'].apply(lambda x: extract_url_attributes(x)[f"{attribute}_present"])
    X = df.drop(["url","type"], axis=1)
    return X


rfc.predict(preprocess_input("https://chat.openai.com/"))

processed = preprocess_input("www.google.com/13401840184018401840184lj242l4jl4j1")

y_pred = rfc.predict(X_test)

confusion_matrix(y_test,y_pred)

plot_confusion_matrix(rfc,X_test,y_test)

print(classification_report(y_test,y_pred))

import pickle

with open("rfc.pk1", "wb") as m:
    pickle.dump(rfc, m)


        
    
for idx,value in enumerate(X_test[0:25]):
    if y_test.iloc[idx] != rfc.predict(value):
        correct = "Incorrect Prediction"
    else:
        correct = "Correct"
        
    print(f"True Value: {y_test.iloc[idx]}\tPrediction: {rfc.predict(value.reshape(1,-1))[0]}\t{correct}")
    
