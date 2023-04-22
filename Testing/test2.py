# -*- coding: utf-8 -*-
"""
Spyder Editor

This is a temporary script file.
"""


import pandas as pd
import re
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
from sklearn.pipeline import Pipeline

df = pd.read_csv("C:\\Users\\damia\\Documents\\GitHub\\ML_Malicous_URL_Classification\\malicious_phish.csv")

def query_domain_length(query):
    try:
        length = len(query.split('.')[-2])
    except:
        length = 0
    return length


def is_ip_address_present(s):
    ipv4_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    ipv6_pattern = r"\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    ipv4_match = re.search(ipv4_pattern, s)
    ipv6_match = re.search(ipv6_pattern, s)
    if ipv4_match or ipv6_match:
        return 1
    else:
        return 0
    
def extract_url_attributes(url):
    attributes = ['scheme', 'netloc', 'path', 'params', 'query', 'fragment']
    parsed = urlparse(url)
    result = {}
    for attribute in attributes:
        result[f"{attribute}_present"] = 1 if getattr(parsed, attribute) != '' else 0
    return result
for attribute in ['scheme', 'netloc', 'path', 'params', 'query', 'fragment']:
    df[f"{attribute}_present"] = df['url'].apply(lambda x: extract_url_attributes(x)[f"{attribute}_present"])


def has_malicious_file_extension(s):
    pattern = r"(\.exe|\.dll|\.bat|\.cmd|\.msi|\.vbs|\.ps1|\.psm1|\.js|\.jse|\.wsh|\.wsf|\.hta|\.scr|\.pif|\.cpl" \
              r"|\.ade|\.adp|\.bas|\.chm|\.cmd|\.com|\.crt|\.csh|\.hlp|\.inf|\.ins|\.isp|\.job|\.js|\.jse|\.lnk|\.mda" \
              r"|\.mdb|\.mde|\.mdt|\.mdw|\.mdz|\.msc|\.msi|\.msp|\.mst|\.nws|\.pcd|\.prf|\.reg|\.scf|\.shb|\.shs" \
              r"|\.tmp|\.url|\.vb|\.vbe|\.vbs|\.wsc|\.wsf|\.wsh)$"
    match = re.search(pattern, s, re.IGNORECASE)
    return 1 if bool(match) else 0


def has_shortened_link(url):
    shortening_services = ["bit.ly", "t.co", "tinyurl.com", "ow.ly", "goo.gl", "is.gd", "buff.ly", "adcrun.ch",
                           "qr.net", "adf.ly", "bc.vc", "ow.ly", "po.st", "tr.im", "v.gd", "x.co", "tiny.cc",
                           "tinyurl.co.uk", "tinyurl.de", "tinyurl.fr", "tinyurl.pl", "tinylink.in", "tinyuri.ca",
                           "tinyurl.dk", "url.ie", "zi.pe"]
    for service in shortening_services:
        pattern = fr"\b{service}\b"
        if re.search(pattern, url, re.IGNORECASE):
            return 1
    return 0





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


#df['type'] = df['type'].apply(lambda x: 'benign' if x == 'benign' else 'malicious')
df["url_len"] = df["url"].apply(lambda x: len(x))
df["url_parts"] = df["url"].apply(lambda x: len(x.split(".")))
df["suffix_len"] = df["url"].apply(lambda x: len(x.split(".")[-1]))
df["domain_len"] = df["url"].apply(query_domain_length)
df['digit_count'] = df['url'].apply(lambda s: sum(c.isdigit() for c in s))
df['alpha_count'] = df['url'].apply(lambda s: sum(c.isalpha() for c in s))
df["ip_present"] = df["url"].apply(is_ip_address_present)
df["file_extension"] = df["url"].apply(has_malicious_file_extension)
df["shorted_link"] = df["url"].apply(has_shortened_link)
df["url_attributes"] = df["url"].apply(extract_url_attributes)
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


#df.columns





X = df.drop(["type","url"],axis=1)
y = df["type"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=101)


#scaler = StandardScaler()   
#rfc = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)

pipeline = Pipeline([
    ('scaler', StandardScaler()),
    ('random_forest', RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42))
])


pipeline.fit(X_train,y_train)

scaler = pipeline.named_steps["scaler"]


y_pred = pipeline.predict(X_test)

plot_confusion_matrix(pipeline,X_test,y_test)

print(classification_report(y_test,y_pred))








def preprocess_input(input_data):
    """
    Takes in a string url as input and does preprocessing of all steps to get ready for prediction
    """
    df = pd.DataFrame({"url": [input_data]})
    
    df["type"] = df["url"].apply(lambda x: 0)
    df["url_len"] = df["url"].apply(lambda x: len(x))
    df["url_parts"] = df["url"].apply(lambda x: len(x.split(".")))
    df["suffix_len"] = df["url"].apply(lambda x: len(x.split(".")[-1]))
    df["domain_len"] = df["url"].apply(query_domain_length)
    df['digit_count'] = df['url'].apply(lambda s: sum(c.isdigit() for c in s))
    df['alpha_count'] = df['url'].apply(lambda s: sum(c.isalpha() for c in s))
    df["ip_present"] = df["url"].apply(is_ip_address_present)
    df["file_extension"] = df["url"].apply(has_malicious_file_extension)
    df["shorted_link"] = df["url"].apply(has_shortened_link)
    df["url_attributes"] = df["url"].apply(extract_url_attributes)
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
    for attribute in ['scheme', 'netloc', 'path', 'params', 'query', 'fragment']:
        df[f"{attribute}_present"] = df['url'].apply(lambda x: extract_url_attributes(x)[f"{attribute}_present"])
    return df

test = preprocess_input("hahahaha")


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
    
