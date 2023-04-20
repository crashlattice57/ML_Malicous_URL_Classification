import pandas as pd
import numpy as np
import re
from sklearn.preprocessing import StandardScaler
import pickle
from flask import Flask, request, jsonify
import json


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


def preprocess_input(input_data):
    """
    Takes in a string url as input and does preprocessing of all steps to get ready for prediction
    """
    df = pd.DataFrame({"url": [input_data]})

    df["url_len"] = df["url"].apply(lambda x: len(x))
    df["url_parts"] = df["url"].apply(lambda x: len(x.split(".")))
    df["suffix_len"] = df["url"].apply(lambda x: len(x.split(".")[-1]))
    df["domain_len"] = df["url"].apply(query_domain_length)
    df["ip_present"] = df["url"].apply(is_ip_address_present)
    df["file_extension"] = df["url"].apply(has_malicious_file_extension)
    df["shorted_link"] = df["url"].apply(has_shortened_link)

    special_char = ["%", "=", "/", "?", ":", "+", "@", "&", "#", "<", ">", "^"]
    for special in special_char:
        df[f'{special}_count'] = df["url"].apply(lambda x: x.count(special))
    X = df.drop("url", axis=1)
    scaler = StandardScaler()
    scaled_X_test = scaler.fit_transform(X)
    return scaled_X_test


##LOAD in model using pickle
with open("rf.pk1", "rb") as f:
    clf = pickle.load(f)

app = Flask(__name__)


@app.route("/predict", methods=["POST"])
def predict():
    # get the input data from the request
    data = request.get_json()
    data = json.dumps(data)
    # preprocess the input data
    X = preprocess_input(data)
    # make predictions using the loaded model
    y_pred = clf.predict(X)
    # return the predictions as a JSON response
    #print(y_pred)
    return jsonify({'prediction': str(y_pred[0])})


if __name__ == '__main__':
    app.run()
