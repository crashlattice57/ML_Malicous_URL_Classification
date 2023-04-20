# -*- coding: utf-8 -*-
"""
Created on Thu Apr 20 04:27:08 2023

@author: damia
"""




import ssl
import socket
import pandas as pd

df = pd.read_csv("C:\\Users\\damia\\Documents\\GitHub\\ML_Malicous_URL_Classification\\malicious_phish.csv")

def has_ssl_cert(url, timeout=0.1):
    try:
        # Extract the hostname from the URL
        hostname = url.split("//")[-1].split("/")[0]
        print(f"connection with {url}")
        # Connect to the hostname on port 443 (the default HTTPS port)
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                # Check whether the SSL certificate is valid
                cert = ssock.getpeercert()
                print(f"connection complete")
                if len(cert) > 1:
                    print("1")
            return 1 if cert is not None else 0
    except :
        return -1



df["has_ssl_cert"] = df["url"].apply(has_ssl_cert)





print(has_ssl_cert("https://www.google.com"))


