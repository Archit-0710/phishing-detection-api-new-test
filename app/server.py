from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import whois
import requests
import urllib.parse
from datetime import datetime
import dns.resolver
import re
import sys
import numpy as np

# --- Feature Extraction Functions ---

def get_domain(url):
    try: return urllib.parse.urlparse(url).netloc
    except: return None

def having_ip_address(url):
    try:
        domain = get_domain(url)
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain): return -1
        return 1
    except: return -1

def url_length(url):
    if len(url) < 54: return 1
    elif 54 <= len(url) <= 75: return 0
    else: return -1

def shortening_service(url):
    shortening_services = ["bit.ly", "goo.gl", "t.co", "tinyurl.com"]
    domain = get_domain(url)
    if domain in shortening_services: return -1
    return 1

def having_at_symbol(url):
    if "@" in url: return -1
    return 1

def double_slash_redirecting(url):
    if "//" in urllib.parse.urlparse(url).path: return -1
    return 1

def prefix_suffix(url):
    domain = get_domain(url)
    if domain and "-" in domain: return -1
    return 1

def having_sub_domain(url):
    domain = get_domain(url)
    if not domain: return -1
    dots = domain.count('.')
    if dots == 2: return 0
    elif dots > 2: return -1
    return 1

def ssl_final_state(url):
    try:
        if url.startswith("https"): return 1
        return -1
    except: return -1

def domain_registration_length(url):
    try:
        domain = get_domain(url)
        w = whois.whois(domain)
        if w.expiration_date:
            exp_date = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            cre_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            if exp_date and cre_date:
                if (exp_date - cre_date).days / 365 <= 1: return -1
        return 1
    except: return -1

def age_of_domain(url):
    try:
        domain = get_domain(url)
        w = whois.whois(domain)
        if w.creation_date:
            cre_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            if (datetime.now() - cre_date).days < 180: return -1
        return 1
    except: return -1

def dns_record(url):
    try:
        domain = get_domain(url)
        if domain:
            dns.resolver.resolve(domain, 'A')
            return 1
        return -1
    except: return -1

# --- Placeholder Functions ---
def favicon(url): return 1
def port(url): return 1
def https_token(url): return 1
def request_url(url): return 1
def url_of_anchor(url): return 1
def links_in_tags(url): return 1
def sfh(url): return 1
def submitting_to_email(url): return 1
def abnormal_url(url): return 1
def redirect(url): return 1
def on_mouseover(url): return 1
def right_click(url): return 1
def popup_window(url): return 1
def iframe(url): return 1
def web_traffic(url): return 0
def page_rank(url): return 0
def google_index(url): return 1
def links_pointing_to_page(url): return 0
def statistical_report(url): return 1

# --- FastAPI App ---

app = FastAPI()

# Load the trained model
try:
    model = joblib.load('app/model.joblib')
except FileNotFoundError:
    print("Model file 'app/model.joblib' not found.")
    sys.exit(1)

class URLData(BaseModel):
    url: str

@app.get('/')
def read_root():
    return {'message': 'Phishing URL Detection API'}

@app.post('/predict')
def predict_url_endpoint(data: URLData):
    """
    Predicts if a URL is a phishing URL and returns the label and confidence score.
    """
    test_url = data.url
    
    if not test_url.startswith('http'):
        test_url = 'https://' + test_url

    if dns_record(test_url) == -1:
        return {"prediction": "Unsafe (Phishing)", "confidence": 1.0, "url": test_url}
    
    features = [
        having_ip_address(test_url), url_length(test_url), shortening_service(test_url),
        having_at_symbol(test_url), double_slash_redirecting(test_url), prefix_suffix(test_url),
        having_sub_domain(test_url), ssl_final_state(test_url), domain_registration_length(test_url),
        favicon(test_url), port(test_url), https_token(test_url), request_url(test_url), url_of_anchor(test_url),
        links_in_tags(test_url), sfh(test_url), submitting_to_email(test_url), abnormal_url(test_url),
        redirect(test_url), on_mouseover(test_url), right_click(test_url), popup_window(test_url),
        iframe(test_url), age_of_domain(test_url), dns_record(test_url), web_traffic(test_url),
        page_rank(test_url), google_index(test_url), links_pointing_to_page(test_url),
        statistical_report(test_url)
    ]
    
    try:
        prediction = model.predict([features])[0]
        probabilities = model.predict_proba([features])[0]
        confidence = max(probabilities)
        
        if prediction == 1:
            label = "Safe"
        elif prediction == 0:
            label = "Neutral"
        else:
            label = "Unsafe (Phishing)"
            
        return {"prediction": label, "confidence": float(confidence), "url": test_url}

    except Exception as e:
        return {"error": str(e)}
