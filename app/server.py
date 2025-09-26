from fastapi import FastAPI
import joblib
import whois
import requests
from bs4 import BeautifulSoup
import urllib.parse
from datetime import datetime
import dns.resolver
import re
import sys

# --- Helper Functions ---

def get_domain(url):
    try:
        return urllib.parse.urlparse(url).netloc
    except:
        return None

def get_soup(url):
    """Fetches the URL and returns a BeautifulSoup object, or None on failure."""
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()  # Raise an exception for bad status codes
        return BeautifulSoup(response.text, 'html.parser')
    except requests.exceptions.RequestException:
        return None

# --- Feature Extraction Functions ---

def having_ip_address(url):
    try:
        domain = get_domain(url)
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
            return -1
        return 1
    except:
        return -1

def url_length(url):
    if len(url) < 54: return 1
    if 54 <= len(url) <= 75: return 0
    return -1

def shortening_service(url):
    domain = get_domain(url)
    shortening_services = [
        "bit.ly", "goo.gl", "t.co", "tinyurl.com", "is.gd", "cli.gs", 
        "tr.im", "ow.ly", "tiny.cc"
    ]
    if domain in shortening_services: return -1
    return 1

def having_at_symbol(url):
    return -1 if "@" in url else 1

def double_slash_redirecting(url):
    # Checks for "//" in the path part of the URL
    path = urllib.parse.urlparse(url).path
    return -1 if path.startswith('//') or "//" in path[1:] else 1

def prefix_suffix(url):
    return -1 if "-" in get_domain(url) else 1

def having_sub_domain(url):
    dots = get_domain(url).count('.')
    # Standard domains like google.com have 1 dot.
    if dots == 2: return 0   # e.g., mail.google.com
    if dots > 2: return -1    # e.g., my.app.mail.google.com
    return 1                 # e.g., google.com

def ssl_final_state(url):
    # This is a simplified check. A full check is more complex.
    return 1 if url.startswith("https") else -1

def domain_registration_length(url):
    try:
        domain = get_domain(url)
        w = whois.whois(domain)
        if w.expiration_date and w.creation_date:
            exp = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
            cre = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            if (exp - cre).days / 365 <= 1:
                return -1
        return 1
    except:
        return -1

def age_of_domain(url):
    try:
        domain = get_domain(url)
        w = whois.whois(domain)
        if w.creation_date:
            cre = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
            if (datetime.now() - cre).days < 180:
                return -1
        return 1
    except:
        return -1

def dns_record(url):
    try:
        dns.resolver.resolve(get_domain(url), 'A')
        return 1
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return -1

# --- NEWLY IMPLEMENTED FUNCTIONS ---

def favicon(url):
    soup = get_soup(url)
    if not soup: return -1
    # Check if favicon is loaded from the same domain
    icon_link = soup.find("link", rel=re.compile(r'icon', re.I))
    if icon_link and icon_link.has_attr('href'):
        href_domain = get_domain(urllib.parse.urljoin(url, icon_link['href']))
        if href_domain != get_domain(url):
            return -1 # Favicon from a different domain is suspicious
    return 1

def request_url(url):
    soup = get_soup(url)
    if not soup: return -1
    
    domain = get_domain(url)
    image_count = 0
    external_image_count = 0
    
    for img in soup.find_all('img'):
        if img.has_attr('src'):
            image_count += 1
            src_domain = get_domain(urllib.parse.urljoin(url, img['src']))
            if src_domain != domain:
                external_image_count += 1
    
    if image_count == 0: return 1 # No images, no external content
    
    percentage = (external_image_count / image_count) * 100
    if percentage < 22.0: return 1
    if 22.0 <= percentage < 61.0: return 0
    return -1

def url_of_anchor(url):
    soup = get_soup(url)
    if not soup: return -1

    domain = get_domain(url)
    anchor_count = 0
    external_anchor_count = 0

    for a in soup.find_all('a'):
        if a.has_attr('href'):
            anchor_count += 1
            href = a['href']
            # Ignore empty, mailto, or javascript links
            if href.startswith('#') or href.startswith('mailto:') or 'javascript:void(0)' in href:
                anchor_count -= 1 # Don't count these
                continue
            
            href_domain = get_domain(urllib.parse.urljoin(url, href))
            if href_domain != domain:
                external_anchor_count += 1

    if anchor_count == 0: return 1

    percentage = (external_anchor_count / anchor_count) * 100
    if percentage < 31.0: return 1
    if 31.0 <= percentage < 67.0: return 0
    return -1

def abnormal_url(url):
    try:
        domain = get_domain(url)
        w = whois.whois(domain)
        # If the domain name is not in the WHOIS response text, it's suspicious
        if domain.lower() not in str(w).lower():
            return -1
        return 1
    except:
        return -1

# --- Functions That Are Hard to Implement ---
def web_traffic(url): return 0
def page_rank(url): return 0
def google_index(url): return 1
def links_pointing_to_page(url): return 0

# --- Functions that were already placeholders in the dataset logic ---
def port(url): return 1
def https_token(url): return 1
def links_in_tags(url): return 1
def sfh(url): return 1
def submitting_to_email(url): return 1
def redirect(url): return 1
def on_mouseover(url): return 1
def right_click(url): return 1
def popup_window(url): return 1
def iframe(url): return 1
def statistical_report(url): return 1

# =================================================================
# === PREDICTION LOGIC (Now more accurate)                      ===
# =================================================================
def predict_url(model, url):
    """Predicts the class of a URL and returns the label and confidence score."""
    if dns_record(url) == -1:
        return "Unsafe (Phishing)", 1.0

    features = [
        having_ip_address(url), url_length(url), shortening_service(url),
        having_at_symbol(url), double_slash_redirecting(url), prefix_suffix(url),
        having_sub_domain(url), ssl_final_state(url), domain_registration_length(url),
        favicon(url), port(url), https_token(url), request_url(url), url_of_anchor(url),
        links_in_tags(url), sfh(url), submitting_to_email(url), abnormal_url(url),
        redirect(url), on_mouseover(url), right_click(url), popup_window(url),
        iframe(url), age_of_domain(url), dns_record(url), web_traffic(url),
        page_rank(url), google_index(url), links_pointing_to_page(url),
        statistical_report(url)
    ]
    
    try:
        prediction = model.predict([features])[0]
        probabilities = model.predict_proba([features])[0]
        confidence = max(probabilities)
        
        label_map = {1: "Safe", 0: "Neutral", -1: "Unsafe (Phishing)"}
        label = label_map.get(prediction, "Unknown")
        
        return label, confidence
    except Exception as e:
        return f"Error during prediction: {e}", 0.0

# --- FastAPI App ---

app = FastAPI()

# Load the trained model
try:
    model = joblib.load('app/phishing_gradient_boosting_model.joblib')
except FileNotFoundError:
    print("Model file 'app/phishing_gradient_boosting_model.joblib' not found.")
    sys.exit(1)


@app.get('/')
def read_root():
    return {'message': 'Phishing URL Detection API'}

@app.get('/predict')
def predict_url_endpoint(url: str):
    """
    Predicts if a URL is a phishing URL and returns the label and confidence score.
    """
    test_url = url
    
    if not test_url.startswith(('http://', 'https://')):
        test_url = 'https://' + test_url
    
    label, confidence = predict_url(model, test_url)
    return {"prediction": label, "confidence": float(confidence), "url": test_url}
