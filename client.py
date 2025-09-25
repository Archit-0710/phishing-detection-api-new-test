import json
import requests
import sys

def test_url(url_to_test):
    """
    Sends a URL to the prediction API and prints the result.
    """
    api_url = 'https://phishing-detection-production-983e.up.railway.app/predict'
    params = {'url': url_to_test}
    
    try:
        response = requests.get(api_url, params=params)
        response.raise_for_status()  # Raise an exception for bad status codes
        
        print(f"Testing URL: {url_to_test}")
        print("Response:")
        print(json.dumps(response.json(), indent=2))
        print("-" * 30)

    except requests.exceptions.RequestException as e:
        print(f"Error connecting to the API: {e}")
        print("Please ensure the Docker container is running and accessible at", api_url)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python client.py <url1> <url2> ...")
        sys.exit(1)

    urls_to_test = sys.argv[1:]
    for url in urls_to_test:
        test_url(url)
