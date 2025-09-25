import json
import requests
import sys

def test_url(url_to_test):
    """
    Sends a URL to the prediction API and prints the result.
    """
    api_url = 'http://localhost:8000/predict'
    payload = {'url': url_to_test}
    
    try:
        response = requests.post(api_url, json=payload)
        response.raise_for_status()  # Raise an exception for bad status codes
        
        print(f"Testing URL: {url_to_test}")
        print("Response:")
        print(json.dumps(response.json(), indent=2))
        print("-" * 30)

    except requests.exceptions.RequestException as e:
        print(f"Error connecting to the API: {e}")
        print("Please ensure the Docker container is running and accessible at", api_url)

if __name__ == "__main__":
    # Example URLs to test
    urls = [
        "google.com",
        "youtube.com",
        "facebook.com",
        "this-is-a-very-long-url-to-test-the-length-feature.com",
        "http://123.45.67.89/login",
        "example.com/path/with//double-slash",
        "some-site-with-prefix.com",
        "sub.domain.example.com",
        "bit.ly/shortened-url",
        "unsafe-site.com" # A generic potentially unsafe site
    ]

    # You can also provide a URL as a command-line argument
    if len(sys.argv) > 1:
        urls_to_test = sys.argv[1:]
    else:
        urls_to_test = urls

    for url in urls_to_test:
        test_url(url)
