import requests from bs4 import BeautifulSoup
import time import logging class Scanner :
    def __init__ ( self,
url, links_to_ignore=None, rate_limit=1 ): self.session = requests.Session() self.target_url = url self.links_to_ignore
= links_to_ignore or [] self.test_payloads = [ "<script>alert('test')</script>" ] self.rate_limit = rate_limit
logging.basicConfig(level=logging.INFO)
def _send_request ( self, method, url, **kwargs ): try :
time.sleep(self.rate_limit) return self.session.request(method, url, **kwargs) except requests.RequestException as
e: logging.error( f"Error during request to {url}: {str(e)}" ) return None
def extract_forms ( self, url ): response =
self._send_request( "GET" , url) if response: parsed_html = BeautifulSoup(response.content, features= "lxml" )
return parsed_html.findAll( "form" ) return []
def submit_form( self, form, payload, url ): form_details = {} action
= form.attrs.get( "action" ) post_url = f"{url}{action}" method = form.attrs.get( "method" ) inputs_list =
form.findAll( "input" ) for input_tag in inputs_list: input_name = input_tag.attrs.get( "name" ) input_type =
input_tag.attrs.get( "type" ) input_value = input_tag.attrs.get( "value" , "" ) if input_type == "text" : input_value =
payload form_details[input_name] = input_value return self._send_request(method, post_url, data=form_details if
method == "POST" else None , params=form_details if method == "GET" else None )
def scan_xss ( self, url ):
forms = self.extract_forms(url) logging.info( f"[+] Detected {len(forms)} forms on {url}." ) for form in forms: for
payload in self.test_payloads: response = self.submit_form(form, payload, url) if response and payload in
response.content.decode(): logging.warning( f"[+] Potential XSS detected on {url} in form {form.attrs}" )
def scan_csrf ( self, url ): forms = self.extract_forms(url) for form in forms: if not any (input_tag.attrs.get( "name" )
== "csrf_token" for input_tag in form.findAll( "input" )): logging.warning( f"[-] No CSRF token found in form on
{url}" ) def scan_error_messages ( self, url ): login_forms = self.extract_forms(url) for form in login_forms:
response = self.submit_form(form, "test' OR '1'='1" , url) if response and "Invalid username or password" not in
response.content.decode(): logging.warning( f"[!] Potential information disclosure in error message on {url}" )
def scan_bruteforce_protection ( self, url ): login_forms = self.extract_forms(url) for _ in range ( 5 ):
self.submit_