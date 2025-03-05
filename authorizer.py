from argparse import ArgumentParser
from burp_reader import BurpRequests
from httplib import HTTPRequest, HTTPResponse, HTTPRequestSender
import base64


def parse_basic_auth(basic_auth):
    if ':' in basic_auth:
        return base64.b64encode(basic_auth.encode()).decode()
    else:
        if is_basic_auth(basic_auth):
            return basic_auth
        else:
            return base64.b64encode(basic_auth+":".encode()).decode()


def is_basic_auth(encoded_str):
    try:
        decoded_bytes = base64.b64decode(encoded_str, validate=True)  # Base64 dekódolás ellenőrzése
        decoded_str = decoded_bytes.decode('utf-8')  # UTF-8 dekódolás
        return ":" in decoded_str and decoded_str.count(":") == 1  # Pontosan egy `:` legyen benne
    except (base64.binascii.Error, UnicodeDecodeError):
        return False  # Ha nem lehet dekódolni, akkor nem Basic Auth
    
def parse_cookies(cookie_string):
    if ";" in cookie_string:
        return {c.split("=")[0].strip(): c.split("=")[1] for c in cookie_string.split(";")}
    else:
        if "=" in cookie_string:
            k,v = cookie_string.strip().split("=",1)
            return {k:v}
        else:
            return {}

def parse_headers(header_arr):
    headers = {header.split(":",1)[0].strip():header.split(":",1)[1].strip() for header in header_arr if ":" in header}
    return headers

def read_file(path):
    with open(path, "r") as file:
        data = file.read().replace("\n","")
    return data






def resend_requests_test(items, sender, wo_auth=False, basic_auth=None, bearer=None, cookies=None, headers=None, replay_original=False):
    
        breq,bresp = items[0]
        req = HTTPRequest(breq.raw_request)
        resp = HTTPResponse(raw_response=bresp.raw_response)
        orig_status_code = resp.status_code

        # Configure sender
        sender.address = breq.host
        sender.port_number = breq.port
        sender.protocol = breq.protocol

        if replay_original:
            orig_req = HTTPRequest(req.rebuild_request())
            if headers: orig_req.update_headers(headers)
            print("### [Original Request] ###\n\n")
            print(orig_req.rebuild_request())
            print("\n\n")

        # Check the request without authorization
        if wo_auth:
            req_wo_auth = HTTPRequest(req.rebuild_request())
            req_wo_auth.clear_cookies()
            req_wo_auth.clear_authorization()
            if headers: req_wo_auth.update_headers(headers)
            print("### [Request Without Cookies & Authorization] ###\n\n")
            print(req_wo_auth.rebuild_request())
            print("\n\n")

        # Clear only the authorization value if it exists
        if "Authorization" in req.headers:
            empty_auth = HTTPRequest(req.rebuild_request())
            empty_auth.clear_cookies()
            empty_auth.clear_authorization(only_value=True)
            if headers: empty_auth.update_headers(headers)
            print("### [Request without Authorization data, keep header] ###\n\n")
            print(empty_auth.rebuild_request())
            print("\n\n")


        # Replay the request with the provided basic auth
        if basic_auth:
            ba_req = HTTPRequest(req.rebuild_request())
            ba_req.set_basic_auth_b64(basic_auth)
            if headers: ba_req.update_headers(headers)
            print("### [Request With Custom Basic Auth] ###\n\n")
            print(ba_req.rebuild_request())
            print("\n\n")
            


        # Replay requests with the provided bearer token
        if bearer:
            bearer_req = HTTPRequest(req.rebuild_request())
            bearer_req.set_bearer_token(bearer)
            if headers: bearer_req.update_headers(headers)
            print("### [Request With Custom Bearer] ###\n\n")
            print(bearer_req.rebuild_request())
            print("\n\n")



        # Replay requests with the provided cookies
        if cookies:
            cookie_req = HTTPRequest(req.rebuild_request())
            cookie_req.clear_cookies()
            for k,v in cookies.items():
                cookie_req.set_cookie(k,v)
            if headers: cookie_req.update_headers(headers)
            print("### [Request with Custom Cookies] ###\n\n")
            print(cookie_req.rebuild_request())
            print("\n\n")

        print("#"*80)


def resend_requests(items, sender, wo_auth=False, basic_auth=None, bearer=None, cookies=None, headers=None, replay_original=False):
    for breq,bresp in items:
        req = HTTPRequest(breq.raw_request)
        resp = HTTPResponse(raw_response=bresp.raw_response)
        orig_status_code = resp.status_code

        # Configure sender
        sender.address = breq.host
        sender.port_number = breq.port
        sender.protocol = breq.protocol
        
        if replay_original:
            orig_req = HTTPRequest(req.rebuild_request())
            orig_resp = sender.send_request(orig_req)
            print(f"[*] URL: {breq.url} | Status Code [{str(orig_status_code)}] ==> [{orig_resp.status_code}]")

        # Check the request without authorization
        if wo_auth:
            req_wo_auth = HTTPRequest(req.rebuild_request())
            req_wo_auth.clear_cookies()
            req_wo_auth.clear_authorization()
            if headers: req_wo_auth.update_headers(headers)
            resp_wo_auth = sender.send_request(req_wo_auth)
            if resp_wo_auth.status_code == orig_status_code:
                print(f"[!] URL: {breq.url} | Status Code: {str(resp_wo_auth.status_code)} | Without Authorization & Cookies")

        # Clear only the authorization value if it exists
        if "Authorization" in req.headers:
            empty_auth = HTTPRequest(req.rebuild_request())
            empty_auth.clear_cookies()
            empty_auth.clear_authorization(only_value=True)
            if headers: empty_auth.update_headers(headers)
            resp_empty_auth = sender.send_request(empty_auth)
            if resp_empty_auth.status_code == orig_status_code:
                print(f"[!] URL: {breq.url} | Status Code: {str(resp_empty_auth.status_code)} | Without Cookies & Empty Authorization")

        # Replay the request with the provided basic auth
        if basic_auth:
            ba_req = HTTPRequest(req.rebuild_request())
            ba_req.set_basic_auth_b64(basic_auth)
            if headers: ba_req.update_headers(headers)
            ba_resp = sender.send_request(ba_req)
            if ba_resp.status_code == orig_status_code:
                print(f"[!] URL: {breq.url} | Status Code: {str(ba_resp.status_code)} | Basic Auth ==> {basic_auth}")

        # Replay requests with the provided bearer token
        if bearer:
            bearer_req = HTTPRequest(req.rebuild_request())
            bearer_req.set_bearer_token(bearer)
            if headers: bearer_req.update_headers(headers)
            bearer_resp = sender.send_request(bearer_req)
            if bearer_resp.status_code == orig_status_code:
                print(f"[!] URL: {breq.url} | Status Code: {str(bearer_resp.status_code)} | Bearer Token")

        # Replay requests with the provided cookies
        if cookies:
            cookie_req = HTTPRequest(req.rebuild_request())
            cookie_req.clear_cookies()
            for k,v in cookies.items():
                cookie_req.set_cookie(k,v)
            if headers: cookie_req.update_headers(headers)
            cookie_resp = sender.send_request(cookie_req)
            if cookie_resp.status_code == orig_status_code:
                cookie_list = ', '.join([k for k in cookies.keys()])
                print(f"[!] URL: {breq.url} | Status Code: {str(cookie_resp.status_code)} | Custom Cookies ==> {cookie_list}")





def parse_arguments():
    parser = ArgumentParser()
    parser.add_argument("-r","--requests", dest="requests", metavar="", help="Set Burp Exported Requests")
    parser.add_argument("-H", "--header", dest="custom_header", metavar="", action='extend', nargs='+', help="Set custom header to the request.")
    parser.add_argument("--replay", dest="replay_original", action="store_true",  help="Replay Original Requests")
    parser.add_argument("--list-urls", dest="list_urls", action="store_true",  help="List available urls")
    parser.add_argument("--count", dest="requests_count", action="store_true",  help="Print Parsed Requests Count")

    auth_parser = parser.add_argument_group('Authentication Options')
    auth_parser.add_argument("--basic-auth", dest="basic_auth", metavar="", help="Set Basic Authentication")
    auth_parser.add_argument("--basic-auth-b64", dest="basic_auth_b64", metavar="", help="Set Already B64 Basic Authentication")
    auth_parser.add_argument("--bearer", dest="bearer", metavar="", help="Set Bearer Token")
    auth_parser.add_argument("-bf","--bearer-file", dest="bearer_file", metavar="", help="Read Bearer Token from file")
    auth_parser.add_argument("--cookie", dest="cookie", metavar="", help="Set Cookies to the request")
    auth_parser.add_argument("-cf","--cookie-file", dest="cookie_file", metavar="", help="Set Cookies from file")
    auth_parser.add_argument("-woa","--witout-auth", dest="without_auth", action="store_true", help="Generate requests withoit Authorizational data")


    sender_parser = parser.add_argument_group('Replay Sending Options')
    sender_parser.add_argument("-x","--proxy", dest="proxy", metavar="", help="Set the proxy value")
    sender_parser.add_argument("-t","--timeout", dest="timeout", metavar="", help="Set the timeout value")


    return parser.parse_args()


def main():
    args = parse_arguments()

    basic_authentication = None
    bearer_token = None
    cookie_dict = None
    header_dict = {}
    burp_requests = None
    # Create the request sender
    request_sender = HTTPRequestSender()
    without_auth = False
    replay_original = False
    

    if args.without_auth:
        without_auth = True

    if args.basic_auth:
        basic_authentication = parse_basic_auth(args.basic_auth)

    if args.basic_auth_b64:
        basic_authentication = args.basic_auth_b64

    if args.bearer:
        bearer_token = args.bearer.replace("Bearer","").strip()

    if args.bearer_file:
        bearer_token = read_file(args.bearer_file).replace("Bearer","").strip()

    if args.cookie:
        cookie_dict = parse_cookies(args.cookie)

    if args.custom_header:
        header_dict = parse_headers(args.custom_header)

    if args.requests:
        burp_requests = BurpRequests(args.requests)
    
    if args.proxy:
        proxy = {
            "http":args.proxy,
            "https": args.proxy
        }
        request_sender.proxies = proxy

    if args.timeout:
        timeout = int(args.timeout)
        request_sender.request_timeout = timeout

    if args.cookie_file:
        data = read_file(args.cookie_file)
        cookie_dict = parse_cookies(data)

    if args.replay_original:
        replay_original = True


    if args.list_urls:
        if burp_requests:
            for i in list(set([item[0].url for item in burp_requests.items])):
                print(i)                

    if args.requests_count:
        if burp_requests:
            print("Requests Count: ", str(len(burp_requests.items)))
        else:
            print("Requests Count: 0")


    if burp_requests:
        resend_requests(burp_requests.items, request_sender, wo_auth=without_auth, basic_auth=basic_authentication, bearer=bearer_token, cookies=cookie_dict, headers=header_dict, replay_original=replay_original)







if __name__ == '__main__':
    main()


# PLAN
#
# Check requests without authentication eg: No Bearer, No Cookies, No basic auth
# Check to tamper which cookie is necessary for the request
# Check the request with the granted credentials
