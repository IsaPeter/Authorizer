# Authorizer

Authorizer is a Python tool designed to **resend and modify HTTP requests** extracted from Burp Suite. It allows testing authorization mechanisms by replaying requests with different authentication methods, cookies, and headers.

## **Features**
- Replay HTTP requests with modified authentication (Basic Auth, Bearer Token).
- Remove authentication or cookies to test authorization weaknesses.
- Read requests exported from **Burp Suite**.
- Custom headers and cookies support.


## **Installation**
Ensure you have **Python 3** installed, then clone the repository:

```bash
git clone https://github.com/IsaPeter/authorizer.git
cd authorizer
pip install -r requirements.txt 
```

## Help

```bash
usage: authorizer.py [-h] [-r] [-H  [...]] [--replay] [--list-urls] [--count] [--basic-auth] [--basic-auth-b64] [--bearer] [-bf] [--cookie] [-cf] [-woa] [-x] [-t]

options:
  -h, --help            show this help message and exit
  -r , --requests       Set Burp Exported Requests
  -H  [ ...], --header  [ ...]
                        Set custom header to the request.
  --replay              Replay Original Requests
  --list-urls           List available urls
  --count               Print Parsed Requests Count

Authentication Options:
  --basic-auth          Set Basic Authentication
  --basic-auth-b64      Set Already B64 Basic Authentication
  --bearer              Set Bearer Token
  -bf , --bearer-file   Read Bearer Token from file
  --cookie              Set Cookies to the request
  -cf , --cookie-file   Set Cookies from file
  -woa, --witout-auth   Generate requests withoit Authorizational data

Replay Sending Options:
  -x , --proxy          Set the proxy value
  -t , --timeout        Set the timeout value
```



## Usage

Run the script with different authentication and request replay options.

### Replay the whole set of requests without modification

```bash
python authorizer.py -r /path/to/burp_requests --replay
```

### Basic Authentication Examples

Specify a clear authentication string `username:password`
```bash
python authorizer.py -r burp_requests.txt --basic-auth "admin:password"
```


Specify an already Base64 encoded string `YWRtaW46cGFzc3dvcmQ=`

```bash
python authorizer.py -r burp_requests.txt --basic-auth "YWRtaW46cGFzc3dvcmQ="
```

### Bearer Token Examples

Specify a Bearer Token for Authorization

```bash
python authorizer.py -r burp_requests --bearer "your_token_here"
```

Or place the token in text file and read pass it to the script

```bash
python authorizer.py -r burp_requests -bf bearer_file 
```

### Set Custom Cookie Values

```bash
python authorizer.py -r burp_requests --cookie "sessionId=<value>; foo=bar; bar=baz"
```

### Remove Authorization & Cookie Headers

```bash
python authorizer.py -r burp_requests -woa
```


### Set Custom headers append to the requests

```bash
python authorizer.py -r burp_requests -H "User-Agent: CustomAgent" -H "Referer: https://example.com"
```


### List available URL's

```bash
python3 authorizer.py -r burp_requests --list-urls
```

### Check Requests Count in a Burp Exported File

```bash
python authorizer.py -r burp_requests --count
```
