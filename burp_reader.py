import base64
import xml.etree.ElementTree as ET


class BurpRequestItem:
    def __init__(self, method, url, host, port, protocol, path, extension, request, status):
        self.method = method
        self.url = url
        self.host = host
        self.port = port
        self.protocol = protocol
        self.path = path
        self.extension = extension
        self.raw_request = request  # Base64 dekódolva tároljuk
        self.status = status


class BurpResponseItem:
    def __init__(self, response, mimetype):
        self.raw_response = response  # Base64 dekódolva tároljuk
        self.mimetype = mimetype


class BurpRequests:
    def __init__(self, filename):
        self.filename = filename
        self.items = []
        self.parse_file()

    def parse_file(self):
        tree = ET.parse(self.filename)
        root = tree.getroot()

        for item in root.findall("item"):
            # Alapadatok lekérése
            method = item.find("method").text
            url = item.find("url").text
            host = item.find("host").text
            port = item.find("port").text
            protocol = item.find("protocol").text
            path = item.find("path").text
            extension = item.find("extension").text
            status = item.find("status").text

            # Request feldolgozása (base64 dekódolás, ha szükséges)
            request_element = item.find("request")
            request_data = request_element.text
            if request_element.get("base64") == "true":
                request_data = base64.b64decode(request_data).decode(errors="ignore")

            # Response feldolgozása (base64 dekódolás, ha szükséges)
            response_element = item.find("response")
            response_data = response_element.text if response_element is not None else ""
            if response_element is not None and response_element.get("base64") == "true":
                response_data = base64.b64decode(response_data).decode(errors="ignore")

            mimetype = item.find("mimetype").text if item.find("mimetype") is not None else ""

            # Példányok létrehozása
            request_item = BurpRequestItem(method, url, host, port, protocol, path, extension, request_data, status)
            response_item = BurpResponseItem(response_data, mimetype)

            # Adatok hozzáadása listához
            self.items.append((request_item, response_item))


# Használat például a testingburp.txt fájl feldolgozására
#burp_requests = BurpRequests("/tmp/a/testingburp.txt")

# Első request és response kiírása
#if burp_requests.items:
#    req, res = burp_requests.items[0]
#    print("Request Method:", req.method)
#    print("Request URL:", req.url)
    #print("Decoded Request:", req.raw_request[:500])  # Csak az első 500 karakter
#    print("\n\nRESPONSE: \n\n")
    #print("Response Mimetype:", res.mimetype)
#    print("Decoded Response:", res.raw_response)  # Csak az első 500 karakter
