import base64
import hashlib
import hmac
import time
import json

def base64_url_decode(payload):
    payload += '=' * (4 - (len(payload) % 4))
    return base64.urlsafe_b64decode(payload)

def verifyJwt(token, secret):
    parts = token.split('.')
    if len(parts) != 3:
        raise ValueError("Token must have exactly 3 parts.")

    header, payload, signature = parts
    # print(header, payload, signature)
    decoded_header = json.loads(base64_url_decode(header).decode('utf-8'))
    decoded_payload = json.loads(base64_url_decode(payload).decode('utf-8'))
    algorithm = decoded_header.get("alg")

    if algorithm not in ['HS256', 'HS512', 'HS384']:
        raise ValueError("Unsupported algorithm or invalid header")

    if algorithm == 'none':
        raise ValueError("Invalid algorithm")

    if algorithm == 'HS256':
        computed_signature = hmac.new(secret.encode(), (header + "." + payload).encode(), hashlib.sha256).digest()
    elif algorithm == 'HS512':
        computed_signature = hmac.new(secret.encode(), (header + "." + payload).encode(), hashlib.sha512).digest()
    elif algorithm == 'HS384':
        computed_signature = hmac.new(secret.encode(), (header + "." + payload).encode(), hashlib.sha384).digest()

    if base64_url_decode(signature) != computed_signature:
        raise ValueError("Invalid signature")

    if 'exp' in decoded_payload:
        if time.time() > decoded_payload['exp']:
            raise ValueError("Token has expired")


    return decoded_payload

def find_secret(jwt):
    s = "1234567890abcdefghijklmnopqrstuvwxyz"
    for a in s:
        for b in s:
            for c in s:
                for d in s:
                    for e in s:
                        print("Trying: ", a+b+c+d+e)
                        curr = a+b+c+d+e                           
                        try:
                            verifyJwt(jwt,curr)
                            return jwt, curr
                        except:
                            pass


# token = str(input("Please enter the token: "))
# # token = "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJUaGlzIGlzIGZvciBteSBhc3NpZ25tbmV0IGF0IElJSVQtRCwgZm9yIGEgc2VjdXJpdHkgY291cnNlIHVuZGVyIFByb2YuIEFydW4gQmFsYWppLiIsIm5hbWUiOiJDaGFpdGFueWEgQXJvcmEiLCJpYXQiOjE1MTYyMzkwMjIsImV4cCI6MTY5NDQ0MzUzMn0.9JzGe21KAjIdRIlvHozMKE8J8_0o836G9L9oEN4QwHqrIO0F9-XIwLW4pUx_BL9w"
# secret = str(input("Please enter the secret key: "))
# # secret = "c3a82562db6e313016fbc167e1c7cfb0d3ced034cfaed84f891179ee7336528d"
# print(verifyJwt(token, secret))
# print(time.time())
jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJmY3MtYXNzaWdubWVudC0xIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE3MDQwNjcyMDAsInJvbGxfbm8iOiIyMHh4eHh4IiwiZW1haWwiOiJhcnVuQGlpaXRkLmFjLmluIiwiaGludCI6Imxvd2VyY2FzZS1hbHBoYW51bWVyaWMtbGVuZ3RoLTUifQ.AgreujrDmdNIGbHc0fmF9yC7hnYxvhOLfOTdlgTfrXE"
# jwt, secret = find_secret(jwt)
# print(f"The secret is {secret}")
verifyJwt(jwt, "ac445")