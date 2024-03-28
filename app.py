from flask import Flask, request, jsonify
import requests
import json
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import base64

app = Flask(__name__)

# Private Key
private_key_str = """
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDDUK2nU5zE4Z+EptAquEl0HhVcG5OskCRig5PfI4lUxVkO1+38
mZ0P895neZTasw3hdWLOdkPLcmkmup5aPEGZplVheLVGF/beAni4ytZAjhyNFmIl
k1tE2Xygqb+KId+MiXp9mPXBnQA/mz1COzeJkYab5JztWdksAYU4CXzf1wIDAQAB
AoGALxi2NwHvbH4nU/pReeukMq7KYcJ4koTTcTnfH1BXXiyUNAMXbPCxsdYRTAxC
O5Yvg60lnTlhUZ6OAnu/kWy0OGbUW8whkoYy4W6qIexYIeERCp/J06XX6JvyDZ5O
WnZg0rF4+QiMj3379D57MEZ/8A9+vClNggJfs3fx3etpc6kCQQD/4ElkhuyiF4D1
KDxEKIu3jPtUxuSVws0QKxsxRTLwAMkf5v5URVSeADVNwyKqLVoVWW33IPXq11BZg
JgF+xRjAkEAw2jivga/U4oQKRqAFQ3+Ck2cNSqDyUtyyHtGQSg+2fN7NOakCFpPD
Pkaaf9Nj9ZrTXoNJ9Lnag4PC/aZOLt+/QJAeypA6aywls1te5RkfgJuTmoESKh8O
0JLZu745dyDSld2eG6+GV5N/sfm4Il/VB8Eb6ZeckhhVytRN+PYSXi0NQJAPb0Lt
oInPNuoE3R99yj+lH7E1b9i99xQnarlHXz7rpzQ1nvwY3s08qJZiBfTh5h1OntP
YL+vwcBDXMJC0rvaeQJAcWHXZJ+IKCNGLgG4oN9+1IIK9ptuoANo54aMtSd4zUMR
vV9cmvNyEqwHFYDywzxzqp9TvYGcROZsZSbc7A+e5w==
-----END RSA PRIVATE KEY-----
"""

def get_bearer_token():
    token_response = requests.get("http://omega-india-phoenix.redbus.in:8001/phoenix/UPSRTC/upsrtc_token")
    token_response.raise_for_status()  # Raise error if request fails
    return token_response.json()['token']


# Load Private Key
private_key = serialization.load_pem_private_key(
    private_key_str.encode(),
    password=None,
    backend=default_backend()
)

@app.route('/get_booking', methods=['GET'])
def get_booking():
    print("Hii")
    booking_id = str(request.args.get('bookingid'))
    print(type(booking_id))

    if not booking_id:
        return jsonify({'error': 'Booking ID is required'}), 400

    # Minified Post Body
    minified_post_body = f'{{"bookingId":"{booking_id}"}}'

    print(minified_post_body)

    # Sign Data
    signature = private_key.sign(
        minified_post_body.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    # Convert Signature to Base64
    signature_output = base64.b64encode(signature).decode()

    # Send the POST request
    url = 'http://upsrtcproxy.redbus.in/v1/bookings/cancellations'
    headers = {
        'Authorization': f'Bearer {get_bearer_token()}',
        'Signature': signature_output,
        'Content-Type': 'application/json',
        'Cookie': 'AWSALB=DNzhiTIKFs0/MCL1lSvNCEXaVYVxz+8k3GMK+81NljEnpxXEt/GFLjuWRzMwDszjf5zlKGhsDE8RNMh3aSYtYYRpkj9twxdw5yEsMBLcIMemeGnMx9h38L6V+nfJ; AWSALBTG=Bxp9ke1Zbg/fGUGAxptU4RZHnjjQZhvzt6JtnFqUlBzVA7YJvgRqKs8Au50UEJeK1LkjELa0k8B/YFTpps9g/XsP95gedT6BrTVdQiZDYb3CW+8QHmzPfSdfenuQfrVb4dhJYrp/7mkaPIjT5dsq8barPdMz9q4AlUBkvJ/EI2B2Nxnecog='
    }
    print(headers)
    data = {
    "bookingId": "0000000C7691"
}

    response = requests.post(url, headers=headers, json=data)
    print(response)

    return jsonify({
        "status_code": response.status_code,
        "response_body": response.text
    })

if __name__ == '__main__':
    app.run(debug=True)