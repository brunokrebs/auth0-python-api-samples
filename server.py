import jwt
import os

from functools import wraps
from flask import Flask, request, jsonify, _app_ctx_stack, send_from_directory
from flask_cors import cross_origin

app = Flask(__name__, static_folder = 'public')

# Format error response and append status code.
def handle_error(error, status_code):
    resp = jsonify(error)
    resp.status_code = status_code
    return resp

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get('Authorization', None)
        if not auth:
            return handle_error({'code': 'authorization_header_missing',
                                'description':
                                    'Authorization header is expected'}, 401)

        parts = auth.split()

        if parts[0].lower() != 'bearer':
            error_message = 'Authorization header must start with Bearer'
            return handle_error({'code': 'invalid_header', 'description': error_message }, 401)
        elif len(parts) == 1:
            return handle_error({'code': 'invalid_header', 'description': 'Token not found'}, 401)
        elif len(parts) > 2:
            error_message = 'Authorization header must be Bearer + \s + token'
            return handle_error({'code': 'invalid_header', 'description': error_message}, 401)

        token = parts[1]
        try:
            payload = jwt.decode(
                token,
                'Z2SDgQpLzxiADLz3PD6L17kanR2qeqMgMo7gMvYeg8ASJK5H2Pnd4KxfG1Kh4dwp',
                audience='pe1TeJnjahK0nZR0Q1waZlMCAJg0sNz6'
            )
        except jwt.ExpiredSignature:
            return handle_error({'code': 'token_expired',
                                'description': 'token is expired'}, 401)
        except jwt.InvalidAudienceError:
            return handle_error({'code': 'invalid_audience',
                                'description': 'incorrect audience, expected: '
                                 + client_id}, 401)
        except jwt.DecodeError:
            return handle_error({'code': 'token_invalid_signature',
                                'description':
                                    'token signature is invalid'}, 401)
        except Exception:
            return handle_error({'code': 'invalid_header',
                                'description': 'Unable to parse authentication'
                                 ' token.'}, 400)

        _app_ctx_stack.top.current_user = payload
        return f(*args, **kwargs)

    return decorated

# Controllers API

@app.route('/<path:filename>')
def send_file(filename):
    return send_from_directory(app.static_folder, filename)

@app.route("/ping")
@cross_origin(headers=['Content-Type', 'Authorization'])
def ping():
    return "All good. You don't need to be authenticated to call this"


@app.route("/secured/ping")
@cross_origin(headers=['Content-Type', 'Authorization'])
@cross_origin(headers=['Access-Control-Allow-Origin', '*'])
@requires_auth
def securedPing():
    return "Indeed you are authorized"


if __name__ == "__main__":
    app.run(host='0.0.0.0', port=os.environ.get('PORT', 3001))
