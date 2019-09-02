#!/usr/bin/env python
import os
from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import request, make_response, jsonify
from ldap_auth import LdapAuth


load_dotenv(find_dotenv('.env'))

app = Flask(__name__)
auth = LdapAuth(os.environ.get('LDAP_ADDRESS'))
auth.base_dn = os.environ.get('LDAP_BASE_DN')
auth.bind_dn = os.environ.get('LDAP_BIND_DN')
auth.bind_pass = os.environ.get('LDAP_BIND_PASS')


@app.route('/')
@app.route('/auth-proxy')
def basic_auth_check():
    if not request.authorization:
        return make_response('Authorization required', 401)

    username = request.authorization['username']
    password = request.authorization['password']

    if not password or len(password) == 0:
        return make_response('Password required', 401)

    message, authorized = auth.check(username, password)
    if authorized:
        return make_response(message, 200)
    else:
        return make_response(message, 401)

if __name__ == '__main__':
    auth.assert_configs()
    host = os.environ.get('APP_BIND', '127.0.0.1')
    port = os.environ.get('APP_PORT', '8080')
    debug = os.environ.get('APP_DEBUG', 'false') in ['true', 'yes', '1']
    app.run(host=host, port=port, debug=debug)
