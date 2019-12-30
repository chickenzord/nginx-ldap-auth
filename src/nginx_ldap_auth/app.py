import os
from . import ldap_auth
from flask import Flask
from flask import request, make_response, jsonify
from dotenv import load_dotenv, find_dotenv


def create_app():
    auth = ldap_auth.create_from_env()
    app = Flask('nginx-ldap-auth')

    @app.route('/')
    @app.route('/auth-proxy')
    def basic_auth_check():

        def unauthorized(message):
            r = make_response(message, 401)
            r.headers['WWW-Authenticate'] = 'Basic realm="LDAP login", charset="UTF-8"'
            return r

        if not request.authorization:
            return unauthorized('Authorization required')

        username = request.authorization['username']
        password = request.authorization['password']

        if not password or len(password) == 0:
            return unauthorized('Password required')

        message, authorized = auth.check_credentials(username, password)
        if authorized:
            return make_response(message, 200)
        else:
            return unauthorized(message)

    @app.route('/ping')
    def ping():
        return 'pong'

    @app.route('/status')
    def status():
        import socket

        ldap_reachable = auth.check_connection()
        ldap_bound = auth.check_binding()
        res = jsonify({
            'hostname': socket.gethostname(),
            'ldap_address': auth.address,
            'ldap_bound': ldap_bound,
            'ldap_reachable': ldap_reachable,
        })
        res.status_code = 200 if ldap_reachable and ldap_bound else 500

        return res

    return app

if __name__ == '__main__':
    ENV_FILE = os.environ.get('ENV_FILE', '.env')
    print('Loading environment from file: ' + ENV_FILE)
    load_dotenv(find_dotenv(ENV_FILE, usecwd=True))
    app = create_app()

    host = os.environ.get('APP_BIND', '127.0.0.1')
    port = os.environ.get('APP_PORT', '8080')
    debug = os.environ.get('APP_DEBUG', 'false') in ['true', 'yes', '1']
    app.run(host=host, port=port, debug=debug)
