import os
import prometheus_client
import socket
from . import ldap_auth
from . import ldap_metrics
from flask import Flask
from flask import request, make_response, jsonify, Response
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
            (ldap_metrics
                    .auth_success
                    .labels(hostname=socket.gethostname(),
                            server=auth.address)
                    .inc())
            return make_response(message, 200)
        else:
            (ldap_metrics
                    .auth_failure
                    .labels(hostname=socket.gethostname(),
                            server=auth.address)
                    .inc())
            return unauthorized(message)

    @app.route('/ping')
    def ping():
        return 'pong'

    def _fetch_status():
        ldap_reachable = auth.check_connection()
        ldap_bound = auth.check_binding()
        return {
            'hostname': socket.gethostname(),
            'ldap_address': auth.address,
            'ldap_bound': ldap_bound,
            'ldap_reachable': ldap_reachable,
        }

    @app.route('/status')
    def status():
        stat = _fetch_status()

        res = jsonify(stat)
        if stat['ldap_reachable'] and stat['ldap_bound']:
            res.status_code = 200
        else:
            res.status_code = 500

        return res

    @app.route('/metrics')
    def metrics():
        stat = _fetch_status()

        (ldap_metrics.server_reachable
            .labels(hostname=stat['hostname'],
                    server=stat['ldap_address'])
            .set(stat['ldap_reachable']))

        (ldap_metrics.server_bound
            .labels(hostname=stat['hostname'],
                    server=stat['ldap_address'])
            .set(stat['ldap_bound']))

        return Response(prometheus_client.generate_latest())

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
