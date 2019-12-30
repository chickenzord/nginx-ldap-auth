import os
from prometheus_client import Gauge, Counter

labels = ['hostname', 'server']
prefix = os.environ.get('METRICS_PREFIX', 'nginx_ldap_')


server_reachable = Gauge(
    prefix + 'server_reachable',
    'LDAP server connection status',
    labels
)

server_bound = Gauge(
    prefix + 'server_bound',
    'LDAP server binding status',
    labels
)

auth_success = Counter(
    prefix + 'auth_success_total',
    'Total successful LDAP authentication attempts',
    labels
)

auth_failure = Counter(
    prefix + 'auth_failure_total',
    'Total failed LDAP authentication attempts',
    labels
)
