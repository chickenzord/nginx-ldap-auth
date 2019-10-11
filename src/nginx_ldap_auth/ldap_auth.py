import ldap
import json


def create_from_env():
    import os
    auth = LdapAuth(os.environ.get('LDAP_ADDRESS'))
    auth.base_dn = os.environ.get('LDAP_BASE_DN')
    auth.bind_dn = os.environ.get('LDAP_BIND_DN')
    auth.bind_pass = os.environ.get('LDAP_BIND_PASS')

    return auth


class LdapAuthException(Exception):
    pass


class LdapAuth(object):

    def __init__(self, address=None):
        self.address = address
        self.base_dn = None
        self.bind_dn = None
        self.bind_pass = None
        self.search_template = 'uid=%(username)s'

    def assert_configs(self):
        print(json.dumps({
            'address': self.address,
            'base_dn': self.base_dn,
            'bind_dn': self.bind_dn,
            'bind_pass': '***' if self.bind_pass else None,
            'search_template': self.search_template,
        }))
        assert self.address is not None
        assert self.base_dn is not None
        assert self.bind_dn is not None
        assert self.bind_pass is not None
        assert self.search_template is not None

    def check(self, username, password):
        # -> (str msg, bool authorized)
        try:
            self.whoami(username, password)
            return ("OK: "+username, True)
        except ldap.LDAPError as e:
            return (e.__class__.__name__, False)
        except Exception as e:
            return (str(e), False)

    def ping(self):
        # initialize
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        l = ldap.initialize(self.address)
        l.simple_bind_s(self.bind_dn, self.bind_pass)

        whoami = l.whoami_s()

        return whoami is not None and len(whoami) > 0

    def whoami(self, username, password):
        # initialize
        ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)
        l = ldap.initialize(self.address)
        l.simple_bind_s(self.bind_dn, self.bind_pass)

        # search user
        search_filter = self.search_template % {'username': username}
        users = l.search_s(self.base_dn, ldap.SCOPE_SUBTREE, search_filter)
        if len(users) == 0:
            msg = "User with username '%s' not found on %s" % (username, self.base_dn)
            raise LdapAuthException(msg)
        if len(users) > 1:
            raise LdapAuthException("Multiple users found")

        # try to verify user password
        user_dn, _ = users[0]
        l.simple_bind_s(user_dn, password)
        whoami = l.whoami_s()

        if whoami is None or len(whoami) == 0:
            raise LdapAuthException("Invalid username/password")

        return whoami
