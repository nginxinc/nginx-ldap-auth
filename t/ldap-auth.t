#!/usr/bin/perl

# (C) Nginx, Inc.

# Test for nginx-ldap-auth daemon with OpenLDAP.

###############################################################################

use warnings;
use strict;

use Test::More;

use MIME::Base64;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';
use Test::Nginx;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

my $t = Test::Nginx->new()->has(qw/http proxy rewrite auth_request/)
	->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

events { }

daemon off;

http {

    %%TEST_GLOBALS_HTTP%%

    #proxy_cache_path cache/  keys_zone=auth_cache:10m;

    server {
        listen 127.0.0.1:8082;

        location / {
            return 200 "ACCESS GRANTED\n";
        }

        location /login {
            return 200 "LOGIN PAGE\n";
        }
    }

    upstream backend {
        server 127.0.0.1:8082;
    }

    server {
        listen 127.0.0.1:8080;

        location / {
            auth_request /auth-proxy;

            error_page 401 =200 /login;

            proxy_pass http://backend/;
        }

        location /ssl {
            auth_request /auth-proxy-ssl;

            error_page 401 =200 /login;

            proxy_pass http://backend/;
        }

        location /starttls {
            auth_request /auth-proxy-starttls;

            error_page 401 =200 /login;

            proxy_pass http://backend/;
        }

        location /nodn {
            auth_request /auth-nodn;

            error_page 401 =200 /login;

            proxy_pass http://backend/;
        }

        location /nourl {
            auth_request /auth-nourl;

            error_page 401 =200 /login;

            proxy_pass http://backend/;
        }

        location /ref1 {
            auth_request /auth-ref1;

            error_page 401 =200 /login;

            proxy_pass http://backend/;
        }

        location /login {
            proxy_pass http://backend/login;

            proxy_set_header X-Target $request_uri;
        }

        location = /auth-proxy {
            internal;

            proxy_pass http://127.0.0.1:8888;

            proxy_pass_request_body off;
            proxy_set_header Content-Length "";

            #proxy_cache auth_cache;
            #proxy_cache_valid 200 10m;
            #proxy_cache_key "$http_authorization$cookie_nginxauth";

            proxy_set_header X-Ldap-URL      "ldap://127.0.0.1:8083";
            proxy_set_header X-Ldap-BaseDN   "ou=Users,dc=test,dc=local";
            proxy_set_header X-Ldap-BindDN   "cn=root,dc=test,dc=local";
            proxy_set_header X-Ldap-BindPass "secret";

            proxy_set_header X-CookieName "nginxauth";
            proxy_set_header Cookie nginxauth=$cookie_nginxauth;

            #proxy_set_header X-Ldap-Starttls "true";

            #proxy_set_header X-Ldap-Template "(sAMAccountName=%(username)s)";
            #proxy_set_header X-Ldap-DisableReferrals "true";

            #proxy_set_header X-Ldap-Template "(cn=%(username)s)";
            #proxy_set_header X-Ldap-Realm    "Restricted";
        }

        location = /auth-proxy-ssl {
            internal;

            proxy_pass http://127.0.0.1:8888;

            proxy_pass_request_body off;
            proxy_set_header Content-Length "";

            proxy_set_header X-Ldap-URL      "ldaps://127.0.0.1:8084";
            proxy_set_header X-Ldap-BaseDN   "ou=Users,dc=test,dc=local";
            proxy_set_header X-Ldap-BindDN   "cn=root,dc=test,dc=local";
            proxy_set_header X-Ldap-BindPass "secret";

            proxy_set_header X-CookieName "nginxauth";
            proxy_set_header Cookie nginxauth=$cookie_nginxauth;

            #proxy_set_header X-Ldap-Starttls "true";
        }

       location = /auth-proxy-starttls {
            internal;

            proxy_pass http://127.0.0.1:8888;

            proxy_pass_request_body off;
            proxy_set_header Content-Length "";

            proxy_set_header X-Ldap-URL      "ldap://127.0.0.1:8083";
            proxy_set_header X-Ldap-BaseDN   "ou=Users,dc=test,dc=local";
            proxy_set_header X-Ldap-BindDN   "cn=root,dc=test,dc=local";
            proxy_set_header X-Ldap-BindPass "secret";

            proxy_set_header X-CookieName "nginxauth";
            proxy_set_header Cookie nginxauth=$cookie_nginxauth;

            proxy_set_header X-Ldap-Starttls "true";
        }

        location = /auth-nodn {
            internal;

            proxy_pass http://127.0.0.1:8888;

            proxy_pass_request_body off;
            proxy_set_header Content-Length "";

            proxy_set_header X-Ldap-URL      "ldap://127.0.0.1:8083";
            proxy_set_header X-Ldap-BindDN   "cn=root,dc=test,dc=local";
            proxy_set_header X-Ldap-BindPass "secret";
        }

        location = /auth-nourl {
            internal;

            proxy_pass http://127.0.0.1:8888;

            proxy_pass_request_body off;
            proxy_set_header Content-Length "";

            proxy_set_header X-Ldap-BaseDN   "ou=Users,dc=test,dc=local";
            proxy_set_header X-Ldap-BindDN   "cn=root,dc=test,dc=local";
            proxy_set_header X-Ldap-BindPass "secret";
        }

        location = /auth-ref1 {
            internal;

            proxy_pass http://127.0.0.1:8888;

            proxy_pass_request_body off;
            proxy_set_header Content-Length "";

            proxy_set_header X-Ldap-URL      "ldap://127.0.0.1:8083";
            proxy_set_header X-Ldap-BaseDN   "ou=Users,dc=test,dc=local";
            proxy_set_header X-Ldap-BindDN   "cn=root,dc=test,dc=local";
            proxy_set_header X-Ldap-BindPass "secret";

            proxy_set_header X-CookieName "nginxauth";
            proxy_set_header Cookie nginxauth=$cookie_nginxauth;
        }

    }
}

EOF

my $d = $t->testdir();

$t->write_file('openssl.conf', <<EOF);
[ req ]
default_bits = 1024
encrypt_key = no
distinguished_name = req_distinguished_name
[ req_distinguished_name ]
EOF

foreach my $name ('localhost') {
	system('openssl req -x509 -new '
		. "-config $d/openssl.conf -subj /CN=$name/ "
		. "-out $d/$name.crt -keyout $d/$name.key "
		. ">>$d/openssl.out 2>&1") == 0
		or die "Can't create certificate for $name: $!\n";
}

$t->write_file_expand("slapd.conf", <<"EOF");
include /etc/openldap/schema/core.schema
include /etc/openldap/schema/cosine.schema
include /etc/openldap/schema/inetorgperson.schema
include /etc/openldap/schema/nis.schema
include /etc/openldap/schema/misc.schema

pidfile  $d/slapd.pid
argsfile $d/slapd.args
logfile $d/slapd.log

loglevel 256 64

access to dn.base="" by * read
access to dn.base="cn=Subschema" by * read
access to *
  by self write
  by users read
  by anonymous read

database hdb
suffix "dc=test,dc=local"
rootdn "cn=root,dc=test,dc=local"
rootpw secret
directory $d/openldap-data
index objectClass eq

TLSCipherSuite HIGH:MEDIUM:+SSLv2
TLSCACertificateFile $d/localhost.crt
TLSCertificateFile $d/localhost.crt
TLSCertificateKeyFile $d/localhost.key

EOF

$t->write_file_expand("slapd2.conf", <<"EOF");
include /etc/openldap/schema/core.schema
include /etc/openldap/schema/cosine.schema
include /etc/openldap/schema/inetorgperson.schema
include /etc/openldap/schema/nis.schema
include /etc/openldap/schema/misc.schema

pidfile  $d/slapd2.pid
argsfile $d/slapd2.args
logfile $d/slapd2.log

loglevel 256 64

access to dn.base="" by * read
access to dn.base="cn=Subschema" by * read
access to *
  by self write
  by users read
  by anonymous read

database hdb
suffix "ou=Users, dc=test,dc=local"
rootdn "cn=root, ou=Users, dc=test,dc=local"
rootpw secret
directory $d/openldap2-data
index objectClass eq

TLSCipherSuite HIGH:MEDIUM:+SSLv2
TLSCACertificateFile $d/localhost.crt
TLSCertificateFile $d/localhost.crt
TLSCertificateKeyFile $d/localhost.key

# our upstream
referral   ldap://127.0.0.1:%%PORT_8083%%/

EOF


$t->write_file_expand("initial.ldif", <<'EOF');
dn: dc=test,dc=local
dc: test
description: BlaBlaBla
objectClass: dcObject
objectClass: organization
o: Example, Inc.

dn: ou=Users, dc=test,dc=local
ou: Users
description: All people in organisation
objectclass: organizationalunit

dn: cn=user1,ou=Users,dc=test,dc=local
objectclass: inetOrgPerson
cn: User number one
sn: u1
uid: user1
userpassword: user1secret
mail: user1@example.com
description: user1
ou: Users

dn: cn=user2,ou=Users,dc=test,dc=local
objectclass: inetOrgPerson
cn: User number one
sn: u2
uid: user2
userpassword: user2secret
mail: user2@example.com
description: user2
ou: Users

dn: cn=user3,ou=Users,dc=test,dc=local
objectclass: inetOrgPerson
cn: User number one
sn: u3
uid: user3
userpassword: user3secret
mail: user3@example.com
description: user3
ou: Users

dn: ou=more,ou=Users,dc=test,dc=local
objectClass: referral
objectClass: extensibleObject
dc: subtree
ref: ldap://127.0.0.1:%%PORT_8085%%/ou=more,ou=Users,dc=test,dc=local

EOF


$t->write_file_expand("initial2.ldif", <<'EOF');
dn: ou=Users, dc=test,dc=local
ou: Users
description: All people in organisation
objectclass: organizationalunit

dn: ou=more,ou=Users,dc=test,dc=local
dc: test
description: BlaBlaBla
objectClass: dcObject
objectClass: organizationalUnit

dn: cn=user4, ou=more, ou=Users,dc=test,dc=local
objectclass: inetOrgPerson
cn: User number one
sn: u4
uid: user4
userpassword: user4secret
mail: user4@example.com
description: user4
ou: Users

EOF

# -u ldap -g ldap
my $SLAPD = defined $ENV{TEST_LDAP_DAEMON} ? $ENV{TEST_LDAP_DAEMON}
	: '/usr/lib64/openldap/slapd';

my $AUTHD = defined $ENV{TEST_LDAP_AUTH_DAEMON} ? $ENV{TEST_LDAP_AUTH_DAEMON}
	: 'nginx-ldap-auth-daemon.py';

$t->has_daemon($SLAPD);
$t->has_daemon($AUTHD);

mkdir("$d/openldap-data");
mkdir("$d/openldap2-data");

my $p3 = port(8083);
my $p4 = port(8084);
my $p5 = port(8085);

# change '0' to '1' or more to get debug from slapd
$t->run_daemon($SLAPD, '-d', '0', '-f', "$d/slapd.conf",
		'-h', "ldap://127.0.0.1:$p3 ldaps://127.0.0.1:$p4");

$t->run_daemon($SLAPD, '-d', '0', '-f', "$d/slapd2.conf",
		'-h', "ldap://127.0.0.1:$p5");

$t->waitforsocket("127.0.0.1:$p3") or die "Can't start slapd";
$t->waitforsocket("127.0.0.1:$p5") or die "Can't start slapd2";

system("ldapadd -H ldap://127.0.0.1:$p3 -x -D \"cn=root,dc=test,dc=local\""
       . " -f $d/initial.ldif -w secret >> $d/ldif.log 2>&1") == 0
		or die "Can't import initial LDIF\n";

system("ldapadd -H ldap://127.0.0.1:$p5 -x -D \"cn=root,ou=Users,dc=test,dc=local\""
       . " -f $d/initial2.ldif -w secret >> $d/ldif2.log 2>&1") == 0
		or die "Can't import initial2 LDIF\n";


$t->write_file_expand("auth_daemon.sh", <<"EOF");
AUTHBIN=\$(realpath $AUTHD)
cd $d
exec coverage2 run \$AUTHBIN --host 127.0.0.1 \\
    -p %%PORT_8888%% >$d/nginx-ldap-auth-dameon.stdlog 2>&1
EOF

$t->run_daemon('/bin/sh', "$d/auth_daemon.sh");
$t->waitforsocket('127.0.0.1:' . port(8888))
	or die "Can't start auth daemon";

$t->plan(21);

$t->run();

###############################################################################

like(http_get_auth('/', 'user1', 'user1secret'), qr!ACCESS GRANTED!,
	'proper user with proper pass');
like(http_get_auth('/', 'user1', 'randompass'), qr!LOGIN PAGE!,
	'proper user with incorrect pass');
like(http_get_auth('/', 'user111', 'user1secret'), qr!LOGIN PAGE!,
	'similar user with user1 pass');
like(http_get_auth('/', 'randomuser', 'randompass'), qr!LOGIN PAGE!,
	'random user with random pass');
like(http_get_auth('/', 'user2', 'user2secret'), qr!ACCESS GRANTED!,
	'user2 with proper pass');
like(http_get_auth('/', 'user3', 'user3secret'), qr!ACCESS GRANTED!,
	'user3 with proper pass');
like(http_get_auth('/', '', ''), qr!LOGIN PAGE!, 'empty user no password');
like(http_get('/'), qr!LOGIN PAGE!, 'no auth header');

like(http_get_cookie('/', 'user1', 'user1secret'), qr!ACCESS GRANTED!,
	'proper user with proper pass cookie');
like(http_get_cookie('/', 'user1', 'randompasz'), qr!LOGIN PAGE!,
	'proper user with incorrect pass cookie');
like(http_get_cookie('/', 'randomuser', 'randompass'), qr!LOGIN PAGE!,
	'random user with random pass cookie');
like(http_get_cookie('/', 'user2', 'user2secret'), qr!ACCESS GRANTED!,
	'user2 with proper pass cookie');
like(http_get_cookie('/', 'user3', 'user3secret'), qr!ACCESS GRANTED!,
	'user3 with proper pass cookie');

like(http_get_auth_broken_base64('/', 'user3', 'user3secret'), qr!LOGIN PAGE!,
	'user3 with proper pass broken base64');
like(http_get_cookie_broken_base64('/', 'user3', 'user3secret'), qr!LOGIN PAGE!,
	'user3 with proper pass broken cookie');

like(http_get_auth('/ssl', 'user1', 'user1secret'), qr!ACCESS GRANTED!,
	'proper user with proper pass with ssl');

like(http_get_auth('/starttls', 'user1', 'user1secret'), qr!ACCESS GRANTED!,
	'proper user with proper pass with starttls');

# dn is not set, no default, daemon error => 502
like(http_get_auth('/nodn', 'user1', 'user1secret'), qr!Internal Server Error!,
	'dn must be set');

# url is not set, default is used, which is not accessible => login page
like(http_get_auth('/nourl', 'user1', 'user1secret'), qr!LOGIN PAGE!,
	'url must be set');

# LDAP referrals

# user can be found, but bind happens on 1st server, instead of the found
# the behaviour may change with different servers
like(http_get_auth('/ref1', 'user4', 'user4secret'), qr!LOGIN PAGE!,
	'server2 user via referral on server1');

# unknown user on referred server, result is empty dn
like(http_get_auth('/ref1', 'userx', 'blah'), qr!LOGIN PAGE!,
	'unknown user with referral on server1');


###############################################################################

sub http_get_auth {
	my ($url, $user, $password) = @_;

	my $auth = encode_base64($user . ':' . $password, '');

	return http(<<EOF);
GET $url HTTP/1.0
Host: localhost
Authorization: Basic $auth

EOF
}

# do not encode auth with base64, send plain
sub http_get_auth_broken_base64 {
	my ($url, $user, $password) = @_;

	my $auth = $user . ':' . $password;

	return http(<<EOF);
GET $url HTTP/1.0
Host: localhost
Authorization: Basic $auth

EOF
}


sub http_get_cookie {
	my ($url, $user, $password) = @_;

	my $auth = encode_base64($user . ':' . $password, '');

	return http(<<EOF);
GET $url HTTP/1.0
Host: localhost
Cookie: nginxauth=$auth

EOF
}

sub http_get_cookie_broken_base64 {
	my ($url, $user, $password) = @_;

	my $auth = $user . ':' . $password;

	return http(<<EOF);
GET $url HTTP/1.0
Host: localhost
Cookie: nginxauth=$auth

EOF
}
