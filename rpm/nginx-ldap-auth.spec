Name:		nginx-ldap-auth
Version:	0.0.3
Release:	1%{?dist}
Summary:	NGINX Plus LDAP authentication daemon

Group:		System Environment/Daemons
License:	2-clause BSD-like license
URL:		https://github.com/nginxinc/nginx-ldap-auth
Source0:	nginx-ldap-auth-release-%{version}.tar.gz

BuildRequires:	systemd
Requires:	systemd
Requires:	python-ldap

%description
Reference implementation of method for authenticating users on behalf of
servers proxied by NGINX or NGINX Plus.

%prep
%setup -q

%install
mkdir -p %buildroot%_bindir
install -m755 nginx-ldap-auth-daemon.py %buildroot%_bindir/nginx-ldap-auth-daemon
mkdir -p %buildroot%_unitdir
install -m644 nginx-ldap-auth.service %buildroot%_unitdir/

%files
%doc README.md nginx-ldap-auth.conf backend-sample-app.py LICENSE
%_bindir/nginx-ldap-auth-daemon
%_unitdir/nginx-ldap-auth.service

%post
/usr/bin/systemctl preset nginx-ldap-auth.service

%preun
/usr/bin/systemctl --no-reload disable nginx-ldap-auth.service >/dev/null 2>&1 ||:
/usr/bin/systemctl stop nginx-ldap-auth.service >/dev/null 2>&1 ||:

%postun
/usr/bin/systemctl daemon-reload >/dev/null 2>&1 ||:

%changelog
* Wed Nov 02 2016 Konstantin Pavlov <thresh@nginx.com> 0.0.3-1
- Initial release
