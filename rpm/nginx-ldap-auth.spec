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
Requires:	python-argparse
Requires:	logrotate

%description
Reference implementation of method for authenticating users on behalf of
servers proxied by NGINX or NGINX Plus.

%prep
%setup -q

%install
ls
mkdir -p %buildroot%_bindir
install -m755 nginx-ldap-auth-daemon.py %buildroot%_bindir/nginx-ldap-auth-daemon
mkdir -p %buildroot%_unitdir
install -m644 %name.service %buildroot%_unitdir/
install -d -m755 %buildroot/etc/default
install -m644 %name.default %buildroot/etc/default/%name
install -d -m755 %buildroot/etc/logrotate.d
install -m644 %name.logrotate %buildroot%_sysconfdir/logrotate.d/%name

%files
%doc README.md nginx-ldap-auth.conf backend-sample-app.py LICENSE
/etc/default/%name
%_sysconfdir/logrotate.d/%name
%_bindir/nginx-ldap-auth-daemon
%_unitdir/%name.service


%post
getent group nginx-ldap-auth > /dev/null || groupadd -r nginx-ldap-auth
getent passwd nginx-ldap-auth > /dev/null || \
    useradd -r -d /var/lib/nginx -g nginx-ldap-auth \
    -s /sbin/nologin -c "Nginx auth helper" nginx-ldap-auth
/usr/bin/systemctl preset nginx-ldap-auth.service

%preun
/usr/bin/systemctl --no-reload disable nginx-ldap-auth.service >/dev/null 2>&1 ||:
/usr/bin/systemctl stop nginx-ldap-auth.service >/dev/null 2>&1 ||:

%postun
/usr/bin/systemctl daemon-reload >/dev/null 2>&1 ||:

%changelog
* Wed Nov 02 2016 Konstantin Pavlov <thresh@nginx.com> 0.0.3-1
- Initial release
