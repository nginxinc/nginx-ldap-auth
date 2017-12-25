# nginx-ldap-auth

Reference implementation of method for authenticating users on behalf of servers proxied by NGINX or NGINX Plus

## Description

**Note:** For ease of reading, this document refers to [NGINX Plus](http://www.nginx.com/products/), but it also applies to [open source NGINX](http://www.nginx.org/en). The prerequisite [ngx_http_auth_request_module](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) module is included both in [NGINX Plus packages](http://cs.nginx.com/repo_setup) and [prebuilt open source NGINX binaries](http://nginx.org/en/linux_packages.html).

The nginx-ldap-auth software is a reference implementation of a method for authenticating users who request protected resources from servers proxied by NGINX Plus. It includes a daemon (*ldap-auth*) that communicates with an authentication server, and a sample daemon that stands in for an actual back-end server during testing, by generating an authentication cookie based on the user’s credentials. The daemons are written in Python for use with a Lightweight Directory Access Protocol (LDAP) authentication server (OpenLDAP or Microsoft Windows Active Directory 2003 and 2012).

The ldap-auth daemon, which mediates between NGINX Plus and the LDAP server, is intended to serve as a model for "connector" daemons written in other languages, for different authentication systems, or both. [NGINX, Inc. Professional Services](http://nginx.com/services/) is available to assist with such adaptations.

![NGINX LDAP Architecture](https://cdn-1.wp.nginx.com/wp-content/uploads/2016/02/ldap-auth-components.jpg)

For a step-by-step description of the authentication process in the reference implementation, see [How Authentication Works in the Reference Implementation](https://nginx.com/blog/nginx-plus-authenticate-users#ldap-auth-flow) in [NGINX Plus and NGINX Can Authenticate Application Users](https://nginx.com/blog/nginx-plus-authenticate-users).

## Installation and Configuration

The NGINX Plus configuration file that is provided with the reference implementation configures all components other than the LDAP server (that is, NGINX Plus, the client, the ldap-auth daemon, and the back-end daemon) to run on the same host, which is adequate for testing purposes. The LDAP server can also run on that host during testing.

In an actual deployment, the back-end application and authentication server typically each run on a separate host, with NGINX Plus on a third host. The ldap-auth daemon does not consume many resources in most situations, so it can run on the NGINX Plus host or another host of your choice.

To install and configure the reference implementation, perform the following steps.

1. Create a clone of the GitHub repository (**nginx-ldap-auth**).

1. If NGINX Plus is not already running, install it according to the [instructions for your operating system](https://cs.nginx.com/repo_setup).

1. If an LDAP authentication server is not already running, install and configure one. By default the ldap-auth daemon communicates with OpenLDAP, but can be configured to work with Active Directory.

    If you are using the LDAP server only to test the reference implementation, you can use the [OpenLDAP server Docker image](https://github.com/osixia/docker-openldap) that is available on GitHub, or you can set up a server in a virtual environment using instructions such as [How To Install and Configure a Basic LDAP Server on an Ubuntu 12.04 VPS](https://www.digitalocean.com/community/tutorials/how-to-install-and-configure-a-basic-ldap-server-on-an-ubuntu-12-04-vps).

1. On the host where the ldap-auth daemon is to run, install the following additional software. We recommend using the versions that are distributed with the operating system, instead of downloading the software from an open source repository.

    - Python version 2. Version 3 is not supported.
    - The Python LDAP module, **python-ldap** (created by the [python-ldap.org](http://www.python-ldap.org) open source project).

1. Copy the following files from your repository clone to the indicated hosts:
    - **nginx-ldap-auth.conf** – NGINX Plus configuration file, which contains the minimal set of directives for testing the reference implementation. Install on the NGINX Plus host (in the **/etc/nginx/conf.d** directory if using the conventional configuration scheme). To avoid configuration conflicts, remember to move or rename any default configuration files installed with NGINX Plus.
    - **nginx-ldap-auth-daemon.py** – Python code for the ldap-auth daemon. Install on the host of your choice.

      Alternatively, use provided Dockerfile to build Docker image:

      ```
      docker build -t nginx-ldap-auth-daemon .
      docker run nginx-ldap-auth-daemon
     ```

    - **nginx-ldap-auth-daemon-ctl.sh** – Sample shell script for starting and stopping the daemon. Install on the same host as the ldap-auth daemon.
    - **backend-sample-app.py** – Python code for the daemon that during testing stands in for a real back-end application server. Install on the host of your choice.

1. Modify the NGINX Plus configuration file as described in [Required Modifications to the NGINX Plus Configuration File](#required-mods) below. For information about customizing your deployment, see [Customization](#customization) below. We recommend running the `nginx -t` command after making your changes to verify that the file is syntactically valid.

1. Start NGINX Plus. If it is already running, run the following command to reload the configuration file:
   <pre>root# <strong>nginx -s reload</strong></pre>

1. Run the following commands to start the ldap-auth daemon and the back-end daemon.
   <pre>root# <strong>nginx-ldap-auth-daemon-ctl.sh start</strong>
    root# <strong>python backend-sample-app.py</strong></pre>

1. To test the reference implementation, use a web browser to access **http://*nginx-server-address*:8081**. Verify that the browser presents a login form. After you fill out the form and submit it, verify that the server returns the expected response to valid credentials. The sample back-end daemon returns this:
<pre>Hello, world! Requested URL: <em>URL</em></pre>

<a name="required-mods">
### Required Modifications to the NGINX Plus Configuration File
</a>

Modify the **nginx-ldap-auth.conf** file, by changing values as appropriate for your deployment for the terms shown in bold font in the following configuration.

For detailed instructions, see [Configuring the Reference Implementation](https://nginx.com/blog/nginx-plus-authenticate-users#ldap-auth-configure) in the [NGINX Plus and NGINX Can Authenticate Application Users](https://nginx.com/blog/nginx-plus-authenticate-users) blog post. The **nginx-ldap-auth.conf** file includes detailed instructions (in comments not shown here) for setting the `proxy-set-header` directives; for information about other directives, see the [NGINX reference documentation](http://nginx.org/en/docs/).

<pre>http {
  ...
  proxy_cache_path <strong>cache/</strong> keys_zone=<strong>auth_cache</strong>:<strong>10m</strong>;

  upstream backend {
        server <strong>127.0.0.1</strong>:9000;
  }

  server {
      listen <strong>127.0.0.1</strong>:8081;

      location = /auth-proxy {
         proxy_pass http://<strong>127.0.0.1</strong>:8888;
         proxy_cache <strong>auth_cache</strong>; # Must match the name in the proxy_cache_path directive above
         proxy_cache_valid 200 <strong>10m</strong>;

         # URL and port for connecting to the LDAP server
         proxy_set_header X-Ldap-URL "<strong>ldap</strong>://<strong>example.com</strong>";

         # Negotiate a TLS-enabled (STARTTLS) connection before sending credentials
         proxy_set_header X-Ldap-Starttls "true";

         # Base DN
         proxy_set_header X-Ldap-BaseDN "<strong>cn=Users,dc=test,dc=local</strong>";

         # Bind DN
         proxy_set_header X-Ldap-BindDN "<strong>cn=root,dc=test,dc=local</strong>";

         # Bind password
         proxy_set_header X-Ldap-BindPass "<strong>secret</strong>";
      }
   }
}</pre>

If the authentication server runs Active Directory rather than OpenLDAP, uncomment the following directive as shown:

```
proxy_set_header X-Ldap-Template "(sAMAccountName=%(username)s)";
```

In addition, the **X-Ldap-Template** header can be used to create complex LDAP searches. The code in ldap-auth-daemon creates a search filter that is based on this template header. By default, template is empty, and does not make any effect on LDAP search. However, you may decide for instance to authenticate only users from a specific user group (see LDAP documentation for more information regarding filters).

Suppose, your web resource should only be available for users from `group1` group.
In such a case you can define `X-Ldap-Template` template as follows:

proxy_set_header X-Ldap-Template "(&(cn=%(username)s)(memberOf=cn=group1,cn=Users,dc=example,dc=com))";

The search filters can be combined from less complex filters using boolean operations and can be rather complex.

The reference implementation uses cookie-based authentication. If you are using HTTP basic authentication instead, comment out the following directives as shown:

<pre><strong>#</strong>proxy_set_header X-CookieName "nginxauth";
<strong>#</strong>proxy_set_header Cookie nginxauth=$cookie_nginxauth;</pre>

## Customization
### Caching

The **nginx-ldap-auth.conf** file enables caching of both data and credentials. To disable caching, comment out the four `proxy_cache*` directives as shown:

<pre>http {
  ...
  <strong>#</strong>proxy_cache_path cache/ keys_zone=auth_cache:10m;
  ...
  server {
    ...
    location = /auth-proxy {
      <strong>#</strong>proxy_cache auth_cache;
      # note that cookie is added to cache key
      <strong>#</strong>proxy_cache_key "$http_authorization$cookie_nginxauth";
      <strong>#</strong>proxy_cache_valid 200 10m;
     }
   }
}</pre>

### Optional LDAP Parameters

If you want to change the value for the `template` parameter that the ldap-auth daemon passes to the OpenLDAP server by default, uncomment the following directive as shown, and change the value:

<pre>proxy_set_header X-Ldap-Template "<strong>(cn=%(username)s)</strong>";</pre>

If you want to change the realm name from the default value (**Restricted**), uncomment and change the following directive:

<pre>proxy_set_header X-Ldap-Realm "<strong>Restricted</strong>";</pre>

### Authentication Server

To modify the ldap-auth daemon to communicate with a different (non-LDAP) type of authentication server, write a new authentication-handler class to replace `LDAPAuthHandler` in the **nginx-ldap-auth-daemon.py** script.

## Compatibility

The auth daemon was tested against default configurations of the following LDAP servers:

* [OpenLDAP](http://www.openldap.org/)</li>
* Microsoft Windows Server Active Directory 2003</li>
* Microsoft Windows Server Active Directory 2012</li>

## Limitations

The back-end daemon uses Base64 encoding on the username and password in the cookie. Base64 is a very weak form of scrambling, rendering the credentials vulnerable to extraction and misuse. We strongly recommend using a more sophisticated algorithm in your actual back-end application.

## License

The reference implementation is subject to the same 2-clause BSD license as the open source NGINX software.
