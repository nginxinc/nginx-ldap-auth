#!/bin/sh
''''which python2 >/dev/null && exec python2 "$0" "$@" # '''
''''which python  >/dev/null && exec python  "$0" "$@" # '''

# Copyright (C) 2014-2015 Nginx, Inc.

# Example of an application working on port 9000
# To interact with nginx-ldap-auth-daemon this application
# 1) accepts GET  requests on /login and responds with a login form
# 2) accepts POST requests on /login, sets a cookie, and responds with redirect

import sys, os, signal, base64, Cookie, cgi, urlparse
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler

Listen = ('localhost', 9000)

import threading
from SocketServer import ThreadingMixIn
class AuthHTTPServer(ThreadingMixIn, HTTPServer):
    pass

class AppHandler(BaseHTTPRequestHandler):

    def do_GET(self):

        url = urlparse.urlparse(self.path)

        if url.path.startswith("/login"):
            return self.auth_form()

        self.send_response(200)
        self.end_headers()
        self.wfile.write('Hello, world! Requested URL: ' + self.path + '\n')


    # send login form html
    def auth_form(self, target = None):

        # try to get target location from header
        if target == None:
            target = self.headers.get('X-Target')

        # form cannot be generated if target is unknown
        if target == None:
            self.log_error('target url is not passed')
            self.send_response(500)
            return

        html="""
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<html>
  <head>
    <meta http-equiv=Content-Type content="text/html;charset=UTF-8">
    <title>Auth form example</title>
  </head>
  <body>
    <form action="/login" method="post">
      <table>
        <tr>
          <td>Username: <input type="text" name="username"/></td>
        <tr>
          <td>Password: <input type="text" name="password"/></td>
        <tr>
          <td><input type="submit" value="Login"></td>
      </table>
        <input type="hidden" name="target" value="TARGET">
    </form>
  </body>
</html>"""

        self.send_response(200)
        self.end_headers()
        self.wfile.write(html.replace('TARGET', target))


    # processes posted form and sets the cookie with login/password
    def do_POST(self):

        # prepare arguments for cgi module to read posted form
        env = {'REQUEST_METHOD':'POST',
               'CONTENT_TYPE': self.headers['Content-Type'],}

        # read the form contents
        form = cgi.FieldStorage(fp = self.rfile, headers = self.headers,
                                environ = env)

        # extract required fields
        user = form.getvalue('username')
        passwd = form.getvalue('password')
        target = form.getvalue('target')

        if user != None and passwd != None and target != None:

            # form is filled, set the cookie and redirect to target
            # so that auth daemon will be able to use information from cookie

            self.send_response(302)

            # WARNING WARNING WARNING
            #
            # base64 is just an example method that allows to pack data into
            # a cookie. You definitely want to perform some encryption here
            # and share a key with auth daemon that extracts this information
            #
            # WARNING WARNING WARNING
            enc = base64.b64encode(user + ':' + passwd)
            self.send_header('Set-Cookie', 'nginxauth=' + enc + '; httponly')

            self.send_header('Location', target)
            self.end_headers()

            return

        self.log_error('some form fields are not provided')
        self.auth_form(target)


    def log_message(self, format, *args):
        if len(self.client_address) > 0:
            addr = BaseHTTPRequestHandler.address_string(self)
        else:
            addr = "-"

        sys.stdout.write("%s - - [%s] %s\n" % (addr,
                         self.log_date_time_string(), format % args))

    def log_error(self, format, *args):
        self.log_message(format, *args)


def exit_handler(signal, frame):
    sys.exit(0)

if __name__ == '__main__':
    server = AuthHTTPServer(Listen, AppHandler)
    signal.signal(signal.SIGINT, exit_handler)
    server.serve_forever()
