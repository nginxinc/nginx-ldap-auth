#!/bin/sh

# shell script to start testsuite and run coverage
# to be executed as Dockerfile CMD

export TEST_NGINX_LEAVE=1
rm -rf /tmp/nginx-test-*

perl ldap-auth.t

testdir=$(find /tmp -name 'nginx-test-*' -print -quit)
cd $testdir
coverage2 html && printf "Coverage report: docker cp <cid>:$testdir/htmlcov <hostdir>\n"
