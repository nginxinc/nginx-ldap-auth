FROM python:3-alpine

COPY nginx-ldap-auth-daemon.py /usr/src/app/

WORKDIR /usr/src/app/

# Install required software
RUN \
    apk --no-cache add openldap-dev && \
    apk --no-cache add --virtual build-dependencies build-base && \
    pip install python-ldap && \
    apk del build-dependencies

# If you need to add your own certs, copy them in here and uncomment
#RUN apk add ca-certificates && rm -rf /var/cache/apk/*
#COPY ./certs/*.pem /usr/local/share/ca-certificates/
#RUN update-ca-certificates

EXPOSE 8888

CMD ["python", "/usr/src/app/nginx-ldap-auth-daemon.py", "--host", "0.0.0.0", "--port", "8888"]
