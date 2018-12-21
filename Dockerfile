FROM python:2-alpine

COPY nginx-ldap-auth-daemon.py /usr/src/app/

WORKDIR /usr/src/app/

# Install required software
RUN \
    apk --no-cache add openldap-dev && \
    apk --no-cache add --virtual build-dependencies build-base && \
    pip install python-ldap && \
    apk del build-dependencies

EXPOSE 8888

ENTRYPOINT ["python", "/usr/src/app/nginx-ldap-auth-daemon.py"]
CMD ["--host", "0.0.0.0", "--port", "8888"]
