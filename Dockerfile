FROM python:2-alpine

COPY requirements.txt /usr/src/app/
COPY nginx-ldap-auth-daemon.py /usr/src/app/

WORKDIR /usr/src/app/

# Install required software
RUN \
    apk --no-cache add openldap-dev && \
    apk --no-cache add --virtual build-dependencies build-base && \
    pip install -r requirements.txt && \
    apk del build-dependencies


EXPOSE 8888

CMD ["python", "/usr/src/app/nginx-ldap-auth-daemon.py"]
