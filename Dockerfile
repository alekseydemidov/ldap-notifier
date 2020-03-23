FROM alpine
ENV PYTHONUNBUFFERED=0
LABEL MAINTAINER="Alexey Demidov <ademidov.info@gmail.com>"
RUN apk update && \
    apk add bash python3 python3-dev gcc linux-headers musl-dev openldap-dev && \
    rm -rf /var/cache/apk/* ; \
    pip3 install python-ldap
COPY ldap_notifier.py /opt
ENTRYPOINT ["/usr/bin/python3", "-u", "/opt/ldap_notifier.py"] 
