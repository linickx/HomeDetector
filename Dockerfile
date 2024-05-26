ARG BUILD_FROM
FROM $BUILD_FROM

# DNS Listener APKs
RUN apk add --no-cache python3 py3-pip py3-virtualenv
# OpenCanary APKs
RUN apk add --no-cache python3-dev bash gcc build-base

# Python Deps, per module (tmp)
COPY dns/requirements.txt /tmp/dns.requirements.txt
COPY opencanary/requirements.txt /tmp/oc.requirements.txt
COPY admin/requirements.txt /tmp/admin.requirements.txt

# Our App Root
RUN mkdir /app/
RUN mkdir /app/static

# App Dependencies
COPY opencanary/opencanary.conf /etc/opencanaryd/opencanary.conf
COPY admin/static/* /app/static/
COPY admin/templates/* /app/templates/

# My custom python apps...
COPY dns/listener.py /app/
COPY admin/web.py /app/

# Setup Python Env...
RUN virtualenv /env
ENV VIRTUAL_ENV /env
ENV PATH /env/bin:$PATH
RUN pip install --requirement /tmp/dns.requirements.txt
RUN pip install --requirement /tmp/oc.requirements.txt
RUN pip install --requirement /tmp/admin.requirements.txt

# And Finally...
COPY run.sh /
RUN chmod a+x /run.sh
CMD [ "/run.sh" ]
