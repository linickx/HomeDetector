ARG BUILD_FROM
FROM $BUILD_FROM

RUN apk add --no-cache python3 py3-pip py3-virtualenv
RUN apk add --no-cache python3-dev bash gcc build-base

COPY dns/requirements.txt /tmp/dns.requirements.txt
COPY opencanary/requirements.txt /tmp/oc.requirements.txt

RUN virtualenv /env
ENV VIRTUAL_ENV /env
ENV PATH /env/bin:$PATH

RUN pip install --requirement /tmp/dns.requirements.txt
RUN pip install --requirement /tmp/oc.requirements.txt

COPY dns/listener.py /
COPY opencanary/default.conf /etc/opencanaryd/opencanary.conf

COPY run.sh /
RUN chmod a+x /run.sh
CMD [ "/run.sh" ]
