ARG BUILD_FROM
FROM $BUILD_FROM

RUN \
  apk add --no-cache \
    python3 py3-pip py3-virtualenv


COPY dns-fw/requirements.txt /tmp/

RUN virtualenv /env
ENV VIRTUAL_ENV /env
ENV PATH /env/bin:$PATH

RUN pip install --requirement /tmp/requirements.txt

COPY run.sh /
RUN chmod a+x /run.sh
COPY dns-fw/listener.py /

CMD [ "/run.sh" ]
