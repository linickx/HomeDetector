ARG BUILD_FROM
FROM $BUILD_FROM

RUN \
  apk add --no-cache \
    python3 py3-pip py3-virtualenv


COPY dns/requirements.txt /tmp/

RUN virtualenv /env
ENV VIRTUAL_ENV /env
ENV PATH /env/bin:$PATH

RUN pip install --requirement /tmp/requirements.txt

COPY run.sh /
RUN chmod a+x /run.sh
COPY dns/listener.py /

CMD [ "/run.sh" ]
