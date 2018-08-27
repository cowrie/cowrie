FROM python:2-alpine3.8 as python-base
LABEL key="Florian Pelgrim <florian.pelgrim@craneworks.de>"
RUN apk add --no-cache libffi && \
  addgroup -S cowrie && \
  adduser -S -s /bin/bash -G cowrie -D -H -h /cowrie cowrie && \
  mkdir -p /cowrie/var/lib/cowrie/downloads && \
  mkdir -p /cowrie/var/lib/cowrie/tty && \
  mkdir -p /cowrie/var/log/cowrie/ && \
  chown -R cowrie:cowrie /cowrie && \
  chmod -R 775 /cowrie
COPY requirements.txt .
COPY data /cowrie/data
COPY honeyfs /cowrie/honeyfs
COPY share /cowrie/share
COPY etc /cowrie/etc

FROM python-base as builder
RUN apk add --no-cache gcc musl-dev python-dev libffi-dev libressl-dev && \
  pip wheel --wheel-dir=/root/wheelhouse -r requirements.txt

FROM python-base as post-builder
COPY --from=builder /root/wheelhouse /root/wheelhouse
RUN pip install -r requirements.txt --no-index --find-links=/root/wheelhouse && \
  rm -rf /root/wheelhouse
COPY src /cowrie

FROM post-builder as linter
RUN pip install flake8 flake8-import-order && \
  flake8 --count --application-import-names cowrie --max-line-length=120 --statistics /cowrie

FROM post-builder as unittest
ENV PYTHONPATH=/cowrie
WORKDIR /cowrie
RUN trial cowrie

FROM post-builder
ENV PYTHONPATH=/cowrie
WORKDIR /cowrie
EXPOSE 2222/tcp
EXPOSE 2223/tcp
RUN chown -R cowrie:cowrie /cowrie
USER cowrie
CMD /usr/local/bin/python /usr/local/bin/twistd --umask 0022 --nodaemon --pidfile= -l - cowrie