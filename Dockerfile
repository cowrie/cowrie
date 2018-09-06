FROM debian:stable-slim as python-base
RUN apt-get update && \
  apt-get install --no-install-recommends -y libffi6 python python-pip  && \
  adduser --system --shell /bin/bash --group --disabled-password --no-create-home --home /cowrie cowrie && \
  mkdir -p /cowrie/var/lib/cowrie/downloads && \
  mkdir -p /cowrie/var/lib/cowrie/tty && \
  mkdir -p /cowrie/var/log/cowrie/ && \
  chown -R cowrie:cowrie /cowrie && \
  chmod -R 775 /cowrie
COPY requirements.txt .
COPY requirements-output.txt .
COPY data /cowrie/data
COPY honeyfs /cowrie/honeyfs
COPY share /cowrie/share
COPY etc /cowrie/etc

FROM python-base as builder
RUN apt-get install --no-install-recommends -y python-wheel python-setuptools build-essential libssl-dev libffi-dev python-dev libsnappy-dev default-libmysqlclient-dev && \
  pip wheel --wheel-dir=/root/wheelhouse -r requirements.txt && \
  pip wheel --wheel-dir=/root/wheelhouse -r requirements-output.txt

FROM python-base as post-builder
COPY --from=builder /root/wheelhouse /root/wheelhouse
RUN pip install -r requirements.txt --no-index --find-links=/root/wheelhouse && \
  pip install -r requirements-output.txt --no-index --find-links=/root/wheelhouse

FROM post-builder as pre-devel
RUN pip install flake8 flake8-import-order pytest

FROM pre-devel as devel
USER cowrie

FROM pre-devel as tests
COPY src /cowrie
ENV PYTHONPATH=/cowrie
WORKDIR /cowrie
RUN flake8 --count --application-import-names cowrie --max-line-length=120 --statistics . && \
  trial cowrie

FROM post-builder as pre-release
RUN apt-get remove -y python-pip && \
  apt-get autoremove -y && \
  apt-get autoclean -y && \
  rm -rf /root/wheelhouse && \
  rm -rf /var/lib/apt/lists/* && \
  rm -rf /var/log/*
COPY src /cowrie
RUN find /cowrie -type d -exec chmod 755 {} \; && \
  find /cowrie -type f -exec chmod 744 {} \;

FROM pre-release as release
LABEL maintainer="Florian Pelgrim <florian.pelgrim@craneworks.de>"
ENV PYTHONPATH=/cowrie
WORKDIR /cowrie
EXPOSE 2222/tcp
EXPOSE 2223/tcp
USER cowrie
CMD /usr/bin/python /usr/local/bin/twistd --umask 0022 --nodaemon --pidfile= -l - cowrie
