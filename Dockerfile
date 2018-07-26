FROM python:2-alpine3.8 as python-base
MAINTAINER Florian Pelgrim <florian.pelgrim@craneworks.de>
RUN apk add --no-cache libffi
COPY requirements.txt .

FROM python-base as builder
RUN apk add --no-cache gcc musl-dev python-dev libffi-dev libressl-dev && \
  pip wheel --wheel-dir=/root/wheelhouse -r requirements.txt

FROM python-base as post-builder
COPY src/ /src
COPY data /src/data
COPY honeyfs /src/honeyfs
COPY share /src/share
COPY etc /src/etc
COPY --from=builder /root/wheelhouse /root/wheelhouse
RUN pip install -r requirements.txt --no-index --find-links=/root/wheelhouse && \
  mkdir /src/dl && \
  mkdir -p /src/log/tty && \
  mkdir /src/var

FROM post-builder as linter
RUN pip install flake8 && \
  rm -rf /root/wheelhouse && \
  flake8 /src --count --select=E1,E2,E901,E999,F821,F822,F823 --show-source --statistics

FROM post-builder as unittest
ENV PYTHONPATH=/src
WORKDIR /src
RUN trial cowrie

FROM post-builder
ENV PYTHONPATH=/src
WORKDIR /src
EXPOSE 2222/tcp
CMD /usr/local/bin/python /usr/local/bin/twistd -u 65534 -g 65534 --umask 0022 --nodaemon --pidfile= -l - cowrie
