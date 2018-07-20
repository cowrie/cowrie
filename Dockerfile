FROM python:2-alpine3.8 as python-base
MAINTAINER Florian Pelgrim <florian.pelgrim@craneworks.de>
RUN apk add --no-cache libffi
COPY app /app
COPY requirements.txt .

FROM python-base as builder
RUN apk add --no-cache gcc musl-dev python-dev libffi-dev libressl-dev && \
  pip wheel --wheel-dir=/root/wheelhouse -r requirements.txt

FROM python-base as linter
COPY --from=builder /root/wheelhouse /root/wheelhouse
RUN pip install -r requirements.txt --no-index --find-links=/root/wheelhouse && pip install flake8 && \
  flake8 /app --count --select=E1,E2,E901,E999,F821,F822,F823 --show-source --statistics

FROM linter as unittest
ENV PYTHONPATH=/app
WORKDIR /app
RUN trial cowrie

FROM python-base
COPY --from=builder /root/wheelhouse /root/wheelhouse
RUN pip install -r requirements.txt --no-index --find-links=/root/wheelhouse && \
  rm -rf /root/wheelhouse
ENV PYTHONPATH=/app
WORKDIR /app
EXPOSE 2222/tcp
CMD /usr/local/bin/python /usr/local/bin/twistd -u 65534 -g 65534 --umask 0022 --nodaemon --pidfile= -l - cowrie
