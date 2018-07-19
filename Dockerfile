FROM python:2-alpine3.7 as python-base
COPY requirements.txt .
RUN apk add --no-cache gcc musl-dev python-dev libffi-dev libressl-dev
RUN pip wheel --wheel-dir=/root/wheelhouse -r requirements.txt

FROM python:2-alpine3.7
RUN apk add --no-cache libffi
COPY --from=python-base /root/wheelhouse /root/wheelhouse
COPY --from=python-base requirements.txt .
COPY app /app
RUN pip install -r requirements.txt --no-index --find-links=/root/wheelhouse && rm -rf /root/wheelhouse
ENV PYTHONPATH=/app
WORKDIR /app
EXPOSE 2222/tcp
CMD /usr/local/bin/python /usr/local/bin/twistd -u 65534 -g 65534 --umask 0022 --nodaemon --pidfile= -l - cowrie
