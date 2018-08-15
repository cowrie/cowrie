FROM python:3-alpine3.8

RUN apk add --no-cache gcc build-base libffi-dev openssl-dev
COPY requirements-integration-tests.txt /tmp
RUN mkdir /app
WORKDIR /app
RUN pip install -r /tmp/requirements-integration-tests.txt