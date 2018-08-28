FROM python:3-alpine3.8

RUN apk add --no-cache gcc build-base libffi-dev openssl-dev
COPY requirements-integration-tests.txt /tmp
RUN pip install ddt
RUN pip install docker
RUN pip install paramiko
RUN pip install pytest
RUN mkdir /app
WORKDIR /app