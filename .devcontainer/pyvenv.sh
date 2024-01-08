#!/bin/sh

if [ ! -d .venv ]; then
    python3 -m venv .venv
    .venv/bin/activate
    python3 -m pip3 install -r mtlsgateway/mbedtls/requirements.txt
fi