#!/bin/sh

WORKDIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../" >/dev/null 2>&1 && pwd )"

if [ ! -d "${WORKDIR}/.venv" ]; then
    python3 -m venv ${WORKDIR}/.venv
    source ${WORKDIR}/.venv/bin/activate
    ${WORKDIR}/.venv/bin/pip3 install -r ${WORKDIR}/mtlsgateway/mbedtls/requirements.txt
fi

# usually, the venv is activated by VSCode via customisation settings
