#!/usr/bin/env bash

# exit when any command fails
# set -e

cd "${0%/*}" || exit

source ./.venv/bin/activate
python main.py
