#!/usr/bin/env bash

# Go to script directory path
cd "$(dirname "$(readlink -f "${BASH_SOURCE}")")"

cd ../
doctoc README.md --github --title "<h5>Table of Contents</h5>"