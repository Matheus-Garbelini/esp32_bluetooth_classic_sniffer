#!/usr/bin/env bash

# Go to script directory path
cd "$(dirname "$(readlink -f "${BASH_SOURCE}")")"

for f in ./*.pdf
do
 echo "-------------------------"
 echo "Applying pdfcrop to $f"
 ./pdfcrop.pl --margins 0 $f $f > /dev/null
 echo "Exporting $f to svg"
 pdf2svg $f $f.svg
done