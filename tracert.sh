#!/bin/bash

for i in {1..500}
do
    echo "Running $i / 500"
    traceroute -q 10 -m 5 --wait=1 google.com >> log
    sleep 1
done
