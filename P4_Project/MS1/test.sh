#!/bin/bash

# Testing some generic puts
python3 send.py put 0 1
python3 send.py put 1 2

# Testing some generic gets without testing versioning
python3 send.py get 0 0
python3 send.py get 1 0
 
# Test all select predicates
python3 send.py select \<= 3 0

# Add some versions
python3 send.py put 10 10
python3 send.py put 10 20
python3 send.py put 10 30

# Get some versions
python3 send.py get 10 0

# Test range with versions
python3 send.py range 10 12 1

# Test select with versions
python3 send.py select == 10 1

sleep 1
pkill -9 -f recv.py