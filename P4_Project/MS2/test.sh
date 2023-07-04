#!/bin/bash

# Testing some generic puts
python3 send.py put 0 1
python3 send.py put 1 2

# Testing some generic gets without testing versioning
python3 send.py get 0 
python3 send.py get 1 
 
# Test all select predicates
python3 send.py select \<= 3 

# Add some versions
python3 send.py put 10 10
python3 send.py put 10 20
python3 send.py put 10 30

# Get some versions
python3 send.py get 10 

# Test range with versions
python3 send.py range 10 12 

# Test select with versions
python3 send.py select == 10 

# Testing some generic puts
python3 send.py put 1022 1023
python3 send.py put 1023 1024

# Testing some generic gets without testing versioning
python3 send.py get 1022 
python3 send.py get 1023
 
# Test all select predicates
python3 send.py select \> 1021 

# Add some versions
python3 send.py put 513 10
python3 send.py put 513 20
python3 send.py put 513 30

# Get some versions
python3 send.py get 513 

# Test range with versions
python3 send.py range 1022 1024 

# Test select with versions
python3 send.py select == 513 

python3 send.py put 509 509
python3 send.py put 510 510
python3 send.py put 511 511
python3 send.py put 512 512

python3 send.py range 505 513

sleep 1
pkill -9 -f recv.py