#!/bin/bash

# valid write for Alice
python3 sendHost0.py put 0 0
python3 sendHost0.py put 20 20
python3 sendHost0.py put 200 200
python3 sendHost0.py put 512 512

# valid write for Bob
python3 sendHost1.py put 1 1
python3 sendHost1.py put 20 21
python3 sendHost1.py put 200 201

# valid read access
python3 sendHost0.py get 0
python3 sendHost0.py get 20
python3 sendHost0.py get 513
python3 sendHost0.py range 200 300
python3 sendHost0.py range 1000 1024
python3 sendHost0.py select \<= 20
python3 sendHost0.py select == 1024
python3 sendHost1.py get 1
python3 sendHost1.py get 200
python3 sendHost1.py range 0 19
python3 sendHost1.py select \< 5
python3 sendHost1.py select == 200

# invalid write access
python3 sendHost0.py put 600 600
python3 sendHost0.py put 1024 1024
python3 sendHost1.py put 300 300
python3 sendHost1.py put 512 513

# invalid read access
python3 sendHost1.py get 512
python3 sendHost1.py get 1024
python3 sendHost1.py range 1000 1024
python3 sendHost1.py range 200 300
python3 sendHost1.py select \> 256
