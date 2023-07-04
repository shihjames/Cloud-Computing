# Milestone 3

## Goal:

- Implement a commonly used mechanism called ACL (Access Control Lists) on the frontend switch to check whether or not a client ID has access to aparticular part of the key range.

## Structure:

1. Makefile: makefile for building MS3
2. topology.json: Topology configuration
3. s0-runtime.json: Switch 0 runtime configuration
4. s1-runtime.json: Switch 1 runtime configuration
5. s2-runtime.json: Switch 2 runtime configuration
6. s3-runtime.json: Switch 3 runtime configuration
7. ms3-0.p4: Load balancer
8. ms3-1.p4: Switch 1
9. ms3-2.p4: Switch 2
10. ms3-3.p4: Standby switch
11. sendHost0.py: Python script for sender with read access to all key ranges [0--1024], but only has write access to key ranges [0, 512]
12. sendHost1.py: Python script for sender with read/write access to [0, 256]
13. receive.py: Python script for receiver
14. ms3-test1.sh: Test cases for valid requests
15. ms3-test2.sh: Test cases for invalid requests

## Execution:

1. Run "make all"
2. In the mininet, run "xterm h1 h1"
3. There will be two terminals, first run "python3 ./receive.py" in one of the terminals.
4. If you want to test one request at a time, run the following command in the other terminal:
   1. "python3 [sender python script] put [key] [value]"
   2. "python3 [sender python script] get [key]"
   3. "python3 [sender python script] range [lower bound] [upper bound]"
   4. "python3 [sender python script] select [operator] [key]"
      - Valid operators:
        - "\>"
        - "\<"
        - "\>="
        - "\<="
        - "=="
      - Valid sender python scripts:
        - ./sendHost0.py
        - ./sendHost1.py
5. If you want to use the testing batch script, run "sh [testing batch script]" in the other terminal
   - Valid testing batch scripts:
     - ./ms3-test.sh
