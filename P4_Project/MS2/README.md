In milestone 2, We implemented GET, PUT, SELECT, and RANGE queries without versioning.

Files contained in the folder:  
• Makefile  
• ms2-0.p4, ms2-1.p4,ms2-2.p4, ms2-3.p4  
• topology.json  
• send.py  
• recv.py  
• s0-runtime.json, s1-runtime.json,s2-runtime.json,s3-runtime.json  
• test.sh  
• testAnswer

Command:

1. Run “make”
2. Run “xterm h1 h1”
3. run “python3 recv.py” in one of the terminals.
4. or different queries, we run different commands in another terminal:
   > > > > PUT: run “python3 send.py put [key] [value]”
   > > > > GET: run “python3 send.py get [key]”
   > > > > Range: run “python3 send.py range [lower bound] [upper bound]”
   > > > > Select run “python3 send.py select [operands] [key]”, operand format should be like this(\>,\<.\>=, \<=, ==), since python terminal need \ to read > or <
5. For testing the correctness of ms2, we also implement a test.sh bash file, run “sh test.sh” in the second terminal instead of a single command, then you can see the output.
6. The expected output of the test.sh should be exactly the same as the text in “testAnswer”.
7. Restart the mininet every time if you want to do several tests since the data is stored persistently.
