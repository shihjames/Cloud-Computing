In milestone 1, We implemented GET, PUT, SELECT, and RANGE queries with versioning.

Files contained in the folder:  
• Makefile  
• ms1.p4  
• topology.json  
• send.py  
• recv.py  
• s1-runtime.json  
• test.sh  
• testAnswer.out

Command:

1. Run “make”
2. Run “xterm h1 h1”
3. run “python3 recv.py” in one of the terminals.
4. For different queries, we run different commands in another terminal:

   > > > > PUT: run “python3 send.py put [key] [value]”
   > > > > GET: run “python3 send.py get [key] [version]”
   > > > > Range: run “python3 send.py range [lower bound] [upper bound] [version]”
   > > > > Select run “python3 send.py select [operands] [key] [version]” (\>,\<.\>=, \<=, \==)(version numbers are between [0-5])
   > > > > i.e. we want to select the value that it key is equal to 10 with version 2, then we will run “python3 send.py select \== 10 2”

5. For testing the correctness of ms1, we also implement a test.sh bash file, run “sh test.sh” in the second terminal instead of a single command, then you can see the output.
6. The expected output of the test.sh should be exactly the same as the text in “testAnswer.out”.
7. Restart the mininet every time if you want to do several tests since the data is stored persistently.
8. run “exit” in the mininet.
9. run “make clean”
10. Restart everything from step 1.
