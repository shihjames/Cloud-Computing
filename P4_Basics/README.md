# Programmable Networks

## Milestone 1: Build a topology for multipath routing

## Milestone 2: Understanding the limitations of ECMP

## Milestone 3: Implement flowlet switching

1. In your shell, run:

    ```bash
    make run
    ```

    This will:

    - compile `p4 file`, and
    - start a Mininet instance with three switches (`s1`, `s2`, `s3`, and `s4`) configured
      in a triangle, each connected to one host (`h1` and `h2`).
    - The hosts are assigned IPs of `10.0.1.1`, `10.0.2.2`.

2. You should now see a Mininet command prompt. Open two terminals for `h1` and `h2`, respectively:

```bash
mininet> xterm h1 h2
```

3. Each host includes a small Python-based messaging client and server. In
   `h2`'s xterm, start the server:

```bash
./receive.py
```

4. In `h1`'s xterm, send a message to `h2`:

```bash
./send.py 10.0.2.2 "P4 is cool"
```

5. Type `exit` or `Ctrl-D` to leave each xterm and the Mininet command line.

6. To close the mininet and clean up everything:

```bash
    make stop
```

```bash
    make clean
```
