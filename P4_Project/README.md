# Building an in-network, load balanced key/value store using a set of P4-based programmable switches

## Description

Cloud switches are programmable in P4. This allows a range of “in-network” cloud functions to be deployed inside the switches. Such functions enjoy higher performance, due to the hardware speeds of switch programs; they also have lower latency than regular, end host-based systems, because the response time to the clients is shorter. It has been demonstrated that, for instance, consensus algorithms, key/value stores, DDoS defense, and many other useful cloud functions can be offloaded to in-network P4
implementations.

## Milestone 1

Implement an in-network key/value store in a single P4 programmable switch.

## Milestone 2

Key/value store partitions, load balancing, fault tolerance.

## Milestone 3

Storage with access control lists.

1. Implement a commonly used mechanism called ACL (Access Control Lists)
   on the frontend switch to check whether or not a client ID has access to a
   particular part of the key range.
2. Assume there are two clients, Alice and Bob, with IDs 0 and 1. We will
   implement the following ACL behavior. (For simplicity we’ll assume that this authentication has already been performed “out of band”, and that every client will have a unique client ID and the embedded IDs are trusted.)
