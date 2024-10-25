
# Fuzzer

The fuzzer designed so far is an inital attempt at creating an appropriate, extensible infrastructure which can be used to create a full fledge black box testing system. It is elementary, in the sense that there are a few mutations elaborated on under the *Mutations* section below, and it only caters to JSON and CSV files, as per the requirements of the Mid-point checkin.

# The infrastructure

The main code starts in `harness.py`, which calls a `run()` function whose purpose is to run all tests. The `run()` function iterates through the programs and tries to break them one by one. Firstly it determines the file type, according to which it executes appropriate commands like reading in a file and setting up appropriate data structures. One data structure we use is a container to represent the types of each cell of each input, for example the type of each value in the JSON object. This type could be an `INT` or a `STRING`.



