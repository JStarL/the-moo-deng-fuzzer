# Authors
z5280740 - Jibitesh Saha
z5441928 - Li Li
z5437039 - Antheo Raviel Santosa
z5408331 - Halliya Hyeryeon UM

# Fuzzer

The fuzzer designed so far is an inital attempt at creating an appropriate, extensible infrastructure which can be used to create a full fledge black box testing system. It is elementary, in the sense that there are a few mutations elaborated on under the *Mutations* section below, and it only caters to JSON and CSV files, as per the requirements of the Mid-point checkin.

# The infrastructure

The main code starts in `harness.py`, which calls a `run()` function whose purpose is to run all tests. The `run()` function iterates through the programs and tries to break them one by one. Firstly it determines the file type, according to which it executes appropriate commands like reading in a file and setting up appropriate data structures. One data structure we use is a container to represent the types of each cell of each input, for example the type of each value in the JSON object. This type could be an `INT` or a `STRING`.

The core of the program are a series of python generator functions which act as fuzzer input generators. The `run()` function creates a json fuzz processor and a csv fuzz processor for JSON and CSV inputs respectively, we perform fuzzing operations. The json fuzz processor does a round robin of fuzzing each field of the json object using a variety of mutations described below under the *mutations* section. The csv fuzz processor first uses repeated keyword techniques for fuzzing before using the same field fuzzing techniques in a round robin format to ensure even fuzzing distribution.

# Mutations

