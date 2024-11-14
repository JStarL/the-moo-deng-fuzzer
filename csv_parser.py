import csv
import copy
from typing import List, Iterator
from utils import FieldType, determine_input_type, field_fuzzer
from mutations.keywords import repeat_last_keyword

def read_csv_file(file_path: str) -> List[List[str]]:
    data = []

    with open(file_path, mode='r') as file:
        csv_reader = csv.reader(file)

        for row in csv_reader:
            data.append(row)

    return data

def process_csv(csv_ds: List[List[str]]) -> List[List[FieldType]]:
    type_ds = []
    for row in csv_ds:
        type_row = []
        for element in row:
            type_row.append(determine_input_type(element))
        type_ds.append(type_row)
    return type_ds

def csv_fuzz_processor(csv_input: List[List[str]], csv_type: List[List[FieldType]]) -> Iterator[List[List[str]]]:
    csv_input_curr = copy.deepcopy(csv_input)
    # Try row based fuzzing before trying each element fuzzing
    for i, row in enumerate(csv_input_curr):
        gen = repeat_last_keyword(row, row)
        while True:
            try:
                new_row = next(gen)
            except StopIteration:
                break
            csv_input_curr[i] = new_row
            yield csv_input_curr

    csv_input_curr = copy.deepcopy(csv_input)

    print('Testing Field Fuzzer')

    i, j = 0, 0
    while i < len(csv_input_curr):

        # Do a round robin of each row of the csv input at a time
        # NOTE: Do we need to process rows[2:]? Do we need to do all of them? Or is just one of them representative enough?
        # The top row of the csv_type ds will contain the current csv_input row's type information
        gens = [field_fuzzer(csv_type[i][indx], csv_input_curr[i][indx], csv_input_curr[i][indx]) for indx in range(len(csv_input_curr[i]))]
        done = [False for _ in range(len(csv_input_curr[i]))]
        j = 0
        count_done = 0
        while count_done < len(gens):

            if j >= len(gens):
                j = 0

            if not done[j]:
                try:
                    csv_input_curr[i][j] = next(gens[j])
                    yield csv_input_curr
                except StopIteration:
                    done[j] = True
                    count_done += 1

            j += 1

        i += 1
