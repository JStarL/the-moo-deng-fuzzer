import csv

csv_data = [
    ["Name", "Age", "City", "Date", "Birth of Date"],
    ["John", 25, "Alice Springs", "2022-01-01", "19 Jan 1973"],
    ["Alice", 30, "Los Angeles", "2022-02-01", "5 Sep 2001"],
    ["Bob", 35, "Sydney", "2022-03-01", "27 May 1938"],
    ["Mary", 6, "New York", "2022-04-01", "31 Feb 2019"]
]

with open("vuln.csv", "w", newline='', encoding='utf-8') as file:
    writer = csv.writer(file)
    writer.writerows(csv_data)

with open("vuln.csv", "rb") as f:
    csv_binary = f.read()

with open("vuln_csv_binary", "wb") as b:
    b.write(csv_binary)