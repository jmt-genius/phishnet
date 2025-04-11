import csv
import json

def csv_to_json(csv_file_path, json_file_path):
    data_list = []

    with open(csv_file_path, encoding='utf-8') as csv_file_handler:
        csv_reader = csv.DictReader(csv_file_handler)

        for row in csv_reader:
            data_list.append(row)

    with open(json_file_path, 'w', encoding='utf-8') as json_file_handler:
        json.dump(data_list, json_file_handler, indent=4)

# Example usage
csv_to_json("transactions.csv", "transactions.json")
