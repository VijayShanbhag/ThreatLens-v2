import csv
import json


def read_file(path):

    if path.endswith(".csv"):

        return read_csv(path)

    elif path.endswith(".json"):

        return read_json(path)

    else:

        return read_text(path)


def read_text(path):

    with open(
        path,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as file:

        return file.readlines()


def read_csv(path):

    rows = []

    with open(
        path,
        newline="",
        encoding="utf-8",
        errors="ignore"
    ) as file:

        reader = csv.DictReader(file)

        for row in reader:

            rows.append(
                str(row)
            )

    return rows


def read_json(path):

    rows = []

    with open(
        path,
        "r",
        encoding="utf-8"
    ) as file:

        data = json.load(file)

    if isinstance(data, list):

        for item in data:

            rows.append(
                str(item)
            )

    else:

        rows.append(
            str(data)
        )

    return rows