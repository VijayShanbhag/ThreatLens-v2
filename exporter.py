import json
import csv


def export_json(
    alerts,
    path
):

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            alerts,
            file,
            indent=4
        )


def export_csv(
    alerts,
    path
):

    with open(
        path,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=[
                "severity",
                "type",
                "ip",
                "mitre",
                "log"
            ]
        )

        writer.writeheader()

        writer.writerows(
            alerts
        )