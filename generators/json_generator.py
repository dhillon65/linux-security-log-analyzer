import json
from pathlib import Path


class JSONGenerator:

    def generate(
        self,
        results,
        output_file
    ):

        Path(output_file).parent.mkdir(
            parents=True,
            exist_ok=True
        )

        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                results,
                f,
                indent=4,
                default=str
            )

        return output_file