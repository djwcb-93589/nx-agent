import argparse
import json
from pathlib import Path
from typing import Any


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def save_json(path: Path, data: Any) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=3)
        f.write("\n")


def map_pairs_with_schema(pairs: list[Any], schema: list[Any]) -> list[Any]:
    if len(pairs) != len(schema):
        raise ValueError(
            f"Length mismatch: pairs has {len(pairs)} items, schema has {len(schema)} items."
        )

    mapped_pairs: list[Any] = []

    for pair_item, schema_item in zip(pairs, schema):
        if not isinstance(pair_item, list) or not pair_item:
            mapped_pairs.append(pair_item)
            continue

        rule_map = {}
        if (
            isinstance(schema_item, list)
            and schema_item
            and isinstance(schema_item[0], dict)
        ):
            rule_map = schema_item[0]

        new_pair_item: list[Any] = [pair_item[0]]

        for field_entry in pair_item[1:]:
            if not isinstance(field_entry, list) or not field_entry:
                new_pair_item.append(field_entry)
                continue

            source_field = field_entry[0]
            if (
                isinstance(source_field, str)
                and source_field in rule_map
                and isinstance(rule_map[source_field], str)
                and rule_map[source_field]
            ):
                new_field_name = f"{source_field}->{rule_map[source_field]}"
                new_field_entry = [new_field_name, *field_entry[1:]]
                new_pair_item.append(new_field_entry)
            else:
                new_pair_item.append(field_entry)

        mapped_pairs.append(new_pair_item)

    return mapped_pairs


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Map field names in pairs JSON using schema JSON rules, and write to a new file."
        )
    )
    parser.add_argument(
        "--pairs",
        default="pairs_syslog.json",
        help="Path to pairs JSON file. Default: pairs_syslog.json",
    )
    parser.add_argument(
        "--schema",
        default="schema_syslog.json",
        help="Path to schema JSON file. Default: schema_syslog.json",
    )
    parser.add_argument(
        "--output",
        default="pairs_syslog_mapped.json",
        help="Output JSON path. Default: pairs_syslog_mapped.json",
    )
    args = parser.parse_args()

    pairs_path = Path(args.pairs)
    schema_path = Path(args.schema)
    output_path = Path(args.output)

    pairs = load_json(pairs_path)
    schema = load_json(schema_path)

    if not isinstance(pairs, list):
        raise TypeError(f"Expected list in pairs file: {pairs_path}")
    if not isinstance(schema, list):
        raise TypeError(f"Expected list in schema file: {schema_path}")

    mapped_pairs = map_pairs_with_schema(pairs, schema)
    save_json(output_path, mapped_pairs)

    print(f"Mapped JSON written to: {output_path}")


if __name__ == "__main__":
    main()
