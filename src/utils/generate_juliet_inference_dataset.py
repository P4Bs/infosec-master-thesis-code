# Downloads the dataset LorenzH/juliet_test_suite_c_1_3 from Hugging Face. Filters by testcases only in the C
# language and then by CWE. CWE list can be found at module dataset_generation_utils

import json
from itertools import zip_longest
from pathlib import Path

from datasets import load_dataset, concatenate_datasets, DatasetDict
from dataset_generation_utils import SYSTEM_PROMPT, extract_cwe_from_filename, filter_by_cases_only_in_c


def build_chat_example(code: str, expected_label: str, filename: str, case_type: str):
    user_content = f"{SYSTEM_PROMPT}{code}"

    messages = [
        { "role": "user", "content": user_content },
    ]

    return {
        "messages": messages,
        "cwe": expected_label,
        "code": code,
        "filename": filename,
        "type": case_type
    }

def process_row(row):
    filename = row['filename']

    # Dataset 'class' column is a specific classifying column - we get the full CWE Identifier
    cwe_bad = extract_cwe_from_filename(filename)

    examples = []
    # Process 'good' cases
    examples.append(build_chat_example(
        code=row['good'],
        expected_label="SAFE",
        filename=filename,
        case_type="good"
    ))

    # Process 'bad' cases
    examples.append(build_chat_example(
        code=row['bad'],
        expected_label=cwe_bad,
        filename=filename,
        case_type="bad"
    ))

    return examples

def main_create_unified():
    # Output at directory datasets
    father_directory = Path(__file__).resolve().parent
    output_folder = father_directory / "datasets" / "inference"
    output_file = output_folder / "inference_juliet_unified_sorted.jsonl"

    # Create folder if it does not exist
    output_folder.mkdir(exist_ok=True)

    # DATASET LINK: https://huggingface.co/datasets/LorenzH/juliet_test_suite_c_1_3
    target_dataset = "LorenzH/juliet_test_suite_c_1_3"
    datasets: DatasetDict = load_dataset(target_dataset, split=["train", "test"])
    combined_filtered = concatenate_datasets(datasets).filter(filter_by_cases_only_in_c)

    all_examples = []
    for row in combined_filtered:
        all_examples.extend(process_row(row))

    # SPLIT IN GOOD AND BAD CASES
    good_examples = [example for example in all_examples if example["type"] == "good"]
    bad_examples = [example for example in all_examples if example["type"] == "bad"]

    # SORT BOTH COLLECTIONS BY CODE LENGTH
    sorted_good_examples = sorted(good_examples, key=lambda ex: len(ex["code"]))
    sorted_bad_examples = sorted(bad_examples, key=lambda ex: len(ex["code"]))

    # UNIFY THEM - FIRST GOOD, THEN BAD
    interleaved_examples = []
    for good_example, bad_example in zip_longest(sorted_good_examples, sorted_bad_examples):
        if good_example is not None:
            interleaved_examples.append(good_example)
        if bad_example is not None:
            interleaved_examples.append(bad_example)

    with open(file=output_file, mode="w", encoding="utf-8") as f:
        for ex in interleaved_examples:
            f.write(json.dumps(ex, ensure_ascii=False) + '\n')

    print(f"Generated {len(interleaved_examples)} examples in chat format.")
    print(f"File can be found at location: {output_file.resolve()}")

if __name__ == "__main__":
    # If you want to get a single jsonl file with good and bad cases
    main_create_unified()

    # If you want to separate good and bad cases in their own files
    # main_create_good_bad()
