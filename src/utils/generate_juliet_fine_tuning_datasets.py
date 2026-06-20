import json
from itertools import zip_longest
from pathlib import Path

from datasets import load_dataset

from dataset_generation_utils import SYSTEM_PROMPT, extract_cwe_from_filename, filter_by_cases_only_in_c


def build_chat_example_train(code: str, expected_label: str, filename: str, case_type: str):
    system_content = SYSTEM_PROMPT
    user_content = f"{code}"

    messages = [
        { "role": "system", "content": system_content },
        { "role": "user", "content": user_content },
        { "role": "assistant", "content": expected_label }
    ]

    return {
        "messages": messages,
        "cwe": expected_label,
        "code": code,
        "filename": filename,
        "type": case_type
    }

def build_chat_example_test(code: str, expected_label: str, filename: str, case_type: str):
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

def process_row(row, processing_function):
    filename = row['filename']

    # Dataset 'class' column is a specific classifying column - we get the full CWE Identifier
    cwe_bad = extract_cwe_from_filename(filename)

    examples = []
    # Process 'good' cases
    examples.append(processing_function(
        code=row['good'],
        expected_label="SAFE",
        filename=filename,
        case_type="good"
    ))

    # Process 'bad' cases
    examples.append(processing_function(
        code=row['bad'],
        expected_label=cwe_bad,
        filename=filename,
        case_type="bad"
    ))

    return examples

def sort_and_interleave_good_and_bad(ds, processing_function):
    chat_examples = []
    for example in ds:
        chat_examples.extend(process_row(example, processing_function))

    good_examples_sorted = sorted([example for example in chat_examples if example["type"] == "good"], key=lambda ex: len(ex["code"]))
    bad_examples_sorted = sorted([example for example in chat_examples if example["type"] == "bad"], key=lambda ex: len(ex["code"]))

    interleaved_examples = []
    for good_example, bad_example in zip_longest(good_examples_sorted, bad_examples_sorted):
        if good_example is not None:
            interleaved_examples.append(good_example)
        if bad_example is not None:
            interleaved_examples.append(bad_example)

    return interleaved_examples


def main():
    # Output at directory datasets
    father_directory = Path(__file__).resolve().parent
    output_folder = father_directory / "datasets" / "fine-tuning"
    training_dataset_output_file = output_folder / "ordered_training_ds_juliet.jsonl"
    testing_dataset_output_file = output_folder / "ordered_testing_ds_juliet.jsonl"

    # Create folder if it does not exist
    output_folder.mkdir(exist_ok=True)

    # DATASET LINK: https://huggingface.co/datasets/LorenzH/juliet_test_suite_c_1_3
    target_dataset = "LorenzH/juliet_test_suite_c_1_3"
    # Filter dataset data only by C test cases and specific CWEs
    train_ds, test_ds = [ds.filter(filter_by_cases_only_in_c) for ds in load_dataset(target_dataset, split=["train", "test"])]

    filtered_training_ds = train_ds.filter(filter_by_cases_only_in_c)
    filtered_test_ds = test_ds.filter(filter_by_cases_only_in_c)

    interleaved_training_dataset = sort_and_interleave_good_and_bad(filtered_training_ds, build_chat_example_train)
    with open(file=training_dataset_output_file, mode="w", encoding="utf-8") as f:
        for ex in interleaved_training_dataset:
            f.write(json.dumps(ex, ensure_ascii=False) + '\n')

    print(f"Generated {len(interleaved_training_dataset)} training examples in chat format.")
    print(f"File can be found at location: {training_dataset_output_file.resolve()}\n")

    interleaved_test_dataset = sort_and_interleave_good_and_bad(filtered_test_ds, build_chat_example_test)
    with open(file=testing_dataset_output_file, mode="w", encoding="utf-8") as f:
        for ex in interleaved_test_dataset:
            f.write(json.dumps(ex, ensure_ascii=False) + '\n')

    print(f"Generated {len(interleaved_test_dataset)} testing examples in chat format.")
    print(f"File can be found at location: {testing_dataset_output_file.resolve()}")

if __name__ == "__main__":
    main()