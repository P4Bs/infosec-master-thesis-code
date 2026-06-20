import re

SYSTEM_PROMPT = """You are a security code analyzer specialized in vulnerability classification according to the CWE (Common Weakness Enumeration) taxonomy.

TASK: Analyze the provided source code snippet and determine whether it contains an exploitable security vulnerability.

OUTPUT FORMAT (STRICT):
- Your response must consist ONLY of one of these two formats:
  1. ONLY ONE VALID CWE identifier in the exact format: CWE-XXX (where XXX is the number, no leading zeros, e.g., CWE-89, CWE-79, CWE-22)
  2. The word: SAFE
- Do NOT add explanations, reasoning, extra text, quotation marks, trailing punctuation, or words like "Vulnerability:" or similar.
- Do NOT return multiple CWEs separated by commas. If you detect several vulnerabilities, return only the most critical/exploitable one.
- If the code is ambiguous but does not show a clear, exploitable vulnerability pattern, respond SAFE.

EXAMPLES OF CORRECT RESPONSES (everything you should ever produce):
"CWE-89"
"SAFE"
"CWE-79"
"CWE-416"

CLASSIFICATION EXAMPLES (few-shot):

Code:
char buffer[10];
strcpy(buffer, user_input);
Response:
CWE-120

Code:
free(ptr);
...
printf("%s", ptr->name);
Response:
CWE-416

Now analyze the following code and respond ONLY with CWE-XXX or SAFE:

"""

CWE_LIST = [ 121, 122, 123, 124, 126, 127, 244, 401, 415, 416, 476, 562, 590, 674, 680, 685, 688, 761, 762, 789, 835 ]
CWE_PATTERN_FILENAME = re.compile(r"CWE(\d+)")

def filter_by_cases_only_in_c(example) -> bool:
    if not example["filename"].endswith(".c"):
        return False

    match = CWE_PATTERN_FILENAME.search(example["filename"])
    if not match:
        return False

    cwe_num = int(match.group(1))

    return cwe_num in CWE_LIST

def extract_cwe_from_filename(filename: str) -> str | None:
    match = CWE_PATTERN_FILENAME.search(filename)
    return f"CWE-{match.group(1)}" if match else None
