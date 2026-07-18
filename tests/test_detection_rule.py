import json
import os

def rule_matches(log):
    image = log.get("Image", "")
    command_line = log.get("CommandLine", "")

    ends_with_powershell = image.endswith("\\powershell.exe")

    encoded_flags = ["-EncodedCommand", "-enc ", "-e ", " -Enc"]
    has_encoded_flag = any(flag in command_line for flag in encoded_flags)

    is_legit_script = "C:\\Scripts\\legitimate-automation.ps1" in command_line

    return ends_with_powershell and has_encoded_flag and not is_legit_script


def run_test(filename, expected_result):
    path = os.path.join("tests", "sample-logs", filename)
    with open(path) as f:
        log = json.load(f)

    result = rule_matches(log)
    status = "PASS" if result == expected_result else "FAIL"
    print(f"[{status}] {filename} -> rule triggered: {result} (expected: {expected_result})")


if __name__ == "__main__":
    run_test("true_positive_encoded_command.json", expected_result=True)
    run_test("true_negative_normal_usage.json", expected_result=False)
