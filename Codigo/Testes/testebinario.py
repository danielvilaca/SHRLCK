import os
import re
import math

def read_binary(file_path):
    try:
        with open(file_path, "rb") as file:
            return file.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        return None

def detect_null_padding(data):
    null_blocks = re.findall(b'\x00{4,}', data)  #4+ null bytes
    return null_blocks

def calculate_entropy(data):
    if not data:
        return 0

    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1

    entropy = 0
    total_bytes = len(data)
    for count in byte_counts:
        if count > 0:
            frequency = count / total_bytes
            entropy -= frequency * math.log2(frequency)

    return entropy

def extract_readable_strings(data, min_length=4):
    ascii_strings = re.findall(b'[ -~]{%d,}' % min_length, data)  #ASCII
    unicode_strings = re.findall(b'(?:[\x20-\x7E][\x00]){%d,}' % min_length, data)  #UTF-16
    return ascii_strings + unicode_strings

def analyze_binary(file_path):
    print(f"Analyzing binary file: {file_path}")
    data = read_binary(file_path)

    if data is None:
        return

    #Null padding
    null_blocks = detect_null_padding(data)
    print(f"Null Padding Blocks Detected: {len(null_blocks)}")

    #Entropy
    entropy = calculate_entropy(data)
    print(f"File Entropy: {entropy:.4f} (High entropy suggests encryption/obfuscation)")

    #Extract
    strings = extract_readable_strings(data)
    print(f"Extracted Strings ({len(strings)}):")
    for s in strings[:10]:  #First 10 strings
        print(f"  {s.decode(errors='ignore')}")

    print("\nAnalysis complete.")

if __name__ == "__main__":
    file_path = input("Enter the path to the binary file: ").strip()

    if os.path.exists(file_path):
        analyze_binary(file_path)
    else:
        print("File not found. Please check the path and try again.")
