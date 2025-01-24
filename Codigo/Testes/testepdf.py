import os
from PyPDF2 import PdfReader
import re
import math
from collections import Counter

def calculate_entropy(data):
    """Calculate the Shannon entropy of a byte sequence."""
    if not data:
        return 0
    counter = Counter(data)
    length = len(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())
    return entropy

def extract_metadata(file_path):
    try:
        reader = PdfReader(file_path)
        metadata = reader.metadata

        print("Metadata:")
        if metadata:
            for key, value in metadata.items():
                print(f"  {key}: {value}")
        else:
            print("  No metadata found.")
        print()
    except Exception as e:
        print(f"Error extracting metadata: {e}")

def check_for_javascript(file_path):
    try:
        reader = PdfReader(file_path)
        javascript_detected = False

        for page in reader.pages:
            text = page.get_text()
            if '/JS' in text or '/JavaScript' in text:
                javascript_detected = True
                break

        print("JavaScript Detection:")
        if javascript_detected:
            print("  JavaScript found in the PDF (possible malicious behavior).")
        else:
            print("  No JavaScript detected.")
        print()
    except Exception as e:
        print(f"Error checking for JavaScript: {e}")

def extract_embedded_objects(file_path):
    try:
        with open(file_path, 'rb') as f:
            content = f.read()

        embedded_files = re.findall(rb'/EmbeddedFile', content)
        print("Embedded Objects Detection:")
        if embedded_files:
            print(f"  Detected {len(embedded_files)} embedded objects (may contain malicious payloads).")

            # Save embedded files for further analysis
            for i, match in enumerate(embedded_files):
                file_name = f"embedded_object_{i}.bin"
                with open(file_name, "wb") as obj_file:
                    obj_file.write(match)
                print(f"  Saved embedded object to: {file_name}")
        else:
            print("  No embedded objects found.")
        print()
    except Exception as e:
        print(f"Error extracting embedded objects: {e}")

def detect_suspicious_keywords(file_path):
    try:
        with open(file_path, 'rb') as f:
            content = f.read()

        keywords = [b"/OpenAction", b"/Launch", b"/URI", b"/JS", b"/JavaScript"]
        found_keywords = [keyword.decode() for keyword in keywords if keyword in content]

        print("Suspicious Keywords Detection:")
        if found_keywords:
            print(f"  Found suspicious keywords: {', '.join(found_keywords)}")
        else:
            print("  No suspicious keywords found.")
        print()
    except Exception as e:
        print(f"Error detecting suspicious keywords: {e}")

def check_encryption(file_path):
    try:
        reader = PdfReader(file_path)

        print("Encryption Check:")
        if reader.is_encrypted:
            print("  PDF is encrypted (may contain obfuscated or hidden content).")
        else:
            print("  PDF is not encrypted.")
        print()
    except Exception as e:
        print(f"Error checking for encryption: {e}")

def calculate_file_entropy(file_path):
    try:
        with open(file_path, 'rb') as f:
            content = f.read()

        entropy = calculate_entropy(content)
        print("File Entropy:")
        print(f"  Entropy: {entropy:.2f}")
        if entropy > 7.5:
            print("  High entropy detected (file may contain compressed or obfuscated content).")
        elif entropy < 1.0:
            print("  Low entropy detected (file may contain null padding).")
        else :
            print("  Normal entropy detected.")
        print()
    except Exception as e:
        print(f"Error calculating entropy: {e}")

def analyze_pdf(file_path):
    print(f"Analyzing PDF: {file_path}")
    print("=" * 50)

    if not os.path.exists(file_path):
        print("Error: File not found.")
        return

    extract_metadata(file_path)
    
    check_for_javascript(file_path)

    extract_embedded_objects(file_path)

    detect_suspicious_keywords(file_path)

    check_encryption(file_path)

    calculate_file_entropy(file_path)

    print("PDF Analysis Complete.\n")

if __name__ == "__main__":
    file_path = input("Enter the path to the PDF file: ").strip()
    analyze_pdf(file_path)
