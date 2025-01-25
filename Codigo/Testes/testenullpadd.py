import os

def clean_null_padding(file_path, output_path=None):
    try:
        # Binary mode
        with open(file_path, 'rb') as f:
            content = f.read()

        # Strip null bytes
        cleaned_content = content.rstrip(b'\x00')

        # Output path
        if output_path is None:
            base, ext = os.path.splitext(file_path)
            output_path = f"{base}_cleaned{ext}"

        # Cleaned file
        with open(output_path, 'wb') as f:
            f.write(cleaned_content)

        print(f"Null padding removed. Cleaned file saved at: {output_path}")
        return output_path

    except Exception as e:
        print(f"Error cleaning file: {e}")
        return None


if __name__ == "__main__":
    input_file = input("Enter the path to the file you want to clean: ")
    clean_null_padding(input_file)
