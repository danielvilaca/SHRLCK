import os
import stat
import magic
from datetime import datetime

def get_file_metadata(file_path):
    try:
        file_stats = os.stat(file_path)

        mime = magic.Magic(mime=True)
        file_type = mime.from_file(file_path)

        #Extract
        metadata = {
            'File Name': os.path.basename(file_path),
            'File Path': file_path,
            'File Size': f"{file_stats.st_size} bytes",
            'Owner ID': file_stats.st_uid,
            'Group ID': file_stats.st_gid,
            'Last Accessed': datetime.fromtimestamp(file_stats.st_atime).strftime('%Y-%m-%d %H:%M:%S'),
            'Last Modified': datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
            'File Type': file_type
        }

        return metadata

    except Exception as e:
        return {'Error': str(e)}

if __name__ == "__main__":
    file_path = input("Enter the path to the file: ").strip()

    if os.path.exists(file_path):
        metadata = get_file_metadata(file_path)
        for key, value in metadata.items():
            print(f"{key}: {value}")
    else:
        print("File not found. Please check the path and try again.")
