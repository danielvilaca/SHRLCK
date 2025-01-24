import os
import pefile

def analyze_pe_file(file_path):
    try:
        #Load
        pe = pefile.PE(file_path)

        print(f"Analyzing PE file: {file_path}")
        print("=" * 50)

        print("Basic Information:")
        print(f"  Machine: {hex(pe.FILE_HEADER.Machine)}")
        print(f"  Number of Sections: {pe.FILE_HEADER.NumberOfSections}")
        print(f"  Time Date Stamp: {hex(pe.FILE_HEADER.TimeDateStamp)}")
        print(f"  Characteristics: {hex(pe.FILE_HEADER.Characteristics)}")
        print()

        print("Sections:")
        for section in pe.sections:
            print(f"  Name: {section.Name.decode().strip()}")
            print(f"    Virtual Address: {hex(section.VirtualAddress)}")
            print(f"    Virtual Size: {hex(section.Misc_VirtualSize)}")
            print(f"    Raw Size: {hex(section.SizeOfRawData)}")
            print(f"    Characteristics: {hex(section.Characteristics)}")
            print()

        #Imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            print("Imported DLLs and Functions:")
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                print(f"  DLL: {entry.dll.decode()}")
                for imp in entry.imports:
                    print(f"    {hex(imp.address)}: {imp.name.decode() if imp.name else 'Ordinal'}")
                print()
        else:
            print("No imports found.\n")

        #Exports
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            print("Exported Functions:")
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                print(f"  {hex(pe.OPTIONAL_HEADER.ImageBase + exp.address)}: {exp.name.decode() if exp.name else 'Ordinal'}")
            print()
        else:
            print("No exports found.\n")

        print("Suspicious Indicators:")
        for section in pe.sections:
            entropy = section.get_entropy()
            if entropy > 7.5:  #Possible obfuscation
                print(f"  Section {section.Name.decode().strip()} has high entropy: {entropy:.2f}")
            elif entropy < 1.0:  #Null padding
                print(f"  Section {section.Name.decode().strip()} has low entropy: {entropy:.2f}")
            else :
                print(f"  Section {section.Name.decode().strip()} has normal entropy: {entropy:.2f}")
            print()

        print("PE Analysis Complete.\n")

    except pefile.PEFormatError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected Error: {e}")

if __name__ == "__main__":
    file_path = input("Enter the path to the PE file: ").strip()

    if os.path.exists(file_path):
        analyze_pe_file(file_path)
    else:
        print("File not found. Please check the path and try again.")
