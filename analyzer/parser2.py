import pefile

def print_dos_header(path):
    pe = pefile.PE(path)
    print("=======  DOS HEADER  =======")
    print(f"e_magic (DOS SIGNATURE): {hex(pe.DOS_HEADER.e_magic)}")
    print(f"e_lfanew (NT HEADER START): {hex(pe.DOS_HEADER.e_lfanew)} ")

def print_nt_header(path):
    pe = pefile.PE(path)
    print("=======  NT HEADER  =======")
    print(f"Signature : {hex.(pe.NT_HEADERS.Signature)}")
    print(f"Machin : {hex.(pe.FILE_HEADER.Machine)}")
    print(f"NumberOfSections : {pe.FILE_HEADER.NumberOfSections}")
    print(f"TimeDataStamp : {hex(pe.FILE_HEADER.TimeDataStamp)}")

def print_section_header(path):
    pe = pefile.PE(path)
    print("======= SECTION HEADERS =======")
    for section in pe.sections:
        name = section.Name.decode(errors='ignore').strip('\x00')
        print(f"{name:8} | VA: 0x{section.VirtualAddress:08x} | Size : {section.SizeOfRawData} | Entropy : {section.get_entropy():.2f}")

def every(path):
    print_dos_header(path)
    print()
    print_nt_header(path)
    print()
    print_section_header(path)


