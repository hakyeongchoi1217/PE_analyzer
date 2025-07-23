import pefile
from analyzer.entrophy import calculate_entropy

def analyze_pe(filepath):
    try:
        pe = pefile.PE(filepath)
    
    except FileNotFoundError:
        return "Error : Cannot Found File"
    
    except pefile.PEFormatError:
        return "Error : Not Valid PE File"
    
    report = []

    report.append(f"Entry Point : 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")
    report.append(f"Imange Base : 0x{pe.OPTIONAL_HEADER.ImageBase:x}\n")
    report.append("Sections: ")
    for section in pe.sections:
        name = section.Name.decode(errors ='ignore').strip('\x00')
        va = section.VirtualAddress
        size = section.SizeOfRawData
        entropy = calculate_entropy(section.get_data())
        alert = "High Entropy" if entropy > 7.0 else ""
        report.append(f"{name:8} VA : 0x{va:08x} Size: {size:6} Entropy : {entropy:.2f} {alert}")

    
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        report.append("\n Import Table:")
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            report.append(f"{entry.dll.decode()}")
            for imp in entry.imports:
                name = imp.name.decode() if imp.name else "ordinal"
                report.append(f"0x{imp.address:x}:{name}")
    
    else:
        report.append("\nImport Table : 없음")

    
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        report.append("\nExport Table: ")
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            name = exp.name.decode() if exp.name else "ordinal"
            address = pe.OPTIONAL_HEADER.ImageBase + exp.address
            report.append("f 0x{address:x}:{name}")
    
    else:
        report.append("\n Export Table : 없음")

    return "\n".join(report)