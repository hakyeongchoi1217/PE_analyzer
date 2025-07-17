import pefile

#pe = pefile.PE("C:\Users\chk44\OneDrive\바탕 화면\ori_notepad.exe")  # 분석할 PE 파일 경로
pe = pefile.PE("ori_notepad.exe")



print(f"Entry Point: 0x{pe.OPTIONAL_HEADER.AddressOfEntryPoint:x}")
print(f"Image Base: 0x{pe.OPTIONAL_HEADER.ImageBase:x}")

print("\n[Section Table]")
for section in pe.sections:
    name = section.Name.decode().strip('\x00')
    va = section.VirtualAddress
    size = section.SizeOfRawData
    entropy = section.get_entropy()
    print(f"  {name:8} VA: 0x{va:08x}  Size: {size}  Entropy: {entropy:.2f}")
