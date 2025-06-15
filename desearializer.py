import pefile
from capstone import *
import re 
import argparse

# Given a function address, return the first place it is called as well as the encapsulating function
def find_xrefs(target, pe):
    print(f'Hunting for xrefs to {hex(target)}')
    code_section = next(s for s in pe.sections if b'.text' in s.Name)
    code = code_section.get_data()
    code_addr = code_section.VirtualAddress + pe.OPTIONAL_HEADER.ImageBase 
    code_len = len(code)
    offset = 0
    last_prologue = -1            
    
    md = Cs(CS_ARCH_X86, CS_MODE_64) 
    while offset < code_len: 
        curr = offset            
        try:
            slice = code[offset:offset + 16] # max x86_64 instr length is 15 bytes
            for (address, size, mnemonic, op_str) in md.disasm_lite(slice, code_addr + offset, count=1):
                if not mnemonic:
                    offset += 1
                    continue                 
                if mnemonic == 'sub' and 'rsp' in op_str:
                    last_prologue = address # Probably not a perfect check
                else:                                        
                    match = re.search(r'\[rip ([+-]) (0x[0-9a-fA-F]+)\]', op_str)
                    if match:
                        sign, val = match.groups()
                        disp = int(val, 16)
                        if sign == '-':
                            disp = -disp
                        end = address + size                                 
                        call_target = end + disp
                        #print(f'Call target: {hex(call_target)}')
                        if target == call_target:
                            print(f'Found call to target address. XREF: {hex(address)}.  Potential function start: {hex(last_prologue)}')
                            return address, last_prologue
                offset += size                
            if curr == offset:
                offset += 1
        
        except CsError as e:
            print(f'Capstone error at offset {offset}: {e}')
            offset += 1                            

# Given a function name, parse the IAT to find the function address
def find_import_address(import_name: bytes, pe: pefile.PE):    
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name and import_name in imp.name:
                rva = imp.address - pe.OPTIONAL_HEADER.ImageBase
                print(f'{import_name.decode("utf-8")} RVA: {hex(rva)}')
                return imp.address
    return None                                            

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file')
    args = parser.parse_args()
    pe = pefile.PE(args.file)
    target = find_import_address(b'LoadResource', pe)
    if target:
        print('Finding xrefs to LoadResource')
        xref, func = find_xrefs(target, pe)
        if not xref or not func:
            print(f'Could not determine xref to LoadResource or encapsulating function. XREF: {xref} FUNC: {func}')        

if __name__ == '__main__':
    main()