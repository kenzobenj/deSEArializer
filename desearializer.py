import pefile
from capstone import *
import re 
import argparse
import speakeasy
import struct
import os

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
                else:           # Maybe only if mnemonic == call?                    
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

class SEADumper(speakeasy.Speakeasy):

    def __init__(self, output_path, debug=False, func_start=-1):
        super(SEADumper, self).__init__(debug=debug)
        self.output_path = output_path
        self.func_start = func_start
        self.count = 0
        self.called_func = False

    def code_hook(self, emu, addr, size, ctx):
        if self.func_start == -1:
            print('!!!! Target function not specified. Exiting...')
            self.stop()
        if self.count > 30:
            print('[*] Emulator ran for too long, exiting.')
            self.stop()
        if addr == self.func_start:
            print(f'Hit target function start.')            
            self.called_func = True
            return True
        opcode = emu.mem_read(addr, size)
        if self.called_func and opcode[0] == 0xC3:
            print(f"[+] Hit RET at {hex(addr)}")
            self.search_and_dump_sea_blob(emu, addr)                
            self.count += 1
        # if self.func_start == addr:
        #     print('[*] Reached SEA blob loader function.')            
        #     self.stop()
        return True

    # TODO for testing, specify the exact ret address and just dump that.  Maybe it's not actually loading resources?
    def search_and_dump_sea_blob(self, emu, addr):                
        magic = struct.pack("<I", 0x0143DA20)            
        for tag, base, size, is_free, proc, data in self.get_memory_dumps():
            if is_free:
                continue  # Skip unallocated/free pages           
            #offset = data.find(magic) 
            indices = [] 
            for match in re.finditer(magic, data):
                indices.append(match.start())
            for index in indices:
                print(f"[+] SEA blob found at {hex(base + index)}")
                with open(f'seablob_dump_{hex(base + index)}', 'wb') as file:
                    file.write(data[index:])                                                           

        print("[-] SEA blob not found in memory. Continuing...")        


def parse_dumps():
    flags = {'kDefault' : 0,
  'kDisableExperimentalSeaWarning' : 1 << 0,
  'kUseSnapshot' : 1 << 1,
  'kUseCodeCache' : 1 << 2,
  'kIncludeAssets' : 1 << 3}    
    for filename in os.listdir('.'):
        if filename.startswith('seablob_dump'):
            with open(filename, 'rb') as file:
                print('\n-------------------------------------------------------------------------\n')
                print(f'Parsing {filename}\n')
                magic = file.read(4)
                #print(f'{filename} magic and flags:')
                #print(' '.join(f'{b:02X}' for b in metadata)) # print magic and flags
                flag_bytes = int.from_bytes(file.read(4), byteorder='little')
                set_flags = [key for key, value in flags.items() if value & flag_bytes]
                print(f'Flags: {set_flags}')
                #TODO handle use_snapshot
                #TODO handle use_code_cache
                #TODO handle include_assets                                
                script_name_size = int.from_bytes(file.read(8), byteorder='little')
                if script_name_size > 500: #arbitrary big number
                    print(f'Script name size too big. Might not be valid blob: {script_name_size}')
                    continue
                try:
                    script_name = file.read(script_name_size).decode('utf-8')
                    print(f'Script name: {script_name}')
                except UnicodeDecodeError:
                    print('Cannot parse script name. Might not be valid blob')
                    continue            
                script_size = int.from_bytes(file.read(8), byteorder='little')
                print(f'Script size: {script_size}')
                try:
                    script_bytes = file.read(script_size)
                except MemoryError:
                    print('Failed to read script content. Possibly invalid blob.')
                    continue
                dump_name = f'{script_name}.dump'
                with open(dump_name, 'wb') as dump:
                    dump.write(script_bytes)
                print(f'Script saved as: {dump_name}')





def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('file')
    args = parser.parse_args()
    confirm = input('Are you running this script from the malware folder???') # TODO remove this
    pe = pefile.PE(args.file)
    target = find_import_address(b'LoadResource', pe)
    if target:
        print('Finding xrefs to LoadResource')
        xref, func = find_xrefs(target, pe)
        if not xref or not func:
            print(f'Could not determine xref to LoadResource or encapsulating function. XREF: {xref} FUNC: {func}')     
        seaDumper = SEADumper(args.file, debug=False, func_start=func)
        module = seaDumper.load_module(args.file)
        #seaDumper.base_addr = pe.OPTIONAL_HEADER.ImageBase 
        #seaDumper.start_addr = func         
        seaDumper.add_code_hook(seaDumper.code_hook)
        seaDumper.run_module(module, all_entrypoints=False)        
        seaDumper.call(func, [])
        parse_dumps()


if __name__ == '__main__':
    main()