from capstone import *

"""
disassembles arm64 little endian binary

args:
+ binary (bytes): the raw bytes to disassemble
+ start_address (int): the starting address 

returns:
+ instructions (list): a list of disassembled instructions
"""

def disassemble_arm64_little(bytes: bytes, start_address: int) -> list:
	md = Cs(CS_ARCH_ARM64, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
	instructions = []

	for instruction in md.disasm(bytes, start_address):
		instructions.append({
			"address": instruction.address,
			"mnemonic": instruction.mnemonic,
			"op_str": instruction.op_str
		})
	
	return instructions

