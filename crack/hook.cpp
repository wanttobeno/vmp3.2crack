#include "stdafx.h"
#include <windows.h>

#include "hook.h"

//prefix_ins
#define C_66           0x00000001       // 66-prefix
#define C_67           0x00000002       // 67-prefix
#define C_LOCK         0x00000004       // lock
#define C_REP          0x00000008       // repz/repnz
#define C_SEG          0x00000010       // seg-prefix
#define C_OPCODE2      0x00000020       // 2nd opcode present (1st==0F)
#define C_MODRM        0x00000040       // modrm present
#define C_SIB          0x00000080       // sib present
#define C_ANYPREFIX    (C_66|C_67|C_LOCK|C_REP|C_SEG)
DWORD disasm_len;                       // 0 if error
DWORD disasm_flag;                      // C_xxx
DWORD disasm_memsize;                   // value = disasm_mem
DWORD disasm_datasize;                  // value = disasm_data
DWORD disasm_defdata;                   // == C_66 ? 2 : 4
DWORD disasm_defmem;                    // == C_67 ? 2 : 4
BYTE  disasm_seg;                       // CS DS ES SS FS GS
BYTE  disasm_rep;                       // REPZ/REPNZ
BYTE  disasm_opcode;                    // opcode
BYTE  disasm_opcode2;                   // used when opcode==0F
BYTE  disasm_modrm;                     // modxxxrm
BYTE  disasm_sib;                       // scale-index-base
BYTE  disasm_mem[8];                    // mem addr value
BYTE  disasm_data[8];                   // data value

// ÷∏¡Ó≥§∂»
int len_disasm(BYTE* opcode0)
{
	BYTE* opcode = opcode0;

	disasm_len = 0;
	disasm_flag = 0;
	disasm_datasize = 0;
	disasm_memsize = 0;
	disasm_defdata = 4;
	disasm_defmem = 4;

retry:
	disasm_opcode = *opcode++;

	switch (disasm_opcode)
	{
	case 0x00: case 0x01: case 0x02: case 0x03:
	case 0x08: case 0x09: case 0x0A: case 0x0B:
	case 0x10: case 0x11: case 0x12: case 0x13:
	case 0x18: case 0x19: case 0x1A: case 0x1B:
	case 0x20: case 0x21: case 0x22: case 0x23:
	case 0x28: case 0x29: case 0x2A: case 0x2B:
	case 0x30: case 0x31: case 0x32: case 0x33:
	case 0x38: case 0x39: case 0x3A: case 0x3B:
	case 0x62: case 0x63:
	case 0x84: case 0x85: case 0x86: case 0x87:
	case 0x88: case 0x89: case 0x8A: case 0x8B:
	case 0x8C: case 0x8D: case 0x8E: case 0x8F:
	case 0xC4: case 0xC5:
	case 0xD0: case 0xD1: case 0xD2: case 0xD3:
	case 0xD8: case 0xD9: case 0xDA: case 0xDB:
	case 0xDC: case 0xDD: case 0xDE: case 0xDF:
	case 0xFE: case 0xFF:
		disasm_flag |= C_MODRM;
		break;
	case 0xCD: disasm_datasize += *opcode == 0x20 ? 1 + 4 : 1;
		break;
	case 0xF6:
	case 0xF7: disasm_flag |= C_MODRM;
		if (*opcode & 0x38) break;
		// continue if <test ..., xx>
	case 0x04: case 0x05: case 0x0C: case 0x0D:
	case 0x14: case 0x15: case 0x1C: case 0x1D:
	case 0x24: case 0x25: case 0x2C: case 0x2D:
	case 0x34: case 0x35: case 0x3C: case 0x3D:
		if (disasm_opcode & 1)
			disasm_datasize += disasm_defdata;
		else
			disasm_datasize++;
		break;
	case 0x6A:
	case 0xA8:
	case 0xB0: case 0xB1: case 0xB2: case 0xB3:
	case 0xB4: case 0xB5: case 0xB6: case 0xB7:
	case 0xD4: case 0xD5:
	case 0xE4: case 0xE5: case 0xE6: case 0xE7:
	case 0x70: case 0x71: case 0x72: case 0x73:
	case 0x74: case 0x75: case 0x76: case 0x77:
	case 0x78: case 0x79: case 0x7A: case 0x7B:
	case 0x7C: case 0x7D: case 0x7E: case 0x7F:
	case 0xEB:
	case 0xE0: case 0xE1: case 0xE2: case 0xE3:
		disasm_datasize++;
		break;
	case 0x26: case 0x2E: case 0x36: case 0x3E:
	case 0x64: case 0x65:
		if (disasm_flag & C_SEG) return 0;
		disasm_flag |= C_SEG;
		disasm_seg = disasm_opcode;
		goto retry;
	case 0xF0:
		if (disasm_flag & C_LOCK) return 0;
		disasm_flag |= C_LOCK;
		goto retry;
	case 0xF2: case 0xF3:
		if (disasm_flag & C_REP) return 0;
		disasm_flag |= C_REP;
		disasm_rep = disasm_opcode;
		goto retry;
	case 0x66:
		if (disasm_flag & C_66) return 0;
		disasm_flag |= C_66;
		disasm_defdata = 2;
		goto retry;
	case 0x67:
		if (disasm_flag & C_67) return 0;
		disasm_flag |= C_67;
		disasm_defmem = 2;
		goto retry;
	case 0x6B:
	case 0x80:
	case 0x82:
	case 0x83:
	case 0xC0:
	case 0xC1:
	case 0xC6: disasm_datasize++;
		disasm_flag |= C_MODRM;

		break;
	case 0x69:
	case 0x81:
	case 0xC7:
		disasm_datasize += disasm_defdata;
		disasm_flag |= C_MODRM;
		break;
	case 0x9A:
	case 0xEA: disasm_datasize += 2 + disasm_defdata;

		break;
	case 0xA0:
	case 0xA1:
	case 0xA2:
	case 0xA3: disasm_memsize += disasm_defmem;
		break;
	case 0x68:
	case 0xA9:
	case 0xB8: case 0xB9: case 0xBA: case 0xBB:
	case 0xBC: case 0xBD: case 0xBE: case 0xBF:
	case 0xE8:
	case 0xE9:
		disasm_datasize += disasm_defdata;
		break;
	case 0xC2:
	case 0xCA: disasm_datasize += 2;
		break;
	case 0xC8:
		disasm_datasize += 3;
		break;
	case 0xF1:
		return 0;
	case 0x0F:
		disasm_flag |= C_OPCODE2;
		disasm_opcode2 = *opcode++;
		switch (disasm_opcode2)
		{
		case 0x00: case 0x01: case 0x02: case 0x03:
		case 0x10: case 0x11: case 0x12: case 0x13:
		case 0x14: case 0x15: case 0x16: case 0x17:
		case 0x18: case 0x1f:
		case 0x20: case 0x21: case 0x22: case 0x23:
		case 0x28: case 0x29: case 0x2A: case 0x2B:
		case 0x2c: case 0x2d: case 0x2e: case 0x2f:
		case 0x40: case 0x41: case 0x42: case 0x43:
		case 0x44: case 0x45: case 0x46: case 0x47:
		case 0x48: case 0x49: case 0x4a: case 0x4b:
		case 0x4c: case 0x4d: case 0x4e: case 0x4f:
		case 0x50: case 0x51: case 0x52: case 0x53:
		case 0x54: case 0x55: case 0x56: case 0x57:
		case 0x58: case 0x59: case 0x5a: case 0x5b:
		case 0x5c: case 0x5d: case 0x5e: case 0x5f:
		case 0x60: case 0x61: case 0x62: case 0x63:
		case 0x64: case 0x65: case 0x66: case 0x67:
		case 0x68: case 0x69: case 0x6a: case 0x6b:
		case 0x6e: case 0x6f:
		case 0x74: case 0x75: case 0x76: case 0x78:
		case 0x79: case 0x7e: case 0x7f:
		case 0x90: case 0x91: case 0x92: case 0x93:
		case 0x94: case 0x95: case 0x96: case 0x97:
		case 0x98: case 0x99: case 0x9a: case 0x9b:
		case 0x9c: case 0x9d: case 0x9e: case 0x9f:
		case 0xA3: case 0xA5: case 0xAB: case 0xAD:
		case 0xAF:
		case 0xB0: case 0xB1: case 0xB2: case 0xB3:
		case 0xB4: case 0xB5: case 0xB6: case 0xB7:
		case 0xb8: case 0xBB:
		case 0xBC: case 0xBD: case 0xBE: case 0xBF:
		case 0xC0: case 0xC1: case 0xc3:
		case 0xd0: case 0xd1: case 0xd2: case 0xd3:
		case 0xd4: case 0xd5: case 0xd6: case 0xd7:
		case 0xd8: case 0xd9: case 0xda: case 0xdb:
		case 0xdc: case 0xdd: case 0xde: case 0xdf:
		case 0xe0: case 0xe1: case 0xe2: case 0xe3:
		case 0xe4: case 0xe5: case 0xe6: case 0xe7:
		case 0xe8: case 0xe9: case 0xea: case 0xeb:
		case 0xec: case 0xed: case 0xee: case 0xef:
		case 0xf0: case 0xf1: case 0xf2: case 0xf3:
		case 0xf4: case 0xf5: case 0xf6: case 0xf7:
		case 0xf8: case 0xf9: case 0xfa: case 0xfb:
		case 0xfc: case 0xfd: case 0xfe:
			disasm_flag |= C_MODRM;
			break;
		case 0x05: case 0x06: case 0x07: case 0x08:
		case 0x09: case 0x0d:
		case 0x30: case 0x31: case 0x32: case 0x33:
		case 0x34: case 0x35:
		case 0x77:
		case 0xA0: case 0xA1: case 0xA2: case 0xA8:
		case 0xA9: case 0xAA:
		case 0xC8: case 0xC9: case 0xCA: case 0xCB:
		case 0xCC: case 0xCD: case 0xCE: case 0xCF:
			break;
		case 0x80: case 0x81: case 0x82: case 0x83:
		case 0x84: case 0x85: case 0x86: case 0x87:
		case 0x88: case 0x89: case 0x8A: case 0x8B:
		case 0x8C: case 0x8D: case 0x8E: case 0x8F:
			disasm_datasize += disasm_defdata;
			break;
		case 0x70:
		case 0xA4: case 0xAC:
		case 0xBA:
		case 0xc2: case 0xc4: case 0xc5: case 0xc6:
			disasm_datasize++;
			disasm_flag |= C_MODRM;
			break;
		default:
			return 0;
		} // 0F-switch
		break;

	} //switch

	if (disasm_flag & C_MODRM)
	{
		disasm_modrm = *opcode++;
		BYTE mod = disasm_modrm & 0xC0;
		BYTE rm = disasm_modrm & 0x07;
		if (mod != 0xC0)
		{
			if (mod == 0x40) disasm_memsize++;
			if (mod == 0x80) disasm_memsize += disasm_defmem;
			if (disasm_defmem == 2)           // modrm16
			{
				if ((mod == 0x00) && (rm == 0x06)) disasm_memsize += 2;
			}
			else                              // modrm32
			{
				if (rm == 0x04)
				{
					disasm_flag |= C_SIB;
					disasm_sib = *opcode++;
					rm = disasm_sib & 0x07;

				}
				if ((rm == 0x05) && (mod == 0x00)) disasm_memsize += 4;
			}
		}
	} // C_MODRM
	disasm_len = ((disasm_flag&C_66) ? 1 : 0) + ((disasm_flag&C_67) ? 1 : 0) + ((disasm_flag&C_LOCK) ? 1 : 0) + ((disasm_flag&C_REP) ? 1 : 0) + ((disasm_flag&C_SEG) ? 1 : 0) + ((disasm_flag&C_OPCODE2) ? 2 : 1) + ((disasm_flag&C_MODRM) ? 1 : 0) + ((disasm_flag&C_SIB) ? 1 : 0) + disasm_memsize + disasm_datasize;
	return disasm_len;
}

#define __malloc(_s)	VirtualAlloc(NULL, _s, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
#define __free(_p)		VirtualFree(_p, 0, MEM_RELEASE)
#define JMP_SIZE		5


int write_memory(void* dest, void* src, int len)
{
	DWORD old;
	if (!VirtualProtect(dest, len, PAGE_EXECUTE_READWRITE, &old))
	{
		return -1;
	}

	memcpy(dest, src, len);

	if (!VirtualProtect(dest, len, old, &old))
	{
		return -1;
	}

	return 0;
}

int getlen(void *target)
{
	int len = 0;
	unsigned char *ptr = (unsigned char *)target;
	while (len < 5)
	{
		int l = len_disasm(ptr+len);
		if (l == 0)
			return 0;
		len += l;
	}
	return len;
}

void *skip(void *target)
{
	// 8BFF            mov     edi, edi
	unsigned char *ptr = (unsigned char *)target;
	if (*(unsigned short *)ptr == 0xFF8B)
		ptr += 2;
	return ptr;
}

void* jmphook(void* target, void* proc)
{
	if (!proc || target == 0)
		return 0;
	target = skip(target);

	int len = getlen(target);
	if (len < 5)
		return 0;

	unsigned char* block = (unsigned char*)__malloc(len + JMP_SIZE * 3);
	unsigned char* p = &block[0];

	// backup target code
	memcpy(p, target, len);
	p += len;

	*p++ = 0xE9; // jmp
	*(DWORD*)p = ((DWORD)target + len) - ((DWORD)p + 4);

	DWORD old;
	VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &old);

	unsigned char* q = (unsigned char*)target;
	*q++ = 0xE9; // jmp proc
	*(DWORD*)q = (DWORD)proc - ((DWORD)q + 4);

	VirtualProtect(target, 5, old, &old);
	return block;
}
