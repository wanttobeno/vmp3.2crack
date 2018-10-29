// crack.cpp : Defines the exported functions for the DLL application.
//

#include "stdafx.h"
#include "crack.h"
#include "hook.h"

typedef PVOID (WINAPI *pfnRtlAllocateHeap)(PVOID HeapHandle, ULONG Flags, SIZE_T Size);

static pfnRtlAllocateHeap RtlAllocateHeap = 0;

unsigned char rsa_n[] = {
	0x80, 0x00, 0x31, 0xad, 0x6c, 0x8a, 0x59, 0x6b, 0xbe, 0xca, 0x99, 0x78, 0x2c, 0xed, 0xd2, 0xff,
	0xc9, 0x0b, 0x74, 0x5d, 0x5f, 0x87, 0x06, 0x96, 0x06, 0x81, 0x79, 0xe7, 0xea, 0x9a, 0xfb, 0x87,
	0xcc, 0x8c, 0x2e, 0xa9, 0xb4, 0x60, 0xfd, 0xaa, 0xd2, 0x18, 0xa4, 0x25, 0xaf, 0x8e, 0x84, 0xd1,
	0x5f, 0x3d, 0x12, 0xf9, 0xce, 0x2b, 0xe0, 0x0f, 0x86, 0xa5, 0xe7, 0x05, 0x00, 0x3b, 0xe5, 0xbc,
	0x51, 0xbc, 0xe5, 0x87, 0x29, 0x06, 0x2a, 0x75, 0x03, 0xd6, 0x71, 0x44, 0x7e, 0xca, 0x19, 0x23,
	0xb2, 0x41, 0x55, 0xfd, 0x93, 0x47, 0x31, 0xd8, 0xe3, 0xe9, 0xb4, 0x47, 0x02, 0xe0, 0x0e, 0x1e,
	0xf4, 0xa6, 0xcc, 0xe1, 0x48, 0x31, 0x85, 0x85, 0x08, 0xa2, 0xea, 0x04, 0x29, 0xf7, 0xcd, 0x0c,
	0x0e, 0x84, 0xc0, 0xd0, 0x24, 0xe1, 0x62, 0x3d, 0x2d, 0x5c, 0x65, 0xf1, 0xed, 0x82, 0x06, 0x9d,
	0xf2, 0xd7, 0x0c, 0xfb, 0x80, 0xb5, 0x13, 0xc7, 0x2b, 0xbf, 0x15, 0x7d, 0x45, 0x39, 0x18, 0xe8,
	0x8f, 0xd5, 0x48, 0xc3, 0x03, 0xb3, 0xc1, 0xc6, 0x98, 0x38, 0x1a, 0xc2, 0x9e, 0x61, 0xef, 0x56,
	0xb3, 0x53, 0x0b, 0x44, 0x05, 0xf9, 0x68, 0x13, 0x14, 0x4a, 0xa5, 0xef, 0x8f, 0x8f, 0x17, 0x6d,
	0xeb, 0x76, 0x64, 0x43, 0xe6, 0x6d, 0x4c, 0xfc, 0x35, 0x67, 0xf1, 0xc3, 0x8b, 0x44, 0x79, 0xaf,
	0xbb, 0x9c, 0x20, 0x5a, 0x46, 0x81, 0xc4, 0x84, 0x73, 0x88, 0x62, 0xd8, 0x1a, 0x7b, 0xde, 0x55,
	0xcd, 0x36, 0x3b, 0x18, 0xe0, 0x8b, 0xf8, 0x43, 0x89, 0xf2, 0x6e, 0xdb, 0x0e, 0x7e, 0xab, 0x0d,
	0x70, 0x90, 0x68, 0xdb, 0x8b, 0xc6, 0x17, 0xa1, 0xf0, 0xc0, 0xb1, 0xa4, 0xd0, 0x00, 0x20, 0xfa,
	0x1a, 0xeb, 0x2d, 0x16, 0x4f, 0x79, 0x85, 0xb8, 0xb7, 0xba, 0xc5, 0xb9, 0xc4, 0xa2, 0xcb, 0xe3,
	0x73, 0xbb
};

unsigned char *ptr_n = 0;

#define STACK_SIZE		0x18C

unsigned char *find_key(void *stack, DWORD addr)
{
	int first = 0;
	unsigned char *key = 0;
	unsigned char *ptr = (unsigned char *)stack;
	for (int i = 0; i < STACK_SIZE; i+=4)
	{
		if (addr == *(DWORD *)&ptr[i])
		{
			if (first != 0)
			{
				if (*(DWORD *)&ptr[i + 4] != 0x80)
				{
					key = &ptr[i + 4];
					break;
				}
			}
			if (*(DWORD *)&ptr[i + 4] == 0x80)
			{
				first = 1;
			}
		}
	}
	return key;
}

int write_rsa_n(unsigned char *ptr, int len)
{
	FILE *pf = fopen("rsa-n.bn", "wb");
	fwrite(ptr, len, 1, pf);
	fclose(pf);
	return 0;
}

#ifdef _DEBUG
void test(unsigned char *ptr, unsigned char *key)
{
	int addr = (int)ptr;
	for (int i = 0; i < sizeof(rsa_n); i += 2)
	{
		int P1 = (addr + i) & 0xFFFF;
		int P2 = ((addr + i) >> 4) & 0xFFFF;
		int A = ~(~(*(unsigned short *)&rsa_n[i]) + P1);
		int K = A ^ (*(unsigned short *)&ptr[i]);
		int X = K - P2 - 0x37;
		int vk = P2 + X + 0x37;

		printf("%04X->%04X, ", (unsigned short)K, (unsigned short)X);
		if (i % 8 == 0)
			printf("\n");
	}
	for (int i = 0; i < 20; i++)
	{
		printf("%02X ", key[i]);
	}
	printf("\n");
}
#endif

#define KEY			0x01

int gen_rsa_n(unsigned char *ptr, unsigned char *key)
{
	int addr = (int)ptr;
#ifdef _DEBUG
	//MessageBox(NULL, "Startup crack ck_setup. ", "crack.dll", MB_OK);
	test(ptr_n, key);
#endif
#ifdef RSA_N
	if (key[0] == KEY && key[1] == KEY)
	{
		for (int i = 0; i < sizeof(rsa_n); i+=2)
		{
			int P1 = (addr + i) & 0xFFFF;
			int P2 = ((addr + i) >> 4) & 0xFFFF;
			unsigned short K = P2 + KEY + 0x37;

			unsigned short C = *(unsigned short *)&ptr[i];
			unsigned short M = ~(~(C^K) - P1);
			*(unsigned short *)&rsa_n[i] = M;
		}
		write_rsa_n(rsa_n, sizeof(rsa_n));
	}
#else
	for (int i = 0; i < sizeof(rsa_n); i+=2)
	{
		int P1 = (addr + i) & 0xFFFF;
		int P2 = ((addr + i) >> 4) & 0xFFFF;
		unsigned short K = P2 + KEY + 0x37;
		unsigned short M = *(unsigned short *)&rsa_n[i];
		unsigned short A = ~M + P1;

		unsigned short C = (~A) ^ K;
		*(unsigned short *)&ptr[i] = C;
	}
	// SHA1-SIZE
	memset(key, KEY, 20);
#endif
	return 0;
}

PVOID WINAPI _RtlAllocateHeap(PVOID HeapHandle, ULONG Flags, SIZE_T Size)
{
	PVOID result = RtlAllocateHeap(HeapHandle, Flags, Size);
	if (Size == 0x102)
	{
		if (ptr_n == 0)
		{
#ifdef RSA_N
			//0019F918   00000000
			//0019F91C   00000202	<- key(20)
			//0019F920   010B1AF8  ASCII "cn9/mj88yixBo
			//0019F924   00000202
			//0019F928   00000000
			//0019F92C   0019FA00	<- breakpoint at hwbp (write dword)
			//0019F930   0019FF70
			//0019F934   00000206
			//0019F938   010B1AF8  ASCII "cn9/mj88yixBoPljZ+2oA
			//0019F93C   00000000
			//0019F940   00000202
			//0019F944   00000257
			//0019F948   00D71298
			//0019F94C   9FE9F06C
			//0019F950   CB797BA6
			//0019F954   5845BDFE
			//0019F958   2C27D21C
			//0019F95C   824C79CB
			//0019F960   6B7C2FD9  MSVCR120.printf
			//0019F964   6B81E060  MSVCR120.6B81E060
			//key 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01 01
			MessageBox(NULL, "Attach the process, breakpoint at key_ptr. ", "rsa-n.dll", MB_OK);
#endif
			ptr_n = (unsigned char *)result;
		}
		else
		{
			// replace rsa-n
			unsigned char *key = find_key(&HeapHandle, (DWORD)ptr_n);
			if (key != 0)
			{
#ifdef RSA_N
				char txt[32] = { 0 };
				sprintf(txt, "RSA-N at: %08X, key address at: %08X", ptr_n, key);
				MessageBox(NULL, txt, "rsa-n.dll", MB_OK);
#endif
				gen_rsa_n(ptr_n, key);
			}
		}
	}
	return result;
}

int ck_setup(void)
{
	HMODULE dll = GetModuleHandle("NTDLL");
	pfnRtlAllocateHeap target = (pfnRtlAllocateHeap)GetProcAddress(dll, "RtlAllocateHeap");

	RtlAllocateHeap = (pfnRtlAllocateHeap)jmphook(target, _RtlAllocateHeap);
	return 0;
}
