// gen.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

enum eChunks
{
	SERIAL_CHUNK_VERSION = 0x01,	//	1 byte of data - version
	SERIAL_CHUNK_USER_NAME = 0x02,	//	1 + N bytes - length + N bytes of customer's name (without enging \0).
	SERIAL_CHUNK_EMAIL = 0x03,	//	1 + N bytes - length + N bytes of customer's email (without ending \0).
	SERIAL_CHUNK_HWID = 0x04,	//	1 + N bytes - length + N bytes of hardware id (N % 4 == 0)
	SERIAL_CHUNK_EXP_DATE = 0x05,	//	4 bytes - (year << 16) + (month << 8) + (day)
	SERIAL_CHUNK_RUNNING_TIME_LIMIT = 0x06,	//	1 byte - number of minutes
	SERIAL_CHUNK_PRODUCT_CODE = 0x07,	//	8 bytes - used for decrypting some parts of exe-file
	SERIAL_CHUNK_USER_DATA = 0x08,	//	1 + N bytes - length + N bytes of user data
	SERIAL_CHUNK_MAX_BUILD = 0x09,	//	4 bytes - (year << 16) + (month << 8) + (day)

	SERIAL_CHUNK_END = 0xFF	//	4 bytes - checksum: the first four bytes of sha-1 hash from the data before that chunk
};

enum // constants. not a good idea to make them public. it is better to refactor this
{
	SERIAL_SIZE_PRODUCT_CODE = 8,
	SERIAL_SIZE_HWID = 8
};

unsigned char rsa_n[] = {	// for test
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

int arg_has_tag(int argc, char **argv, const char *tag)
{
	for (int i = 1; i < argc; i++)
	{
		if (*argv[i] == '-' || *argv[i] == '/')
		{
			if (strcmp(argv[i] + 1, tag) == 0)
			{
				return 1;
			}
		}
	}
	return 0;
}

const char* arg_get_value(int argc, char **argv, const char *tag)
{
	for (int i = 1; i < argc; i++)
	{
		if (*argv[i] == '-' || *argv[i] == '/')
		{
			if (strcmp(argv[i] + 1, tag) == 0)
			{
				if (i + 1 >= argc)
					return 0;
				return argv[i + 1];
			}
		}
	}
	return 0;
}

int test(void)
{
	unsigned char n[] = {
		//0x91, 0xA7, 0xB5, 0xF3, 0xC1, 0x2E, 0x44, 0x4D, 0x29, 0xED, 0x51, 0x3F, 0xD3, 0xB3, 0xE2, 0xA0,
		//0xAB, 0xAC, 0xF9, 0x43, 0xE1, 0x29, 0xE8, 0x1A, 0x4E, 0x27, 0x80, 0xC9, 0x3A, 0x1D, 0xFA, 0x28,
		//0xBF, 0x13, 0x90, 0x0F, 0x3B, 0x47, 0xCE, 0x0D, 0x0B, 0x9F, 0x9A, 0x8B, 0x76, 0x11, 0x7E, 0xD7,
		//0x3B, 0x63, 0x7D, 0xBF, 0x36, 0x8C, 0xB0, 0x90, 0xEC, 0x0B, 0x4C, 0xAA, 0x32, 0x7D, 0x8E, 0xE3,
		//0x04, 0xFC, 0x3D, 0x28, 0x48, 0xAA, 0xFF, 0x3B, 0x18, 0xDA, 0xC5, 0x64, 0xC5, 0xEE, 0xE1, 0x85,
		//0x74, 0x67, 0x9C, 0xA3, 0x91, 0x69, 0xC7, 0xD8, 0x2F, 0xCE, 0xB9, 0x69, 0x5E, 0xC0, 0x9B, 0x82,
		//0x83, 0x09, 0xCA, 0xC7, 0x4B, 0x77, 0x02, 0x2B, 0x05, 0x06, 0x64, 0xAB, 0x44, 0xB9, 0x73
		0x00, 0xD7, 0xAF, 0x83, 0xE8, 0x5E, 0xD3, 0x3D, 0x36, 0x9D, 0x0F, 0x4F, 0xA0, 0xC3, 0x44, 0xD0, 0x38, 0xDC, 0xE3, 0x33, 0xCA, 0x59, 0x71, 0x6A, 0x6F, 0x57, 0xDE, 0xB9, 0x4F, 0x6D, 0x5C, 0x58,
		0x2E, 0x63, 0x8E, 0x7F, 0x12, 0x37, 0x55, 0x7D, 0x28, 0xEF, 0xF8, 0xFB, 0x01, 0x61, 0xD4, 0xA7, 0xAC, 0x13, 0x63, 0xCF, 0x19, 0xFC, 0x29, 0xE0, 0xCD, 0x7B, 0x2E, 0xDA, 0x47, 0x0D, 0x24, 0x93,
		0x95, 0x8C, 0x27, 0x58, 0x61, 0xDA, 0x60, 0x4B, 0x3F, 0xAA, 0xA3, 0x14, 0xB6, 0x9E, 0x4F, 0xF5, 0xE7, 0x17, 0x86, 0xD3, 0xBA, 0x19, 0x5E, 0xA8, 0x0E, 0xBE, 0xDF, 0x19, 0x23, 0xB0, 0x35, 0xF2,
		0x12, 0x79, 0xEC, 0xB7, 0x62, 0x07, 0x99, 0x5B, 0x26, 0x76, 0x06, 0xDB, 0x3B, 0xC9, 0xD9, 0xDC, 0x19, 0x54, 0xC9, 0xA0, 0x37, 0xB7, 0x6B, 0x13, 0x32, 0x2C, 0x6C, 0xC7, 0xF6, 0x56, 0x0F, 0x73,
		0xFA, 0xA9, 0x02, 0xCD, 0x74, 0x8B, 0x05, 0x99, 0x2B, 0x91, 0x03, 0x53, 0x31, 0x0F, 0x02, 0xB8, 0x76, 0xAB, 0x3F, 0x95, 0xE6, 0x86, 0xA2, 0x9A, 0x89, 0x08, 0x09, 0x96, 0x8B, 0x37, 0xD8, 0x2A,
		0x99, 0x25, 0xE3, 0x15, 0xEB, 0xC8, 0x48, 0xE5, 0xE6, 0x1F, 0x71, 0xC1, 0x69, 0x61, 0xE3, 0x3C, 0xB0, 0x4A, 0x39, 0x15, 0xB9, 0x43, 0x1D, 0xCC, 0xF6, 0x3A, 0xBC, 0x95, 0x44, 0x14, 0x30, 0x81,
		0x77, 0x6C, 0xD2, 0x2F, 0x0E, 0x57, 0x72, 0x54, 0x27, 0x58, 0x14, 0xA8, 0xC2, 0x4E, 0x9C, 0x2B, 0x70, 0x0A, 0xE4, 0xE9, 0x81, 0x5D, 0xAF, 0x15, 0x3C, 0xC6, 0x19, 0xAD, 0xBF, 0x53, 0x40, 0xE3,
		0x1E, 0x60, 0x08, 0xAD, 0x29, 0x9A, 0xBF, 0x70, 0x86, 0x90, 0x49, 0x74, 0x6A, 0xD0, 0xBC, 0xCF, 0xA5, 0xBE, 0xB4, 0xEB, 0xD4, 0x48, 0x00, 0x88, 0x30, 0x8E, 0x44, 0x8F, 0x47, 0x76, 0x42, 0xB5,
		0xE3, 0x8E
	};

	//int ptr = 0x00B72C80;
	int ptr = 0x00F02C80;
	for (int i = 0; i < sizeof(n); i += 2)
	{
		int P1 = (ptr + i) & 0xFFFF;
		int P2 = ((ptr + i) >> 4) & 0xFFFF;
		int A = ~(~(*(unsigned short *)&rsa_n[i]) + P1);
		int K = A ^ (*(unsigned short *)&n[i]);
		int X = K - P2 - 0x37;
		int vk = P2 + X + 0x37;

		printf("%04X->%04X, ", (unsigned short)K, (unsigned short)X);
		if (i % 8 == 0)
			printf("\n");
	}
	return 0;
}

unsigned char* check(unsigned char *ptr, int* len)
{
	if (ptr[0] != 0 || ptr[1] != 2)
		return 0;
	int i = 2;
	while (i < *len)
	{
		if (ptr[i] == 0)
			break;
		i++;
	}
	i += 1;
	if (ptr[i] != 1 || ptr[i + 1] != 1)
		return 0;
	*len -= i;
	return &ptr[i];
}

int parse(unsigned char *ptr, int len)
{
	int i = 2;
	if (ptr[i] == SERIAL_CHUNK_USER_NAME)
	{
		string v((char *)&ptr[i + 2], ptr[i + 1]);
		printf("user:%s\n", v.c_str());
		i += ptr[i + 1] + 2;
	}
	if (ptr[i] == SERIAL_CHUNK_EMAIL)
	{
		string v((char *)&ptr[i + 2], ptr[i + 1]);
		printf("email:%s\n", v.c_str());
		i += ptr[i + 1] + 2;
	}
	if (ptr[i] == SERIAL_CHUNK_HWID)
	{
		char v[256] = { 0 };
		base64_encode(&ptr[i + 2], ptr[i + 1], v);
		printf("hwid:%s\n", v);
		i += ptr[i + 1] + 2;
	}
	if (ptr[i] == SERIAL_CHUNK_EXP_DATE)
	{
		i += 4 + 1;
	}
	if (ptr[i] == SERIAL_CHUNK_RUNNING_TIME_LIMIT)
	{
		i += 1 + 1;
	}
	if (ptr[i] == SERIAL_CHUNK_PRODUCT_CODE)
	{
		char v[256] = { 0 };
		base64_encode(&ptr[i + 1], SERIAL_SIZE_PRODUCT_CODE, v);
		printf("product code:%s\n", v);
		i += SERIAL_SIZE_PRODUCT_CODE + 1;
	}
	if (ptr[i] == SERIAL_CHUNK_USER_DATA)
	{
		printf("data:");
		for (unsigned char j = 0; j < ptr[i + 1]; j++)
		{
			if (j % 16 == 0)
				printf("\n");
			printf("%02x ", ptr[i + 2 + j]);
		}
		printf("\n");
		i += ptr[i + 1] + 2;
	}

	return 0;
}

int read_rsa_n(const char *filename, unsigned char *ptr, int len)
{
	FILE *pf = fopen(filename, "rb");
	if (pf == 0)
		return 0;
	int r = fread(ptr, 1, len, pf);
	fclose(pf);
	return r;
}

int read_serial(const char *filename, char *ptr, int len)
{
	FILE *pf = fopen(filename, "r");
	if (pf == 0)
		return 0;
	int r = fread(ptr, 1, len, pf);
	fclose(pf);
	return r;
}

int gen(const char *sfilename, const char *nfilename)
{
	char *p = new char[2048+2];
	memset(p, 0, 2048+2);
	int r = read_serial(sfilename, p, 2048);
	if (r == 0)
	{
		printf("read file %s failed.\n", sfilename);
		delete[] p;
		return 0;
	}

	size_t nSrcLen = strlen(p);
	std::vector<byte> res;
	base64_decode(p, nSrcLen, res);
	Bignum c = bignum_from_bytes(&res[0], (int)res.size());
	delete[] p;

	unsigned char e_ptr[] = { 0x02, 0x00, 0x01, 0x00, 0x01, 0x00 };
	Bignum e = (Bignum)e_ptr;

	unsigned char n_ptr[0x102] = { 0x00 };
	r = read_rsa_n(nfilename, n_ptr, 0x102);
	if (r != 0x102)
	{
		printf("read file %s failed.\n", nfilename);
		freebn(c);
		return 0;
	}
	if (n_ptr[0] != 0x80 || n_ptr[1] != 00)
	{
		printf("invalid rsa-n.\n", nfilename);
		freebn(c);
		return 0;
	}
	Bignum n = (Bignum)n_ptr;

	Bignum m = modpow(c, e, n);
	int nBytes;
	byte *pRes = bignum_to_bytes(m, &nBytes);

	freebn(c);
	freebn(m);

	unsigned char *serial = check(pRes, &nBytes);
	if (serial == 0)
	{
		printf("Decrypt error:RSA-N or version incorrect.\n");
		delete[] pRes;
		return 0;
	}

	parse(serial, nBytes);
	delete[] pRes;
	return 0;
}

int _tmain(int argc, _TCHAR* argv[])
{
	// gen -t for test
	if (arg_has_tag(argc, argv, "t"))
	{
		test();
		return 0;
	}

	// gen -n print user info
	gen("serial.txt", "rsa-n.bn");
	return 0;
}
