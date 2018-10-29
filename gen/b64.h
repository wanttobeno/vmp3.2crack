#pragma once

int base64_encode(const unsigned char* bytes_to_encode, size_t in_len, char *dst);
void base64_decode(const char *src, size_t len, std::vector<byte> &ret);

size_t base64_encode_len(size_t len);

#define base64_decode_len(A) (A)
