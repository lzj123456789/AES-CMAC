#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "string.h"
#include "common.h"
#include "InvCipher.h"
#include "Cipher.h"


class CMAC
{
public:
	CMAC(){};
	~CMAC(){};
	void AES_CMAC(uint8_t  *key,uint8_t *input,int length,uint8_t *mac,unsigned long int keyLength);
	void padding(uint8_t *lastb,uint8_t *pad,int length);
	void generate_subkey(uint8_t *key,uint8_t *K1,uint8_t *K2,unsigned long int keyLength);
	void leftshift_onebit(uint8_t *input,uint8_t *output);

	void xor_128(uint8_t *a,uint8_t *b, uint8_t *out);
};