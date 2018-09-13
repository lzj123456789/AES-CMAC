#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "string.h"
#include "common.h"

#ifndef KEYEXPANSION_H_H
#define KEYEXPANSION_H_H

class KeyExpansion
{
public:
	/*
	 * The cipher Key.	
	 */
	int K;

	/*
	 * Number of columns (32-bit words) comprising the State. For this 
	 * standard, Nb = 4.
	 */
	int Nb = 4;

	/*
	 * Number of 32-bit words comprising the Cipher Key. For this 
	 * standard, Nk = 4, 6, or 8.
	 */
	int Nk;

	/*
	 * Number of rounds, which is a function of  Nk  and  Nb (which is 
	 * fixed). For this standard, Nr = 10, 12, or 14.
	 */
	int Nr;
	void SetParameters(int _K,int _Nb, int _Nk, int _Nr);
	void KeyExpansionProcess(uint8_t *key, uint32_t *w);
	uint32_t RotWord(uint32_t word);
	uint32_t SubWord(uint32_t word);
	
};
#endif