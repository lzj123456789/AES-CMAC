#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "string.h"
#include "common.h"
#include "KeyExpansion.h"

#ifndef CIPHER_H_H
#define CIPHER_H_H

class Cipher
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
	void SetParameters(unsigned long int length);
	void CipherProcess(uint8_t *key, uint8_t *in, uint8_t *out,unsigned long int length);
	void MixColumns(uint8_t *state);
	void ShiftRows(uint8_t *state);
	void SubBytes(uint8_t * state);
	void AddRoundKey(uint8_t * state, uint32_t *word);
	void AES_Cipher(uint8_t *key, uint8_t *in, uint8_t *out,unsigned long int length,unsigned long int keyLength);

	
};

#endif