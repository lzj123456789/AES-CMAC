#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "string.h"
#include "common.h"
#include "InvCipher.h"
#include "Cipher.h"
#include "CMAC.h"

using namespace std;


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

int main(int argc, char const *argv[])
{
	 uint8_t key[] = {
	 	0x00, 0x00, 0x00, 0x00,
	 	0x00, 0x00, 0x00, 0x00,
	 	0x00, 0x00, 0x00, 0x00,
	 	0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x03, 0x01,
		0x05, 0x00, 0x01, 0x00,
		0x04, 0x08, 0x00, 0x06}; 
	
	/* uint8_t key[] = {
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x03, 0x01,
		0x05, 0x00, 0x01, 0x00,
		0x04, 0x08, 0x00, 0x06}; */

	
	uint8_t in[] = "Information Security is a multidisciplinary area of study and professional activity which is concerned with the development and implementation of security mechanisms of all available types (technical, organizational, human-oriented and legal) in order to keep information in all its locations (within and outside the organization's perimeter) and, consequently, information systems, where information is created, processed, stored, transmitted and destroyed, free from threats.";

	uint8_t *cmacOut = (uint8_t *)malloc(16);
	printf("CMAC CODE\n");
	CMAC *cmacT = new CMAC();
	cmacT->AES_CMAC(key,in,(int)sizeof(in),cmacOut,sizeof(key));
	for(int i=0;i<16;i++){
		printf("%x ",cmacOut[i] );
	}
	printf("\n");


	printf("KEY:\n");
	for (unsigned long int i = 0; i < sizeof(key); ++i)
	{
		printf("%x ", key[i]);
	}
	printf("\n");

	printf("PLAINTXT:\n");

	for( unsigned long int i=0;i<sizeof(in);i++){
		printf("%c", in[i]);
	}
	printf("\n");


	Cipher *Cip = new Cipher();


	uint8_t *out=(uint8_t *)malloc(sizeof(in));

	printf("AES CIPHER:\n");
	Cip->AES_Cipher(key,in,out,sizeof(in),sizeof(key));
	for(unsigned long int i=0;i<sizeof(in);i++){
		printf("%x ", out[i]);
	}
	printf("\n");

	printf("AES INVICPHER:\n");
	InvCipher *InCip = new InvCipher();
	InCip->AES_InvCipher(key,out,in,sizeof(out),sizeof(key));

	for(unsigned long int i=0;i<sizeof(in);i++){
		printf("%c", in[i]);
	}
	printf("\n");
	return 0;
}