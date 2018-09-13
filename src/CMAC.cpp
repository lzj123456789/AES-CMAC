#include "CMAC.h"

/* For CMAC Calculation */
uint8_t const_Rb[16] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87
};
uint8_t const_Zero[16] = {
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

void CMAC::xor_128(uint8_t *a,uint8_t *b, uint8_t *out){
    int i;
    for(i=0;i<16;i++){
    	out[i] = a[i]^b[i];
    }
}

/*
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+Algorithm Generate_Subkey                                          +
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+                                                                   +
+Input: K (128-bit key)                                             +
+Output: K1 (128-bit first subkey)                                  +
+        K2 (128-bit second subkey)                                 +
+-------------------------------------------------------------------+
+                                                                   +
+Constants: const_Zero is 0x00000000000000000000000000000000        +
+           const_Rb   is 0x00000000000000000000000000000087        +
+Variables: L          for output of AES-128 applied to 0^128       +
+                                                                   +
+Step 1.   L := AES-128(K, const_Zero);                             +
+Step 2.   if MSB(L) is equal to 0                                  +
+          then  K1 := L << 1;                                      +
+          else  K1 := (L << 1) XOR const_Rb;                       +
+Step 3.   if MSB(K1) is equal to 0                                 +
+          then  K2 := K1 << 1;                                     +
+          else  K2 := (K1 << 1) XOR const_Rb;                      +
+Step 4.   return K1, K2;                                           +
+                                                                   +
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
*/

void CMAC::leftshift_onebit(uint8_t *input,uint8_t *output)
{
	int i;
	uint8_t overflow=0;
	for(i=15;i>=0;i--){
		output[i] = input[i]<<1;
		output[i] |= overflow;
		overflow = (input[i] & 0x80) ? 1:0;
	}
	return;
}

void CMAC::generate_subkey(uint8_t *key,uint8_t *K1,uint8_t *K2,unsigned long int keyLength)
{
	uint8_t L[16];
	uint8_t Z[16];
	uint8_t tmp[16];
	int i;
	for(i=0;i<16;i++){
		Z[i] = 0;
	}

	Cipher *Cip = new Cipher();
	Cip->CipherProcess(key,Z,L,keyLength);
	if((L[0]&0x80)==0){
		leftshift_onebit(L,K1);
	}else{
		leftshift_onebit(L,tmp);
		xor_128(tmp,const_Rb,K1);
	}
	if((K1[0]&0x80)==0){
		leftshift_onebit(K1,K2);
	}else{
		leftshift_onebit(K1,tmp);
		xor_128(tmp,const_Rb,K2);
	}
	return;

}


void CMAC::padding(uint8_t *lastb,uint8_t *pad,int length)
{
	int j;
	for(j=0;j<16;j++){
		if(j<length){
			pad[j] = lastb[j];
		}else if(j==length){
			pad[j] = 0x80;
		}else{
			pad[j] = 0x00;
		}
	}
}
/*

+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+                   Algorithm AES-CMAC                              +
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+                                                                   +
+Input    : K        ( 128-bit key )                                +
+         : M        ( message to be authenticated )                +
+         : len      ( length of the message in octets )            +
+Output   : T        ( message authentication code )                +
+                                                                   +
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
+Constants: const_Zero is 0x00000000000000000000000000000000        +
+           const_Bsize is 16                                       +
+                                                                   +
+Variables: K1, K2 for 128-bit subkeys                              +
+           M_i is the i-th block (i=1..ceil(len/const_Bsize))      +
+           M_last is the last block xor-ed with K1 or K2           +
+           n      for number of blocks to be processed             +
+           r      for number of octets of last block               +
+           flag   for denoting if last block is complete or not    +
+                                                                   +
+Step 1. (K1,K2) := Generate_Subkey(K);                             +
+Step 2. n := ceil(len/const_Bsize);                                +
+Step 3. if n = 0                                                   +
+        then                                                       +
+            n := 1;                                                +
+            flag := false;                                         +
+        else                                                       +
+            if len mod const_Bsize is 0                            +
+            then flag := true;                                     +
+            else flag := false;                                    +
+                                                                   +
+Step 4. if flag is true                                            +
+        then M_last := M_n XOR K1;                                 +
+        else M_last := padding(M_n) XOR K2;                        +
+Step 5. X := const_Zero;                                           +
+Step 6. for i := 1 to n-1 do                                       +
+             begin                                                 +
+                Y := X XOR M_i;                                    +
+                X := AES-128(K,Y);                                 +
+             end                                                   +
+        Y := M_last XOR X;                                         +
+        T := AES-128(K,Y);                                         +
+Step 7. return T;                                                  +
+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

*/
void CMAC::AES_CMAC(uint8_t  *key,uint8_t *input,int length,uint8_t *mac,unsigned long int keyLength)
{
	uint8_t X[16],Y[16],M_last[16],padded[16];
	uint8_t K1[16],K2[16];
	int n,i,flag;

	generate_subkey(key,K1,K2,keyLength);
	n=(length+15)/16;
	if(n==0){
		n=1;
		flag=0;
	}else{
		if((length%16)==0){
			flag=1;
		}else{
			flag=0;
		}
	}

	if(flag){
		xor_128(&input[16*(n-1)],K1,M_last);
	}else{
		padding(&input[16*(n-1)],padded,length%16);
		xor_128(padded,K2,M_last);
	}
	for(i=0;i<16;i++){
		X[i] = 0;
	}
	for(i=0;i<n-1;i++){
		xor_128(X,&input[16*i],Y);
		Cipher *Cip = new Cipher();
	    Cip->CipherProcess(key,Y,X,keyLength);
	}
	xor_128(X,M_last,Y);
	Cipher *Cip = new Cipher();
	Cip->CipherProcess(key,Y,X,keyLength);
	for(i=0;i<16;i++){
		mac[i] = X[i];
	}
}