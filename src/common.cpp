#include "common.h"


/*
 * Multiplication in GF(2^8)
 * http://en.wikipedia.org/wiki/Finite_field_arithmetic
 * Irreducible polynomial m(x) = x8 + x4 + x3 + x + 1
 */
uint8_t gmult(uint8_t a, uint8_t b) {

	uint8_t p = 0, i = 0, hbs = 0;

	for (i = 0; i < 8; i++) {
		if (b & 1) {
			p ^= a;
		}

		hbs = a & 0x80;
		a <<= 1;
		if (hbs) a ^= 0x1b; // 0000 0001 0001 1011	
		b >>= 1;
	}

	return (uint8_t)p;
}

/*
× The round constant word array.
*/
uint32_t Rcon( uint32_t word)
{
	uint32_t R = 0x02000000;
	uint8_t R0 = 0x02;
	if(word==1){
		R = 0x01000000;
	}else if(word >1){
		R = 0x02000000;
		word --;
		R0 = (uint8_t) ((R & 0xff000000) >> 24);
		while(word-1>0){			
			R0 = gmult(R0,0x02);
			word -- ;
		}
		R = (R & 0x00ffffff) | ((uint32_t) (R0 << 24));
		
		
	}
	return R;
}
