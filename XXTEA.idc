#include <idc.idc>

#define MX ( ((shr(z,5)^(y<<2)) + (shr(y,3)^(z<<4))) ^ ((sum^y) + (Dword(k+4*(p&3^e))^z)) )

#define DELTA 0x9e3779b9

#define shr(x,n) ((x>>n)&(~(0xFFFFFFFF<<32-n)))

#define V(n) (v+4*(n))

static btea( n, k , v ) {
	auto z, y,sum,e, p, q;

	z=Dword(V(n-1));
	y=Dword(V(0));

	if (n > 1) {          /* Coding Part */
		q = 6+52/n;
		while (q-- > 0) {
			sum = sum + DELTA;
			e = (shr(sum,2)) & 3;
        		for (p=0; p<n-1; p++){
					y = Dword(V(p+1));
					z = Dword(V(p)) + MX;
					PatchDword(V(p),z);
				}
			y = Dword(V(0));
			z = Dword(V(n-1)) + MX;
			PatchDword(V(n-1), z);
		}
		Message("Encryption finished!\n");
      	return 0 ;
	} else if ( n <-1 ) {		/* Decoding Part */
		n = -n ;
		q = 6+52/n;
		sum = q*DELTA ;
		while (sum != 0) {
			e = (shr(sum,2)) & 3;
			for (p = n-1 ; p > 0 ; p-- ){
				z = Dword(V(p-1));
				y = Dword(V(p))-MX;
				PatchDword(V(p),y);
			}
			z = Dword(V(n-1));
			y = Dword(V(0))-MX;
			PatchDword(V(0),y);
			sum = sum - DELTA;
		}
		Message("Decryption finished!\n");
			
		return 0 ;
	}
return 1 ;} /* Signal n=0,1,-1 */

static enc(){
	btea(0x8C0,0x408EC4,0x406BC1);
}

static dec(){
	btea(-0x8C0,0x408EC4,0x406BC1);
}

