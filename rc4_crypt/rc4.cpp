#include "stdafx.h"

#include "rc4.hpp"

struct RC4Schedule
{
	unsigned char x;
	unsigned char y;
	unsigned char tab[256];
};

// sub_00190F54
void rc4_init(RC4Schedule *r, const unsigned char *key, unsigned int keylen)
{
	unsigned int keyindex = 0;
	unsigned int stateindex = 0;

	r->x = 0;
	r->y = 0;

	for (int i = 0; i < 256; i++)
		r->tab[i] = i;

	for (int i = 0; i < 256; i++)
	{
		unsigned char t, u;

		t = r->tab[i];
		stateindex = (key[keyindex] + stateindex + t) & 0xFF;

		u = r->tab[stateindex];
		r->tab[stateindex] = t;
		r->tab[i] = u;

		if (++keyindex >= keylen)
			keyindex = 0;
	}
}

// sub_001910D0
unsigned char rc4_byte(RC4Schedule *r)
{
	unsigned char x, y, sx, sy;

	x = (r->x + 1) & 0xFF;
	sx = r->tab[x];
	y = (sx + r->y) & 0xFF;
	sy = r->tab[y];

	r->x = x;
	r->y = y;
	r->tab[y] = sx;
	r->tab[x] = sy;

	return r->tab[(sx + sy) & 0xFF];
}

// sub_001911D0
void rc4_crypt(RC4Schedule *r, unsigned char *dest, const unsigned char *src, unsigned int len)
{
	for (unsigned int i = 0; i < len; i++)
		dest[i] = src[i] ^ rc4_byte(r);
}

// sub_00191254
void rc4_crypt_ALL(unsigned char *key, unsigned int keylen, const unsigned char *src, unsigned char* dest, unsigned int bufsize)
{
	RC4Schedule r;
	rc4_init(&r, key, keylen);
	rc4_crypt(&r, dest, src, bufsize);
}