/*
 * $Id: defs.h,v 1.1.1.1 2000/08/14 18:46:10 labovit Exp $
 */

#ifndef _DEFS_H
#define _DEFS_H
/* need HAVE_U_TYPES */
#include "config.h"
#ifdef HAVE_SYS_BITYPES_H
#include <sys/bitypes.h>
#endif /* HAVE_SYS_BITYPES_H */
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif /* HAVE_INTTYPES_H */

#define MAXLINE		1024

#define BIT_SET(f, b)   ((f) |= b)
#define BIT_RESET(f, b) ((f) &= ~(b))
#define BIT_FLIP(f, b)  ((f) ^= (b))
#define BIT_TEST(f, b)  ((f) & (b))
#define BIT_MATCH(f, b) (((f) & (b)) == (b))
#define BIT_COMPARE(f, b1, b2)  (((f) & (b1)) == b2)
#define BIT_MASK_MATCH(f, g, b) (!(((f) ^ (g)) & (b)))

#define BITM_TEST(bits, value) BIT_TEST((bits), (1<<(value)))
#define BITM_SET(bits, value) BIT_SET((bits), (1<<(value)))
#define BITM_RESET(bits, value) BIT_RESET((bits), (1<<(value)))

typedef unsigned long bitx_mask_t;
#define BITX_NBITS (sizeof (bitx_mask_t) * 8)

#define BITX_SET(p, n) ((p)->bits[(n)/BITX_NBITS] |= \
                            ((unsigned)1 << ((n) % BITX_NBITS)))
#define BITX_RESET(p, n) ((p)->bits[(n)/BITX_NBITS] &= \
                            ~((unsigned)1 << ((n) % BITX_NBITS)))
#define BITX_TEST(p, n) ((p)->bits[(n)/BITX_NBITS] & \
                            ((unsigned)1 << ((n) % BITX_NBITS)))

#ifndef byte
#define byte u_char
#endif

/*
 * Macros to get various length values from the stream.  cp must be a
 * (byte *)
 */           

#define	MRT_GET_BYTE(val, cp)	((val) = *(u_char *)(cp)++)

#define	MRT_GET_SHORT(val, cp) \
	do { \
		register u_int Xv; \
		Xv = (*(byte *)(cp)++) << 8; \
		Xv |= *(byte *)(cp)++; \
		(val) = Xv; \
	} while (0)

#define	MRT_GET_LONG(val, cp) \
	do { \
		register u_long Xv; \
		Xv = (*(byte *)(cp)++) << 24; \
		Xv |= (*(byte *)(cp)++) << 16; \
		Xv |= (*(byte *)(cp)++) << 8; \
		Xv |= *(byte *)(cp)++; \
		(val) = Xv; \
	} while (0)

#define	MRT_GET_NETSHORT(val, cp) \
	do { \
		register byte *Xvp; \
		u_short Xv; \
		Xvp = (byte *) &Xv; \
		*Xvp++ = *(cp)++; \
		*Xvp++ = *(cp)++; \
		(val) = Xv; \
	} while (0)

#define	MRT_GET_NETLONG(val, cp) \
	do { \
		register byte *Xvp; \
		u_long Xv; \
		Xvp = (byte *) &Xv; \
		*Xvp++ = *(cp)++; \
		*Xvp++ = *(cp)++; \
		*Xvp++ = *(cp)++; \
		*Xvp++ = *(cp)++; \
		(val) = Xv; \
	} while (0)


/*
 * The following macro extracts network addresses from the stream.  It
 * is used to decode the end of update messages, and understands that
 * network numbers are stored internally in network byte order.
 */
#define	MRT_GET_ADDR(addr, cp) \
	do { \
		register byte *Xap; \
		Xap = (byte *)(addr); \
		*Xap++ = *(cp)++; \
		*Xap++ = *(cp)++; \
		*Xap++ = *(cp)++; \
		*Xap++ = *(cp)++; \
	} while (0)

#define	MRT_GET_ADDR6(addr, cp) \
	do { \
		register byte *Xap; \
		register int i; \
		Xap = (byte *)(addr); \
		for (i = 0; i < 16; i++) \
			*Xap++ = *(cp)++; \
	} while (0)

/*
 * That is it for incoming messages.  The next set of macroes are used
 * for forming outgoing messages.
 */
#define	MRT_PUT_BYTE(val, cp) 	(*(cp)++ = (byte)(val))

#define	MRT_PUT_SHORT(val, cp) \
	do { \
		register u_short Xv; \
		Xv = (u_short)(val); \
		*(cp)++ = (byte)(Xv >> 8); \
		*(cp)++ = (byte)Xv; \
	} while (0)

#define	MRT_PUT_LONG(val, cp) \
	do { \
		register u_long Xv; \
		Xv = (u_long)(val); \
		*(cp)++ = (byte)(Xv >> 24); \
		*(cp)++ = (byte)(Xv >> 16); \
		*(cp)++ = (byte)(Xv >>  8); \
		*(cp)++ = (byte)Xv; \
	} while (0)

#define	MRT_PUT_NETSHORT(val, cp) \
	do { \
		register byte *Xvp; \
		u_short Xv = (u_short)(val); \
		Xvp = (u_char *)&Xv; \
		*(cp)++ = *Xvp++; \
		*(cp)++ = *Xvp++; \
	} while (0)

#define	MRT_PUT_NETLONG(val, cp) \
	do { \
		register byte *Xvp; \
		u_long Xv = (u_long)(val); \
		Xvp = (u_char *)&Xv; \
		*(cp)++ = *Xvp++; \
		*(cp)++ = *Xvp++; \
		*(cp)++ = *Xvp++; \
		*(cp)++ = *Xvp++; \
	} while (0)

#define	MRT_GET_DATA(data, len, cp) (memcpy (data, cp, len), (cp) += (len))
#define	MRT_PUT_DATA(data, len, cp) (memcpy (cp, data, len), (cp) += (len))
#define	MRT_PUT_ZERO(len, cp) (memset (cp, 0, len), (cp) += (len))

/*
 * The following puts a network address into the buffer in the
 * form a BGP update message would like.  We know the address
 * is in network byte order already.
 */
#define	MRT_PUT_ADDR(addr, cp) \
	do { \
		register byte *Xap; \
		Xap = (byte *)(addr); \
		*(cp)++ = *Xap++; \
		*(cp)++ = *Xap++; \
		*(cp)++ = *Xap++; \
		*(cp)++ = *Xap++; \
	} while (0)

#define	MRT_PUT_ADDR6(addr, cp) \
	do { \
		register byte *Xap; \
		register int i; \
		Xap = (byte *)(addr); \
		for (i = 0; i < 16; i++) \
			*(cp)++ = *Xap++; \
	} while (0)


#ifndef HAVE_U_TYPES
typedef unsigned char	u_char;
typedef unsigned int	u_int;
typedef unsigned short	u_short;
typedef unsigned long	u_long;
#endif /* HAVE_U_TYPES */

#endif /* _DEFS_H */

