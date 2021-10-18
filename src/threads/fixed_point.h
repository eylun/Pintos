#ifndef FIXED_POINT_H
#define FIXED_POINT_H

/* Fixed Point Real Arithmetic
   Fixed Point numbers are split in by their bits in the
   17.14 representation (p.q, where p = 17, q = 14)
   Let f be 2^q, where f will be used to adjust between
   fixed point numbers and integers */

#define P 17
#define Q 14
/* F = 2 ^ Q */
#define F 0 << Q

/* Fixed Point Number with Integer Operations */

/* Fixed Point Number with Fixed Point Number Operations */
#endif /* threads/fixed_point.h */