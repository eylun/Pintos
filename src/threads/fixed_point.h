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
#define F 1 << Q

/* Fixed Point Number Conversion Functions */
#define FROM_INT_TO_FP(n) (n) * (F)
#define FROM_FP_TO_INT(fp) (fp) / (F)
#define FROM_FP_TO_ROUNDED_INT(fp) ((fp) >= 0                    \
                                        ? ((fp) + (F) / 2) / (F) \
                                        : ((fp) - (F) / 2) / (F))

/* Fixed Point Number with Integer Operations */
/* fp is a Fixed Point Number, n is an Integer */
#define FP_INT_ADD(fp, n) (fp) + (n) * (F)
#define FP_INT_DIFF(fp, n) (fp) - (n) * (F)
#define FP_INT_MULT(fp, n) (fp) * (n)
#define FP_INT_QUO(fp, n) (fp) / (n)

/* Fixed Point Number with Fixed Point Number Operations */
/* fp, fp_ are Fixed Point Numbers */
#define FP_FP_ADD(fp, fp_) (fp) + (fp_)
#define FP_FP_DIFF(fp, fp_) (fp) - (fp_)
#define FP_FP_MULT(fp, fp_) (((int64_t)(fp)) * (fp_) / (F))
#define FP_FP_QUO(fp, fp_) (((int64_t)(fp)) * (F) / (fp_))

#endif /* threads/fixed_point.h */