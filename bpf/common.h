#ifndef UTILS_H
#define UTILS_H

#define UNUSED __attribute__((unused))
#define RWBS_LEN 8

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#endif

#endif
