#ifndef NC_LWIP_ARCH_CC_H
#define NC_LWIP_ARCH_CC_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define LWIP_ERR_T int

/* Byte order from the compiler (iOS targets are little-endian arm64). */
#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif
#define LWIP_BYTE_ORDER BYTE_ORDER

typedef uint8_t u8_t;
typedef int8_t s8_t;
typedef uint16_t u16_t;
typedef int16_t s16_t;
typedef uint32_t u32_t;
typedef int32_t s32_t;
typedef uintptr_t mem_ptr_t;

#define X8_F "02x"
#define U16_F "hu"
#define S16_F "hd"
#define X16_F "hx"
#define U32_F "u"
#define S32_F "d"
#define X32_F "x"
#define SZT_F "zu"

#define LWIP_PLATFORM_DIAG(x)
#define LWIP_PLATFORM_ASSERT(x) do { nc_lwip_assert_failed(); } while (0)
void nc_lwip_assert_failed(void);

#define LWIP_RAND() ((u32_t)arc4random())
uint32_t arc4random(void);

/* Pack structs the lwIP way on this compiler. */
#define PACK_STRUCT_FIELD(x) x
#define PACK_STRUCT_STRUCT __attribute__((packed))
#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_END

#define LWIP_PROVIDE_ERRNO 1

#endif
