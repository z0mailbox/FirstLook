#ifndef _FL_COMMON
#define _FL_COMMON

#ifndef _WIN64
typedef unsigned int size_t;
#endif

typedef unsigned long Z0_STATUS;
typedef void* Z0_HANDLE;

#define Z0_STATUS_OK			0

#define Z0_STATUS_INVALID_PARAMETER_1	1
#define Z0_STATUS_INVALID_PARAMETER_2	2
#define Z0_STATUS_INVALID_PARAMETER_3	3
#define Z0_STATUS_INVALID_PARAMETER_4	4

#define Z0_STATUS_UNKNOWN_MODE		0x10
#define Z0_STATUS_UNKNOWN_CMD		0x11
#define Z0_STATUS_UNKNOWN_TYPE		0x12

#define Z0_STATUS_OUT_OF_ARRAY		0x20
#define Z0_STATUS_NOT_IMPLEMENTED	0x21
#define Z0_STATUS_INVALID_POSITION	0x22
#define Z0_STATUS_INVALID_SIZE		0x23
#define Z0_STATUS_INVALID_IO_RESPONSE	0x24
#define Z0_STATUS_INVALID_IO_HANDLE	0x25
#define Z0_STATUS_INVALID_TYPE		0x26

#define Z0_STATUS_NOT_ENOUGH_MEMORY	0x30
#define Z0_STATUS_MEMPROTECT_FAILED	0x31
#define Z0_STATUS_NOT_FOUND		0x32
#define Z0_STATUS_ALREADY_EXISTS	0x33
#define Z0_STATUS_NULL_PTR		0x34
#define Z0_STATUS_EMPTY_STRING		0x35
#define Z0_STATUS_LOCK_FAILED		0x36

#define Z0_STATUS_EXCEPTION		0x40

#define Z0_STATUS_UD			0x80000001

#define Z0_MAX_NAME_LENGTH 0x80
#define Z0_MAX_LOG_STRING 0x200

typedef void (__cdecl *type_printf)(char* format, ...);

int z0_status_failed(Z0_STATUS status);

void* z0_malloc(unsigned long size);
void z0_free(void* ptr);

void* z0_memcpy(void* dst, void* src, size_t count);
void* z0_memset(void* dst, int c, size_t count);

#endif
