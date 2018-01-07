#include "common.h"

#include <windows.h>

#define FILE_NAME "out.dat"
#define BUFLEN 0x100000

extern Z0_OPCODE_TABLE opcode_base[];

Z0_STATUS __stdcall print_disasm(PZ0_DISASM_CONTEXT context);

Z0_STATUS __stdcall empty_sub(PZ0_DISASM_CONTEXT context)
{
	return Z0_STATUS_OK;
}

unsigned long long total =0;

void entry(void)
{
	Z0_DISASM_CONTEXT context;
	Z0_STATUS status;
	unsigned char* buffer =NULL;
	HANDLE file =INVALID_HANDLE_VALUE;
	DWORD bytes;
	DWORD offset;

	LARGE_INTEGER frequency;
	LARGE_INTEGER time_start;
	LARGE_INTEGER time_stop;
	unsigned long long time_elapsed;

	do
	{
		file =CreateFile(FILE_NAME, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		if(INVALID_HANDLE_VALUE == file)
		{
			printf("CreateFile error %u\r\n", GetLastError());
			break;
		}

		buffer =(unsigned char*) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, BUFLEN);
		if(!buffer)
		{
			printf("malloc %u bytes failed\r\n", BUFLEN);
			break;
		}

		context.mode = Z0_DISASM_MODE_32;
		context.finish = print_disasm;
	//	context.finish = empty_sub;

		QueryPerformanceCounter(&time_start);

		do
		{
			if(!ReadFile(file, buffer, BUFLEN, &bytes, NULL))
			{
				printf("ReadFile error %u\r\n", GetLastError());
				break;
			}

			if(!bytes) break; // normal exit

			offset =0;
			context.addr =buffer;
			context.length =0;

			do
			{
				status =disasm(&context);
				if(Z0_STATUS_OK != status)
				{
					printf("disasm error %s\r\n", translate_status(status));
				}

				total++;

				offset += context.length;

				if(offset >= bytes) break;

				if((bytes - offset) < Z0_MAX_OPCODE_LENGTH)
				{
					SetFilePointer(file, (offset - bytes), NULL, FILE_CURRENT);
					break;
				}

			} while(1);

			_cprintf("%I64u instructions disassembled\r", total);

		} while(1);

		QueryPerformanceCounter(&time_stop);

	} while(0);

	if(INVALID_HANDLE_VALUE != file) CloseHandle(file);
	if(buffer) HeapFree(GetProcessHeap(), 0, buffer);

	time_elapsed =time_stop.QuadPart -time_start.QuadPart;
	QueryPerformanceFrequency(&frequency);
	_cprintf("%I64u instructions disassembled; %I64u instructions/sec\r\n", total, (total *frequency.QuadPart)/time_elapsed);

	ExitProcess(0);
}
