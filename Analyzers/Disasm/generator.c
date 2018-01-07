#include "common.h"

#include <windows.h>

#define FILE_NAME "out.dat"
#define BUFFER_SIZE 0x100000

HANDLE file =INVALID_HANDLE_VALUE;
unsigned char* buffer =NULL;
unsigned int length =0;

void random_bytes(unsigned char* ptr, int size)
{
	int i;

	for(i =0; i < size; i++) *(ptr +i) = rand() %0x100;
}

unsigned long long total =0;

Z0_STATUS __stdcall write_result(PZ0_DISASM_CONTEXT context)
{
	DWORD bytes;
	int i;

	do
	{
		if((length +context->length) > BUFFER_SIZE)
		{
			if(!WriteFile(file, buffer, length, &bytes, NULL))
			{
				printf("ERROR: writer %u\r\n", GetLastError());
				break;
			}

			if(bytes != length)
			{
				printf("ERROR: writer wrong bytes =%#x (must be %#x)\r\n", bytes, length);
				break;
			}

			length =0;

			printf("%I64u instructions generated\r", total);
		}

		memcpy(buffer +length, context->bytes, context->length);

		length +=context->length;

		total++;

	} while(0);

	return Z0_STATUS_OK;
}

void entry(void)
{
	Z0_DISASM_CONTEXT context;
	Z0_STATUS status;
	int i, j;
	DWORD bytes;

	do
	{
		srand(GetTickCount());

		file =CreateFile(FILE_NAME, GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
		if(INVALID_HANDLE_VALUE == file)
		{
			printf("ERROR: can not open file %s\r\n", FILE_NAME);
			break;
		}

		buffer =(unsigned char*) HeapAlloc(GetProcessHeap(), 0, BUFFER_SIZE);
		if(!buffer)
		{
			break;
		}
		
		for(i =0; i < 0x100; i++)
	//	for(i =0x0f; i < 0x10; i++)
		{
			memset(&context, 0, sizeof(Z0_DISASM_CONTEXT));
			context.bytes[0] =i;
			context.length =1;
			context.finish =write_result;

			for(j =0; j < Z0_MAX_OPERANDS; j++) context.optype[j] = opcode_base[i].optype[j];
			context.flags = opcode_base[i].flags;
			context.mnemonic = opcode_base[i].mnemonic;

			status =opcode_base[i].process_handler(&context);
			if(Z0_STATUS_OK != status)
			{
				printf("ERROR: constructor %s\r\n", translate_status(status));
				break;
			}
		}

		if(length)
		{
			if(!WriteFile(file, buffer, length, &bytes, NULL))
			{
				printf("ERROR: writer %u\r\n", GetLastError());
				break;
			}

			if(bytes != length)
			{
				printf("ERROR: writer wrong bytes =%#x (must be %#x)\r\n", bytes, length);
				break;
			}
		}

		printf("%I64u instructions generated\r\n", total);

	} while(0);


	if(INVALID_HANDLE_VALUE != file) CloseHandle(file);
	if(buffer) HeapFree(GetProcessHeap(), 0, buffer);

	ExitProcess(0);
}
