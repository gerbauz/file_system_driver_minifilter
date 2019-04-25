#include <fltKernel.h>
#include <dontuse.h>
#include <suppress.h>
#include <stdio.h>
#include <string.h>

#pragma prefast(disable:__WARNING_ENCODE_MEMBER_FUNCTION_POINTER, "Not valid for kernel mode drivers")


PFLT_FILTER gFilterHandle;
ULONG_PTR OperationStatusCtx = 1;

#define PTDBG_TRACE_ROUTINES            0x00000001
#define PTDBG_TRACE_OPERATION_STATUS    0x00000002

#define CONFIG_PATH L"\\??\\C:\\dr_config.txt"

#define TARGET_PATH "\\mbks5\\"

ULONG gTraceFlags = 0;


#define PT_DBG_PRINT( _dbgLevel, _string )          \
    (FlagOn(gTraceFlags,(_dbgLevel)) ?              \
        DbgPrint _string :                          \
        ((int)0))

/*************************************************************************
	Prototypes
*************************************************************************/

DRIVER_INITIALIZE DriverEntry;
NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
);

NTSTATUS
PtInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
);

VOID
PtInstanceTeardownStart(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

VOID
PtInstanceTeardownComplete(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
);

NTSTATUS
PtUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
);

NTSTATUS
PtInstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
PtPreOperationCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

VOID
PtOperationStatusCallback(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
	_In_ NTSTATUS OperationStatus,
	_In_ PVOID RequesterContext
);

FLT_POSTOP_CALLBACK_STATUS
PtPostOperationCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
);

FLT_PREOP_CALLBACK_STATUS
PtPreOperationNoPostOperationmbks5labfilesystemdriver(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
);

BOOLEAN
PtDoRequestOperationStatus(
	_In_ PFLT_CALLBACK_DATA Data
);

BOOLEAN NPUnicodeStringToChar(PUNICODE_STRING UniName, char Name[]);

BOOLEAN CheckProcessAccess(HANDLE hFile, CHAR pid_string[], CHAR object[], BOOLEAN read_request, BOOLEAN write_request);

void itoa(int n, char s[]);

//
//  Assign text sections for each routine.
//

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, PtUnload)
#pragma alloc_text(PAGE, PtInstanceQueryTeardown)
#pragma alloc_text(PAGE, PtInstanceSetup)
#pragma alloc_text(PAGE, PtInstanceTeardownStart)
#pragma alloc_text(PAGE, PtInstanceTeardownComplete)
#endif

//
//  operation registration
//

CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE,
	  0,
	  NULL,
	  PtPostOperationCallback },

	  { IRP_MJ_OPERATION_END }
};

//
//  This defines what we want to filter with FltMgr
//

CONST FLT_REGISTRATION FilterRegistration = {

	sizeof(FLT_REGISTRATION),			//  Size
	FLT_REGISTRATION_VERSION,           //  Version
	0,                                  //  Flags

	NULL,                               //  Context
	Callbacks,                          //  Operation callbacks

	PtUnload,                           //  MiniFilterUnload

	PtInstanceSetup,                    //  InstanceSetup
	PtInstanceQueryTeardown,            //  InstanceQueryTeardown
	PtInstanceTeardownStart,            //  InstanceTeardownStart
	PtInstanceTeardownComplete,         //  InstanceTeardownComplete

	NULL,                               //  GenerateFileName
	NULL,                               //  GenerateDestinationFileName
	NULL                                //  NormalizeNameComponent

};



NTSTATUS
PtInstanceSetup(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_SETUP_FLAGS Flags,
	_In_ DEVICE_TYPE VolumeDeviceType,
	_In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);
	UNREFERENCED_PARAMETER(VolumeDeviceType);
	UNREFERENCED_PARAMETER(VolumeFilesystemType);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("mbks5labfilesystemdriver!PtInstanceSetup: Entered\n"));

	return STATUS_SUCCESS;
}


NTSTATUS
PtInstanceQueryTeardown(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("mbks5labfilesystemdriver!PtInstanceQueryTeardown: Entered\n"));

	return STATUS_SUCCESS;
}


VOID
PtInstanceTeardownStart(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("mbks5labfilesystemdriver!PtInstanceTeardownStart: Entered\n"));
}


VOID
PtInstanceTeardownComplete(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("mbks5labfilesystemdriver!PtInstanceTeardownComplete: Entered\n"));
}


/*************************************************************************
	MiniFilter initialization and unload routines.
*************************************************************************/

NTSTATUS
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	NTSTATUS status;

	UNREFERENCED_PARAMETER(RegistryPath);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("mbks5labfilesystemdriver!DriverEntry: Entered\n"));

	//
	//  Register with FltMgr to tell it our callback routines
	//

	status = FltRegisterFilter(DriverObject,
		&FilterRegistration,
		&gFilterHandle);

	FLT_ASSERT(NT_SUCCESS(status));

	if (NT_SUCCESS(status)) {

		//
		//  Start filtering i/o
		//

		status = FltStartFiltering(gFilterHandle);

		if (!NT_SUCCESS(status)) {

			FltUnregisterFilter(gFilterHandle);
		}
	}

	return status;
}

NTSTATUS
PtUnload(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Flags);

	PAGED_CODE();

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("mbks5labfilesystemdriver!PtUnload: Entered\n"));

	FltUnregisterFilter(gFilterHandle);

	return STATUS_SUCCESS;
}


/*************************************************************************
	MiniFilter callback routines.
*************************************************************************/
FLT_PREOP_CALLBACK_STATUS
PtPreOperationCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
	NTSTATUS status;

	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("mbks5labfilesystemdriver!PtPreOperationmbks5labfilesystemdriver: Entered\n"));

	//
	//  See if this is an operation we would like the operation status
	//  for.  If so request it.
	//
	//  NOTE: most filters do NOT need to do this.  You only need to make
	//        this call if, for example, you need to know if the oplock was
	//        actually granted.
	//



	if (PtDoRequestOperationStatus(Data)) {

		status = FltRequestOperationStatusCallback(Data,
			PtOperationStatusCallback,
			(PVOID)(++OperationStatusCtx));
		if (!NT_SUCCESS(status)) {

			PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
				("mbks5labfilesystemdriver!PtPreOperationmbks5labfilesystemdriver: FltRequestOperationStatusCallback Failed, status=%08x\n",
					status));
		}
	}

	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}



VOID
PtOperationStatusCallback(
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_ PFLT_IO_PARAMETER_BLOCK ParameterSnapshot,
	_In_ NTSTATUS OperationStatus,
	_In_ PVOID RequesterContext
)
{
	UNREFERENCED_PARAMETER(FltObjects);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("mbks5labfilesystemdriver!PtOperationStatusCallback: Entered\n"));

	PT_DBG_PRINT(PTDBG_TRACE_OPERATION_STATUS,
		("mbks5labfilesystemdriver!PtOperationStatusCallback: Status=%08x ctx=%p IrpMj=%02x.%02x \"%s\"\n",
			OperationStatus,
			RequesterContext,
			ParameterSnapshot->MajorFunction,
			ParameterSnapshot->MinorFunction,
			FltGetIrpName(ParameterSnapshot->MajorFunction)));
}


FLT_POSTOP_CALLBACK_STATUS
PtPostOperationCallback(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_In_opt_ PVOID CompletionContext,
	_In_ FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("mbks5labfilesystemdriver!PtPostOperationmbks5labfilesystemdriver: Entered\n"));

	NTSTATUS status;


	UNICODE_STRING file_directory;

	PFLT_FILE_NAME_INFORMATION file_name;

	status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &file_name);

	if (!NT_SUCCESS(status))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}
	status = FltParseFileNameInformation(file_name);

	if (!NT_SUCCESS(status))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	char file_dir[256] = { "" };

	file_directory = file_name->ParentDir;

	if (!NPUnicodeStringToChar(&file_name->ParentDir, file_dir))
	{
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	if (!strcmp(file_dir, TARGET_PATH))
	{

		status = FltGetFileNameInformation(Data, FLT_FILE_NAME_SHORT | FLT_FILE_NAME_QUERY_DEFAULT, &file_name);

		if (!NT_SUCCESS(status))
		{
			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		status = FltParseFileNameInformation(file_name);

		if (!NT_SUCCESS(status))
		{
			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		ULONG pid;
		CHAR object_name[256] = { "" };
		CHAR pid_string[256] = { "" };
		BOOLEAN read_request = FALSE;
		BOOLEAN write_request = FALSE;

		pid = FltGetRequestorProcessId(Data);

		itoa(pid, pid_string);

		if (!NPUnicodeStringToChar(&file_name->Name, object_name))
		{
			return FLT_POSTOP_FINISHED_PROCESSING;
		}

		read_request = Data->Iopb->TargetFileObject->ReadAccess;
		write_request = Data->Iopb->TargetFileObject->WriteAccess;

		if (read_request | write_request)
		{
			HANDLE hFile;
			OBJECT_ATTRIBUTES ObjectAttributes;
			IO_STATUS_BLOCK	IoStatusBlock;
			UNICODE_STRING usObjectName;

			RtlInitUnicodeString(&usObjectName, CONFIG_PATH);

			InitializeObjectAttributes(&ObjectAttributes, &usObjectName, OBJ_CASE_INSENSITIVE, NULL, NULL);

			status = ZwCreateFile(&hFile, GENERIC_READ | SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

			if (!NT_SUCCESS(status))
			{
				return FLT_POSTOP_FINISHED_PROCESSING;
			}

			//DbgPrint("Config file opened\n");

			if (FALSE == CheckProcessAccess(hFile, pid_string, object_name, read_request, write_request))
			{
				Data->IoStatus.Status = STATUS_ACCESS_DENIED;
				Data->IoStatus.Information = 0;
			}

			ZwClose(hFile);
		}
	}


	return FLT_POSTOP_FINISHED_PROCESSING;
}

VOID tokenize_spaces(PCHAR tok)
{
	while (tok++)
	{
		if (*tok == ' ')
		{
			*tok = '\0';
			break;
		}
	}
}

BOOLEAN CheckProcessAccess(HANDLE hFile, CHAR pid_string[], CHAR object[], BOOLEAN read_request, BOOLEAN write_request)
{
	NTSTATUS loc_status;
	IO_STATUS_BLOCK	IoStatusBlock;
	CHAR word;
	//char filename_buf[256] = { "" };
	//char rights_buf[64] = { "" };
	LARGE_INTEGER ByteOffset;
	ByteOffset.HighPart = -1;
	ByteOffset.LowPart = FILE_USE_FILE_POINTER_POSITION;

	CHAR* current_sym;

	BOOLEAN not_eof = TRUE;

	while (not_eof)
	{
		CHAR buf[512] = { "" };
		current_sym = &buf[0];
		do
		{
			loc_status = ZwReadFile(hFile, NULL, NULL, NULL, &IoStatusBlock, &word, sizeof(CHAR), &ByteOffset, NULL);
			if (loc_status == STATUS_END_OF_FILE)
			{
				not_eof = FALSE;
				break;
			}
			if (word == '\n')
				break;

			*current_sym++ = word;
		} while (word != '\0');

		PCHAR pid;
		PCHAR file_name;
		PCHAR rights;

		PCHAR tok = &buf[0];


		pid = buf;
		while (tok++)
		{
			if (*tok == ' ')
			{
				*tok = '\0';
				break;
			}
		}

		file_name = ++tok;

		while (tok++)
		{
			if (*tok == ' ')
			{
				*tok = '\0';
				break;
			}
		}

		rights = ++tok;

		//DbgPrint("PID: %s\n", pid);
		//DbgPrint("FILE: %s\n", file_name);
		//DbgPrint("RGHTS: %s\n", rights);

		//DbgPrint("PID2: %s\n", pid_string);
		//DbgPrint("FILE2: %s\n", object);

		if (!strcmp(pid, pid_string))
		{
			if (!strcmp(file_name, object))
			{
				if (read_request && (rights[0] == 'r' || rights[1] == 'r'))
					return TRUE;
				if (write_request && (rights[0] == 'w' || rights[1] == 'w'))
					return TRUE;
			}
		}

	}


	return FALSE;
}


FLT_PREOP_CALLBACK_STATUS
PtPreOperationNoPostOperationmbks5labfilesystemdriver(
	_Inout_ PFLT_CALLBACK_DATA Data,
	_In_ PCFLT_RELATED_OBJECTS FltObjects,
	_Flt_CompletionContext_Outptr_ PVOID * CompletionContext
)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	PT_DBG_PRINT(PTDBG_TRACE_ROUTINES,
		("mbks5labfilesystemdriver!PtPreOperationNoPostOperationmbks5labfilesystemdriver: Entered\n"));

	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


BOOLEAN
PtDoRequestOperationStatus(
	_In_ PFLT_CALLBACK_DATA Data
)
{
	PFLT_IO_PARAMETER_BLOCK iopb = Data->Iopb;

	//
	//  return boolean state based on which operations we are interested in
	//

	return (BOOLEAN)

		//
		//  Check for oplock operations
		//

		(((iopb->MajorFunction == IRP_MJ_FILE_SYSTEM_CONTROL) &&
		((iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_FILTER_OPLOCK) ||
			(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_BATCH_OPLOCK) ||
			(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_1) ||
			(iopb->Parameters.FileSystemControl.Common.FsControlCode == FSCTL_REQUEST_OPLOCK_LEVEL_2)))

			||

			//
			//    Check for directy change notification
			//

			((iopb->MajorFunction == IRP_MJ_DIRECTORY_CONTROL) &&
			(iopb->MinorFunction == IRP_MN_NOTIFY_CHANGE_DIRECTORY))
			);
}

BOOLEAN NPUnicodeStringToChar(PUNICODE_STRING UniName, char Name[])
{
	ANSI_STRING	AnsiName;
	NTSTATUS loc_status;
	char* nameptr;

	loc_status = RtlUnicodeStringToAnsiString(&AnsiName, UniName, TRUE);

	if (!NT_SUCCESS(loc_status))
	{
		return FALSE;
	}

	if (AnsiName.Length < 256)
	{
		nameptr = (PCHAR)AnsiName.Buffer;
		strcpy(Name, nameptr);
	}

	RtlFreeAnsiString(&AnsiName);
	return TRUE;
}

void reverse(char s[])
{
	int i, j;
	char c;

	for (i = 0, j = strlen(s) - 1; i < j; i++, j--)
	{
		c = s[i];
		s[i] = s[j];
		s[j] = c;
	}
}

void itoa(int n, char s[])
{
	int i, sign;

	if ((sign = n) < 0)
		n = -n;
	i = 0;
	do
	{
		s[i++] = n % 10 + '0';
	} while ((n /= 10) > 0);
	if (sign < 0)
		s[i++] = '-';
	s[i] = '\0';
	reverse(s);
}