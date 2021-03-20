#include <ntifs.h>
#include <ntddk.h>
#include <ntstrsafe.h>

#define DRIVER_TAG 'RINd'

typedef NTSTATUS(__stdcall* QUERY_INFO_PROCESS)(
    __in       HANDLE ProcessHandle,
    __in       PROCESSINFOCLASS ProcessInformationClass,
    __out      PVOID ProcessInformation,
    __in       ULONG ProcessInformationLength,
    __out_opt  PULONG ReturnLength
    );

QUERY_INFO_PROCESS ZwQueryInformationProcess = NULL;

ULONG GetLength(UNICODE_STRING Buffer)
{
    ULONG i = 0;
    while (Buffer.Buffer[i] != '\0')
    {
        i++;
    }
    return i;
}

NTSTATUS LogToFile(UNICODE_STRING Buffer, int reason)
{
    ULONG bufferSize = GetLength(Buffer);
    UNICODE_STRING FilePath;
    ANSI_STRING temp;
    NTSTATUS Status = 0;
    RtlUnicodeStringToAnsiString(&temp, &Buffer, TRUE);
    //DbgPrint("%wZ =  %s\n", Buffer,  temp.Buffer);
    if (reason == 1)
    {
        RtlInitUnicodeString(&FilePath, L"\\DosDevices\\C:\\driver\\cp.txt");
    }
    else if (reason == 2)
    {
        RtlInitUnicodeString(&FilePath, L"\\DosDevices\\C:\\driver\\cp2.txt");
    }
    else
    {
        RtlInitUnicodeString(&FilePath, L"\\DosDevices\\C:\\driver\\dll.txt");
    }
    DbgPrint("Writer start %wZ\n", FilePath);

    HANDLE              hFile;
    OBJECT_ATTRIBUTES   ObjAttr;
    IO_STATUS_BLOCK     IoStatusBlock;


    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
    {
        DbgPrint("Irql level low\n");
        return 0;
    }
    InitializeObjectAttributes(&ObjAttr, &FilePath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);


    Status = ZwCreateFile(&hFile, FILE_APPEND_DATA | SYNCHRONIZE, &ObjAttr, &IoStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL,
        0, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);


    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[DRV_NAME]: Opening file error %X\n", Status);
        return Status;
    }
    Status = ZwWriteFile(hFile, 0, NULL, NULL, &IoStatusBlock, temp.Buffer, bufferSize, NULL, NULL);

    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[DRV_NAME]: Writing file error %X\n", Status);
        ZwClose(hFile);
        return Status;
    }
    ZwClose(hFile);
    return Status;





    /*LARGE_INTEGER ByteOffset;

    ByteOffset.HighPart = -1;
    ByteOffset.LowPart = FILE_WRITE_TO_END_OF_FILE;

    Status = ZwWriteFile(hFile, 0, NULL, NULL, &IoStatusBlock, &Buffer, bufferSize, NULL, NULL);

    if (!NT_SUCCESS(Status))
    {
        DbgPrint("[DRV_NAME]: Writing file error %X\n", Status);
        ZwClose(hFile);
        return Status;
    }*/

}

NTSTATUS GetProcessImageName(HANDLE ProcessHandle, PUNICODE_STRING ProcessImageName)
{
    NTSTATUS status = STATUS_ACCESS_DENIED;
    PUNICODE_STRING imageName = NULL;
    ULONG returnedLength = 0;
    ULONG bufferLength = 0;
    PVOID buffer = NULL;

    if (ZwQueryInformationProcess == NULL)
    {
        UNICODE_STRING routineName;
        RtlInitUnicodeString(&routineName, L"ZwQueryInformationProcess");
        ZwQueryInformationProcess = (QUERY_INFO_PROCESS)MmGetSystemRoutineAddress(&routineName);
        if (NULL == ZwQueryInformationProcess) { return STATUS_INSUFFICIENT_RESOURCES; }
    }

    status = ZwQueryInformationProcess(ProcessHandle, ProcessImageFileName, NULL, 0, &returnedLength);
    if (STATUS_INFO_LENGTH_MISMATCH != status) { return status; }

    bufferLength = returnedLength - sizeof(UNICODE_STRING);
    if (ProcessImageName->MaximumLength < bufferLength)
    {
        ProcessImageName->Length = (USHORT)bufferLength;
        return STATUS_BUFFER_OVERFLOW;
    }

    buffer = ExAllocatePoolWithTag(PagedPool, returnedLength, 'ipgD');
    if (NULL == buffer) { return STATUS_INSUFFICIENT_RESOURCES; }

    status = ZwQueryInformationProcess(ProcessHandle, ProcessImageFileName, buffer, returnedLength, &returnedLength);
    if (NT_SUCCESS(status))
    {
        imageName = (PUNICODE_STRING)buffer;
        RtlCopyUnicodeString(ProcessImageName, imageName);
    }
    ExFreePool(buffer);
    return status;
}

BOOLEAN RetrieveProcessNameByID(HANDLE ProcessId, PUNICODE_STRING pusImageFileName)
{
    UNICODE_STRING ProcImgName = { 0 };
    HANDLE hProcessHandle = NULL;
    NTSTATUS status = STATUS_ACCESS_DENIED;
    PEPROCESS eProcess = NULL;
    int iEntryIndex = -1;

    status = PsLookupProcessByProcessId(ProcessId, &eProcess);
    if ((!NT_SUCCESS(status)) || (!eProcess))
    {
        return FALSE;
    }

    status = ObOpenObjectByPointer(eProcess, 0, NULL, 0, 0, KernelMode, &hProcessHandle);
    if ((!NT_SUCCESS(status)) || (!hProcessHandle))
    {
        ObDereferenceObject(eProcess);
        return FALSE;
    }

    ProcImgName.Length = 0;
    ProcImgName.MaximumLength = 1024;
    ProcImgName.Buffer = ExAllocatePoolWithTag(NonPagedPool, ProcImgName.MaximumLength, '2leN');
    if (ProcImgName.Buffer == NULL)
    {
        ZwClose(hProcessHandle);
        ObDereferenceObject(eProcess);
        return FALSE;
    }

    RtlZeroMemory(ProcImgName.Buffer, ProcImgName.MaximumLength);
    status = GetProcessImageName(hProcessHandle, &ProcImgName);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("[NotifyProcessCreate] GetProcessImageName failed (0x%08x)\n", status);
        ExFreePoolWithTag(ProcImgName.Buffer, '2leN');
        ZwClose(hProcessHandle);
        ObDereferenceObject(eProcess);
        return FALSE;
    }

    if (pusImageFileName)
    {
        RtlCopyUnicodeString(pusImageFileName, &ProcImgName);
    }
    ExFreePoolWithTag(ProcImgName.Buffer, '2leN');
    ZwClose(hProcessHandle);
    ObDereferenceObject(eProcess);
    return TRUE;
}

VOID PsCreateProcessNotifyRoutineEx(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNICODE_STRING ParentProcessFilePath;
    ParentProcessFilePath.MaximumLength = 256;
    ParentProcessFilePath.Buffer = ExAllocatePoolWithTag(NonPagedPool, 256, DRIVER_TAG);

    UNICODE_STRING toRet;
    toRet.MaximumLength = 512;
    toRet.Buffer = ExAllocatePoolWithTag(NonPagedPool, 512, DRIVER_TAG);



    if (CreateInfo == NULL) {
        DbgPrint("PsCreateProcessNotifyRoutineEx: PID 0x%p exiting. "\
            "Process PID 0x%p\n",
            Process,
            ProcessId);

        ExFreePool(ParentProcessFilePath.Buffer);
        ExFreePool(toRet.Buffer);
        return;
    }
    BOOLEAN res = RetrieveProcessNameByID(CreateInfo->ParentProcessId, &ParentProcessFilePath);
    RtlUnicodeStringPrintf(&toRet, L"%wZ: %wZ", ParentProcessFilePath, CreateInfo->CommandLine);
    if (!res)
    {
        DbgPrint("Fail get Parent Process name\n");
    }
    DbgPrint("PsCreateProcessNotifyRoutineEx: %wZ Runned by %wZ\n",
        CreateInfo->CommandLine,
        ParentProcessFilePath
    );
    DbgPrint("%wZ\n", toRet);

    ExFreePool(ParentProcessFilePath.Buffer);
    ExFreePool(toRet.Buffer);
    return;
}

VOID PsCreateProcessNotifyRoutineEx2(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNICODE_STRING ParentProcessFilePath;
    ParentProcessFilePath.MaximumLength = 256;
    ParentProcessFilePath.Buffer = ExAllocatePoolWithTag(NonPagedPool, 256, DRIVER_TAG);

    UNICODE_STRING toRet;
    toRet.MaximumLength = 1024;
    toRet.Length = 1024;
    toRet.Buffer = ExAllocatePoolWithTag(NonPagedPool, 1024, DRIVER_TAG);

    if (CreateInfo == NULL) { //если процесс закрывается, а не создается
        BOOLEAN res = RetrieveProcessNameByID(ProcessId, &ParentProcessFilePath); //получить имя закрывающегося процесса
        DbgPrint("PsCreateProcessNotifyRoutineEx2: PID 0x%p %wZ exiting." //вывести в dbg
            "Process PID 0x%p\n",
            Process,
            ParentProcessFilePath,
            ProcessId);
        return;
    }

    BOOLEAN res = RetrieveProcessNameByID(CreateInfo->ParentProcessId, &ParentProcessFilePath);//получить имя процесса-родителя 
    if (!res) //если имя получить по какой-либо причине не удалось пишем об этом
    {
        DbgPrint("Fail get Parent Process name\n");
    }
    /*DbgPrint("PsCreateProcessNotifyRoutineEx2: %wZ Runned by %wZ\n", //выводим полученный результат
        CreateInfo->CommandLine,
        ParentProcessFilePath
    );*/
    NTSTATUS print_res = RtlUnicodeStringPrintf(&toRet, L"%wZ: %wZ\n", ParentProcessFilePath, CreateInfo->CommandLine);
    if (!NT_SUCCESS(print_res))
    {
        DbgPrint("%X\n", print_res);
    }
    //DbgPrint("%wZ\n", toRet);
    LogToFile(toRet, 2);
    ExFreePool(ParentProcessFilePath.Buffer);
    ExFreePool(toRet.Buffer);
    return;
}

VOID PsLoadImageNotifyRoutine(PUNICODE_STRING  FullImageName, HANDLE ProcessId, PIMAGE_INFO  ImageInfo)
{

    PIMAGE_INFO_EX imageInfoEx = NULL;
    PFILE_OBJECT   backingFileObject;
    UNICODE_STRING ParentProcessFilePath;
    ParentProcessFilePath.Buffer = ExAllocatePoolWithTag(NonPagedPool, 256, DRIVER_TAG);

    UNICODE_STRING toRet;
    toRet.Buffer = ExAllocatePoolWithTag(NonPagedPool, 512, DRIVER_TAG);

    if (ImageInfo->ExtendedInfoPresent) {

        imageInfoEx = CONTAINING_RECORD(ImageInfo, IMAGE_INFO_EX, ImageInfo);

        backingFileObject = imageInfoEx->FileObject;

    }
    else {

        backingFileObject = NULL;

    }

    BOOLEAN res = RetrieveProcessNameByID(ProcessId, &ParentProcessFilePath);
    DbgPrint("PsLoadImageNotifyRoutine: %wZ being loaded into "\
        "Process 0x%p ,%wZ . Backing File Object %s (0x%p)\n",
        FullImageName,
        ProcessId,
        ParentProcessFilePath,
        backingFileObject != NULL ? "Available" : "Unavailable",
        backingFileObject);

    RtlUnicodeStringPrintf(&toRet, L"%wZ: %wZ", ParentProcessFilePath, FullImageName);
    DbgPrint("%wZ\n", toRet);
    ExFreePool(ParentProcessFilePath.Buffer);
    ExFreePool(toRet.Buffer);
    return;
}

VOID UnregisterAllCallbacks(VOID)
{

    NTSTATUS status;

    status = PsSetCreateProcessNotifyRoutineEx(
        PsCreateProcessNotifyRoutineEx,
        TRUE);

    ASSERT(NT_SUCCESS(status));

    status = PsSetCreateProcessNotifyRoutineEx(
        PsCreateProcessNotifyRoutineEx,
        TRUE);
    ASSERT(NT_SUCCESS(status));

    status = PsSetCreateProcessNotifyRoutineEx2(
        PsCreateProcessNotifySubsystems,
        PsCreateProcessNotifyRoutineEx2,
        TRUE);
    // 
    // This should work because we know we registered.
    // 
    ASSERT(NT_SUCCESS(status));
    status = PsRemoveLoadImageNotifyRoutine(PsLoadImageNotifyRoutine);
    ASSERT(NT_SUCCESS(status));
}

VOID Unload(PDRIVER_OBJECT DriverObject)
{

    UNREFERENCED_PARAMETER(DriverObject);

    UnregisterAllCallbacks();
    return;
}


NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{

    NTSTATUS       status;
    UNICODE_STRING callbackName;
    UNICODE_STRING altitude;
    OB_CALLBACK_REGISTRATION   obCbRegistration;
    POB_OPERATION_REGISTRATION obOpRegistration = NULL;
    ULONG                      obOpSize;
    // 
    // PS CALLBACKS 
    //
    DbgPrint("Nir starts\n");
    /*
    status = PsSetCreateProcessNotifyRoutineEx(
        PsCreateProcessNotifyRoutineEx,
        FALSE);

    if (!NT_SUCCESS(status)) {
        DbgPrint("PsSetCreateProcessNotifyRoutineEx failed! Status 0x%x\n",
            status);
        goto Exit;
    }*/

    status = PsSetCreateProcessNotifyRoutineEx2(PsCreateProcessNotifySubsystems,
        PsCreateProcessNotifyRoutineEx2,
        FALSE);

    if (!NT_SUCCESS(status)) {
        DbgPrint("PsSetCreateProcessNotifyRoutineEx2 failed! Status 0x%x\n",
            status);
        goto Exit;
    }
    /*
    status = PsSetLoadImageNotifyRoutine(PsLoadImageNotifyRoutine);

    if (!NT_SUCCESS(status)) {
        DbgPrint("PsSetLoadImageNotifyRoutine failed! Status 0x%x\n",
            status);
        goto Exit;
    }*/
    //CreateProcessPath.Buffer = ExAllocatePoolWithTag(NonPagedPool, 256, DRIVER_TAG);

    DriverObject->DriverUnload = Unload;

Exit:
    if (!NT_SUCCESS(status)) {
        // 
        // Undo what we've done and fail.
        // 
        UnregisterAllCallbacks();
    }

    return status;
}

