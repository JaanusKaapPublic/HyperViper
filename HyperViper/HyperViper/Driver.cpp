#include<ntddk.h>
#include"Driver.h"
#include"Hypercall.h"
#include"MSR.h"
#include"VMbusChannels.h"
#include"VMbusPipe.h"
#include"DevIoCtrlHandler.h"

MSR msr;
NTSTATUS DriverIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS TracedrvDispatchOpenClose(IN PDEVICE_OBJECT pDO, IN PIRP Irp);
VOID DriverUnload(PDRIVER_OBJECT  DriverObject);

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegistryPath)
{
	UNREFERENCED_PARAMETER(pRegistryPath);
	DbgPrint("Starting HyperViper\n");

	NTSTATUS NtStatus = STATUS_SUCCESS;
	PDEVICE_OBJECT pDeviceObject = NULL;
	UNICODE_STRING usDriverName, usDosDeviceName;

	pDriverObject->MajorFunction[IRP_MJ_CLOSE] = TracedrvDispatchOpenClose;
	pDriverObject->MajorFunction[IRP_MJ_CREATE] = TracedrvDispatchOpenClose;
	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoControl;

	RtlInitUnicodeString(&usDriverName, DEVICE_NAME);
	RtlInitUnicodeString(&usDosDeviceName, SYMBOLIC_LINK_NAME);
	NtStatus = IoCreateDevice(pDriverObject, 0,	&usDriverName, 	FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &pDeviceObject);
	if (NtStatus == STATUS_SUCCESS)
	{
		IoCreateSymbolicLink(&usDosDeviceName, &usDriverName);

		pDriverObject->DriverUnload = DriverUnload;
	}

	Hypercall::init();
	VMbusChannels::init();
	VMbusPipe::init();
	return NtStatus;
}

NTSTATUS TracedrvDispatchOpenClose(IN PDEVICE_OBJECT pDO, IN PIRP Irp)
{
	UNREFERENCED_PARAMETER(pDO);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	PAGED_CODE();

	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT  DriverObject)
{
	Hypercall::close();
	VMbusChannels::close();
	VMbusPipe::close();
    
    UNICODE_STRING usDosDeviceName;    
    RtlInitUnicodeString(&usDosDeviceName, SYMBOLIC_LINK_NAME);
    IoDeleteSymbolicLink(&usDosDeviceName);
    IoDeleteDevice(DriverObject->DeviceObject);

	DbgPrint("Closed HyperViper\n");
}

NTSTATUS DriverIoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	UNREFERENCED_PARAMETER(DeviceObject);
	NTSTATUS NtStatus = STATUS_NOT_SUPPORTED;
	PIO_STACK_LOCATION pIoStackIrp = IoGetCurrentIrpStackLocation(Irp);
	ULONGLONG dataLen = 0;
	
	if (pIoStackIrp)
	{
		switch (pIoStackIrp->Parameters.DeviceIoControl.IoControlCode)
		{
		case IOCTL_HYPERCALLS_CALL:
			NtStatus = DevIoCtrlHandler::hypercallSend(Irp, pIoStackIrp, &dataLen);
			break;
		case IOCTL_HYPERCALLS_HOOK:
		case IOCTL_HYPERCALLS_UNHOOK:
			NtStatus = DevIoCtrlHandler::hypercallHooking(Irp, pIoStackIrp, &dataLen);
			break;
		case IOCTL_HYPERCALLS_GENERAL_DISGARD_SLOW:
		case IOCTL_HYPERCALLS_GENERAL_DISGARD_FAST:
		case IOCTL_HYPERCALLS_GENERAL_DBG_MSG:
			NtStatus = DevIoCtrlHandler::hypercallSetGeneralConf(Irp, pIoStackIrp, &dataLen);
			break;
		case IOCTL_HYPERCALLS_START_RECORD:
			NtStatus = DevIoCtrlHandler::hypercallLogging(Irp, pIoStackIrp, &dataLen);
			break;
		case IOCTL_HYPERCALLS_SINGLE_CLEAR:
		case IOCTL_HYPERCALLS_SINGLE_DBG_MSG:
		case IOCTL_HYPERCALLS_SINGLE_BREAKPOINT:
		case IOCTL_HYPERCALLS_SINGLE_LOG:
		case IOCTL_HYPERCALLS_SINGLE_FUZZ:
			NtStatus = DevIoCtrlHandler::hypercallSetSingleConf(Irp, pIoStackIrp, &dataLen);
			break;
		case IOCTL_HYPERCALLS_GET_STATS:
		case IOCTL_HYPERCALLS_GET_CONF:
			NtStatus = DevIoCtrlHandler::hypercallGetData(Irp, pIoStackIrp, &dataLen);
			break;
		case IOCTL_HYPERCALLS_FUZZ_ADDITION:
			NtStatus = DevIoCtrlHandler::hypercallFuzz(Irp, pIoStackIrp, &dataLen);
			break;


		case IOCTL_MSR_READ:
			NtStatus = DevIoCtrlHandler::msrRead(Irp, pIoStackIrp, &dataLen);
			break;
		case IOCTL_MSR_WRITE:
			NtStatus = DevIoCtrlHandler::msrWrite(Irp, pIoStackIrp, &dataLen);
			break;


		case IOCTL_CHANNELS_HOOK:
		case IOCTL_CHANNELS_UNHOOK:
			NtStatus = DevIoCtrlHandler::channelHooking(Irp, pIoStackIrp, &dataLen);
			break;
		case IOCTL_CHANNELS_LIST:
			NtStatus = DevIoCtrlHandler::channelGetData(Irp, pIoStackIrp, &dataLen);
			break;
		case IOCTL_CHANNELS_START_RECORD:
		case IOCTL_CHANNELS_STOP_RECORD:
			NtStatus = DevIoCtrlHandler::channelLogging(Irp, pIoStackIrp, &dataLen);
			break;
		case IOCTL_CHANNELS_SEND:
			NtStatus = DevIoCtrlHandler::channelSend(Irp, pIoStackIrp, &dataLen);
			break;
		case IOCTL_CHANNELS_FUZZ_SINGLE:
			NtStatus = DevIoCtrlHandler::channelFuzz(Irp, pIoStackIrp, &dataLen);
			break;


		case IOCTL_PIPE_HOOK:
		case IOCTL_PIPE_UNHOOK:
			NtStatus = DevIoCtrlHandler::pipeHooking(Irp, pIoStackIrp, &dataLen);
			break;
		case IOCTL_PIPE_START_RECORD:
		case IOCTL_PIPE_STOP_RECORD:
			NtStatus = DevIoCtrlHandler::pipeLogging(Irp, pIoStackIrp, &dataLen);
			break;

		case IOCTL_PMIO_READ:
			NtStatus = DevIoCtrlHandler::pmioRead(Irp, pIoStackIrp, &dataLen);
			break;
		case IOCTL_PMIO_WRITE:
			NtStatus = DevIoCtrlHandler::pmioWrite(Irp, pIoStackIrp, &dataLen);
			break;
		}
	}

	Irp->IoStatus.Status = NtStatus;
	Irp->IoStatus.Information = dataLen;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return NtStatus;

}