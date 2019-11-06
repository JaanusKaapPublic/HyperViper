#pragma once
#include<ntddk.h>
#include"Hypercall.h"
#include"MSR.h"
#include"PMIO.h"
#include"VMbusChannels.h"


class DevIoCtrlHandler
{
public:
	static NTSTATUS hypercallSend(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten);
	static NTSTATUS hypercallHooking(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten);
	static NTSTATUS hypercallLogging(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten);
	static NTSTATUS hypercallSetGeneralConf(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten);
	static NTSTATUS hypercallSetSingleConf(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten);
	static NTSTATUS hypercallGetData(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten);
	static NTSTATUS hypercallFuzz(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten);

	static NTSTATUS msrRead(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten);
	static NTSTATUS msrWrite(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten);

	static NTSTATUS channelHooking(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten);
	static NTSTATUS channelGetData(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten);
	static NTSTATUS channelLogging(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten);
	static NTSTATUS channelSend(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten);
	static NTSTATUS channelFuzz(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten);

	static NTSTATUS pipeHooking(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten);
	static NTSTATUS pipeLogging(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten);

	static NTSTATUS pmioRead(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten);
	static NTSTATUS pmioWrite(PIRP Irp, PIO_STACK_LOCATION pIoStackIrp, PULONGLONG pdwDataWritten);
};