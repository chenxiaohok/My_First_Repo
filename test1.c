/*
    测试Task Management请求各功能的作用
*/

#include"myhead.h"

// struct mpt3_ioctl_command_user iocmd={0};

#define SIZE 256

char sendbuf[SIZE]={0};
char recvbuf[SIZE]={0};
char sensebuf[SIZE]={0};
char reply_addr[SIZE]={0};

int main(int argc, char const *argv[])
{

    // scsi_io请求消息
    // struct mpi_scsi_io_request req_queset = {
    //     .Function = 0, // MPI2_FUNCTION_SCSI_IO_REQUEST
    //     .DevHandle = 0x1,
    // };

    // ioctl_commd命令消息
    struct mpt3_ioctl_command_user *iocmd =(struct mpt3_ioctl_command_user*)malloc(sizeof(struct mpt3_ioctl_command_user) + sizeof(mpi2_scsi_task_manage_request));
    memset(iocmd,0,sizeof(struct mpt3_ioctl_command_user) + sizeof(mpi2_scsi_task_manage_request));

    // iocmd->data_sge_offset=24;
    // iocmd->hdr.ioc_number=1;

    iocmd->data_out_size = 0;
    iocmd->data_in_size = 255;
    iocmd->data_in_buf_ptr = recvbuf;
    iocmd->data_out_buf_ptr = sendbuf;
    iocmd->sense_data_ptr = sensebuf;
    iocmd->reply_frame_buf_ptr = reply_addr;
    iocmd->data_sge_offset = 24;
    iocmd->max_reply_bytes = 255;
    iocmd->max_sense_bytes = 255;

    //  printf("sizeof=%ld %ld\n",sizeof(*iocmd),sizeof(mpt3_ioctl_command_user));  
    
    mpi2_scsi_task_manage_request* req_queset=(mpi2_scsi_task_manage_request*)&iocmd->mf;
    memset(req_queset,0,sizeof(mpi2_scsi_task_manage_request));
    req_queset->Function=0x1;
    req_queset->DevHandle=(0x9);
    req_queset->TaskMID=0;
    req_queset->MsgFlags=0x1;

    int input_number = 0x1;
    switch (input_number)
    {
    case 0x1:
        req_queset->TaskType = MPI2_SCSITASKMGMT_TASKTYPE_ABORT_TASK;
        break;
    case 0x2:
        req_queset->TaskType = MPI2_SCSITASKMGMT_TASKTYPE_ABRT_TASK_SET;
        break;
    case 0x3:
        req_queset->TaskType = MPI2_SCSITASKMGMT_TASKTYPE_TARGET_RESET;
        break;
    case 0x5:
        req_queset->TaskType = MPI2_SCSITASKMGMT_TASKTYPE_LOGICAL_UNIT_RESET;
        break;
    case 0x6:
        req_queset->TaskType = MPI2_SCSITASKMGMT_TASKTYPE_CLEAR_TASK_SET;
        break;
    case 0x7:
        req_queset->TaskType = MPI2_SCSITASKMGMT_TASKTYPE_QUERY_TASK ;
        break;
    case 0x8:
        req_queset->TaskType = MPI2_SCSITASKMGMT_TASKTYPE_CLR_ACA;
        break;
    case 0x9:
        req_queset->TaskType = MPI2_SCSITASKMGMT_TASKTYPE_QRY_TASK_SET;
        break;
    case 0xA:
        req_queset->TaskType = MPI2_SCSITASKMGMT_TASKTYPE_QRY_ASYNC_EVENT;
        break;
    }


    int fd=open("/dev/mpt3ctl",O_RDWR);
    if(fd==-1) 
    {
        perror("open err\n");
        return -1;
    }
    
    if( ioctl(fd,MPT3COMMAND,iocmd) )
    {
        perror("ioctl err\n");
        return -1;
    }

    //获取task回复信息
    _mpi2_scsi_task_manage_reply* res=iocmd->reply_frame_buf_ptr;
// printf("%d\n",sizeof(res));
    info_print(res,sizeof(_mpi2_scsi_task_manage_reply)/4);
 
//  u16 DevHandle;		/*0x00 */
// 	u8 MsgLength;		/*0x02 */
// 	u8 Function;		/*0x03 */
// 	u8 ResponseCode;	/*0x04 */
// 	u8 TaskType;		/*0x05 */
// 	u8 Reserved1;		/*0x06 */
// 	u8 MsgFlags;		/*0x07 */
// 	u8 VP_ID;		/*0x08 */
// 	u8 VF_ID;		/*0x09 */
// 	u16 Reserved2;		/*0x0A */
// 	u16 Reserved3;		/*0x0C */
// 	u16 IOCStatus;		/*0x0E */
// 	u32 IOCLogInfo;		/*0x10 */
// 	u32 TerminationCount;	/*0x14 */
// 	u32 ResponseInfo;	/*0x18 */


    printf("DevHandle=%#x\n",res->DevHandle);
    printf("MsgLength=%#x\n",res->MsgLength);
    printf("Function=%#x\n",res->Function);
    printf("ResponseCode=%#x\n",res->ResponseCode);
    printf("TaskType=%#x\n",res->TaskType);
    printf("Reserved1=%#x\n",res->Reserved1);
    printf("MsgFlags=%#x\n",res->MsgFlags);
    printf("VP_ID=%#x\n",res->VP_ID);
    printf("VF_ID=%#x\n",res->VF_ID);
    printf("Reserved2=%#x\n",res->Reserved2);
    printf("Reserved3=%#x\n",res->Reserved3);
    printf("IOCStatus=%#x\n",res->IOCStatus);
    printf("IOCLogInfo=%#x\n",res->IOCLogInfo);
    printf("TerminationCount=%#x\n",res->TerminationCount);
    printf("ResponseInfo=%#x\n",res->ResponseInfo);


    //空
    info_print(recvbuf,sizeof(res)/4);
    // printf("DevHadle=%#x Function=%#x MsgLength=%d,TaskType=%#x\n",res->DevHandle,res->Function,res->MsgLength,res->TaskType);




    return 0;
}
