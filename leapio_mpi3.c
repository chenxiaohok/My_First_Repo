#include "leapio_mpi3.h"

static struct dentry *leapio_mpi_root;

#define MPI_MAGIC				(777)
#define MAX_BUF_SZ 				(0x40000000)	/* 1G */
#define MAX_PACKET_SZ 			(MAX_BUF_SZ)
#define LEAPIO_FLAG_SHIFT  		(24)

/**
 * 	blob file format use pcap:
 *  Global Header
 *  Packet Header
 *  Packet Data
 *  Packet Header
 *  Packet Data
 * 
 * 	each packet include muti entry, one entry inclue:
 * 	|-------------------------------------------|
 * 	|  high 4-bit |   4-bit    |    low 24-bit  |
 * 	|  sge_type   |  data_type |    len 		|
 * 	|-------------------------------------------|
 * 	|				len bytes					|
 * 	|				  data						|
 * 	|-------------------------------------------|
 *  Note: becase all mpi message endianness is little end, 
 *        so we save pcap header as litte end.
*/

/* trace interaction between host and ioc by Messaging Queues except request descriptor */
enum data_type {
	NONE,
	REQUEST_FRAME,
	REQUEST_SGL,
	REQUEST_DATA,
	REPLY_DESC,
	REPLY_FRAME,
};

enum sge_type {
	SGE_NONE,
	SGE_MPI,
};

/**
 * pcap_init_ghdr - init pcap grobal header
 * @ioc:	mpi3mr_ioc object
 */
void pcap_init_ghdr(struct mpi3mr_ioc *ioc)
{
	pcap_hdr_t *ghdr = (pcap_hdr_t *) ioc->mpi_blob;
	ghdr->magic_number = cpu_to_le32(0xa1b2c3d4);
	
	/* v2.4 */
	ghdr->version_major = cpu_to_le16(0x0002);
	ghdr->version_minor = cpu_to_le16(0x0004);
	ghdr->thiszone = 0;
	ghdr->sigfigs = 0;
	/* max captured len is 1MB */
	ghdr->snaplen = cpu_to_le32(MAX_PACKET_SZ);
	/* LINKTYPE_NULL */
	ghdr->network = 0;
	ioc->mpi_blob_sz = sizeof(pcap_hdr_t);
}

/**
 * pcap_add_phdr - add pcap packet header
 * @incl_len:	the number of bytes of packet data actually saved in the file
 * @orig_len:	the number of bytes of packet data captured
 * @ioc:		mpi3mr_ioc object
 * return:		this pcap packet header pointer
 */
static pcaprec_hdr_t *pcap_add_phdr(struct mpi3mr_ioc *ioc, u32 incl_len,
				    u32 orig_len)
{
	struct timespec64 kt;
	pcaprec_hdr_t *phdr =
	    (pcaprec_hdr_t *) (ioc->mpi_blob + ioc->mpi_blob_sz);

	ktime_get_real_ts64(&kt);
	phdr->ts_sec = cpu_to_le32(kt.tv_sec);
	phdr->ts_usec = cpu_to_le32((u32) (kt.tv_nsec / 1000));
	phdr->incl_len = cpu_to_le32(incl_len);
	phdr->orig_len = cpu_to_le32(orig_len);
	ioc->mpi_blob_sz += sizeof(pcaprec_hdr_t);
	return phdr;
}

/**
 * append_to_blob - append data to blob buffer
 * @ioc:		mpi3mr_ioc object
 * @type:		data type
 * @orig_len:	data captured length
 * @data:		data
 * @pkt_hdr:	the packet header pointer to append
 * return:  	number of bytes sucess saved.
 */
static int append_to_blob(struct mpi3mr_ioc *ioc, u8 type, u32 orig_len,
			  void *data, pcaprec_hdr_t * pkt_hdr)
{
	void *buffer;
	u32 type_len;
	u32 pkt_incl_len = le32_to_cpu(pkt_hdr->incl_len);
	u32 pkt_orig_len = le32_to_cpu(pkt_hdr->orig_len);
	u32 incl_len = orig_len;
	if (incl_len + pkt_incl_len > MAX_PACKET_SZ) {
		incl_len = MAX_PACKET_SZ - pkt_incl_len;
		if (incl_len < 0) {
			pr_err("%s: packet full, can't append\n", __func__);
			return 0;
		}
	}

	if ((ioc->mpi_blob_sz + incl_len + 4) > MAX_BUF_SZ) {
		dev_err(&ioc->pdev->dev,
			"data overflow, go back to the head of the buffer\n");
		ioc->mpi_blob_sz = sizeof(pcap_hdr_t);
	}

	buffer = ioc->mpi_blob;
	type_len = cpu_to_le32((type << 24) | incl_len);
	memcpy(buffer + ioc->mpi_blob_sz, &type_len, 4);
	ioc->mpi_blob_sz += 4;
	memcpy(buffer + ioc->mpi_blob_sz, data, incl_len);
	ioc->mpi_blob_sz += incl_len;
	/* update packet length */
	/* four extra bytes for type_len */
	pkt_hdr->incl_len = cpu_to_le32(pkt_incl_len + incl_len + 4);
	pkt_hdr->orig_len = cpu_to_le32(pkt_orig_len + orig_len + 4);
	return incl_len;
}

/**
 * save_to_blob - save data to blob buffer
 * @ioc:		mpi3mr_ioc object
 * @type:		sge type & data type
 * @orig_len:	data captured length
 * @data:		data
 * @pkt_hdr:	return last packet header pointer
 * return:  	number of bytes sucess saved.
 */
static int save_to_blob(struct mpi3mr_ioc *ioc, u8 type, u32 orig_len,
			void *data, pcaprec_hdr_t ** pkt_hdr)
{
	void *buffer;
	u32 mpi_magic;
	u32 type_len;
	u32 incl_len = orig_len;

	if (incl_len > MAX_PACKET_SZ) {
		incl_len = MAX_PACKET_SZ;
	}

	if ((ioc->mpi_blob_sz + incl_len + 8 + sizeof(pcaprec_hdr_t)) >
	    MAX_BUF_SZ) {
		dev_err(&ioc->pdev->dev,
			"data overflow, go back to the head of the buffer\n");
		ioc->mpi_blob_sz = sizeof(pcap_hdr_t);
	}

	/* eight extra bytes for mpi-magic-number and type_len */
	if (pkt_hdr) {
		*pkt_hdr = pcap_add_phdr(ioc, incl_len + 8, orig_len + 8);
	} else {
		pcap_add_phdr(ioc, incl_len + 8, orig_len + 8);
	}

	buffer = ioc->mpi_blob;
	mpi_magic = cpu_to_le32(MPI_MAGIC);
	memcpy(buffer + ioc->mpi_blob_sz, &mpi_magic, 4);
	ioc->mpi_blob_sz += 4;
	type_len = cpu_to_le32((type << 24) | incl_len);
	memcpy(buffer + ioc->mpi_blob_sz, &type_len, 4);
	ioc->mpi_blob_sz += 4;
	memcpy(buffer + ioc->mpi_blob_sz, data, incl_len);
	ioc->mpi_blob_sz += incl_len;

	return incl_len;
}

/**
 * analyse_sge - analyse sg element, return data type(REQUEST_SGL or REQUEST_DATA),it's addr and len 
 * @sge:			the sg element to be analysed
 * @sge_type: 		sge format type
 * @data_addr:		return data virtual addr
 * @len:			return data len
 * @end: 			return the sge is last or not 
 * return data type
 */
static u8 analyse_sge(void *sge, u8 sge_type, void **data_addr, u32 * len,
		      u8 * end)
{
	struct mpi3_sge_common* mpi_sge;	

	u8 data_type = NONE;

	mpi_sge=(struct mpi3_sge_common*)sge;

	//获取长度和地址
	*len =le32_to_cpu(mpi_sge->length);
	*data_addr =bus_to_virt(le64_to_cpu(mpi_sge->address));

	switch (sge_type) {
	case SGE_MPI:
		switch (mpi_sge->flags & MPI3_SGE_FLAGS_ELEMENT_TYPE_MASK) {
		case MPI3_SGE_FLAGS_ELEMENT_TYPE_SIMPLE:
			data_type = REQUEST_DATA;
			if ((le16_to_cpu(mpi_sge->flags)&
			    MPI3_SGE_FLAGS_END_OF_LIST)) {
				*end = 1;
			}
			break;
		case MPI3_SGE_FLAGS_ELEMENT_TYPE_LAST_CHAIN:
			data_type = REQUEST_SGL;
			break;
		default:
			pr_err("%s: unknow sge elemnt type\n", __func__);
			break;
		}
		break;
	default:
		pr_err("%s: unknow sge format\n", __func__);
		break;
	}
	return data_type;
}

/**
 * trace_sgl_iodata - trace sgl and io data of request frame.
 * @ioc:			mpi3mr_ioc object
 * @mpi_request:	request frame
 * @sge_type: 		sge format type
 * @pkt_hdr:		the packet header pointer to append
 */
static void
trace_sgl_iodata(struct mpi3mr_ioc *ioc,
		 void * mpi_request, u8 sge_type,
		 pcaprec_hdr_t * pkt_hdr)
{
	struct mpi3_scsi_io_request *scsiio_request =
	    (struct mpi3_scsi_io_request *) mpi_request;
	void *data_addr = NULL;
	u32 len = 0;
	u32 meta_sg = le32_to_cpu(scsiio_request->flags) &
	    MPI3_SCSIIO_FLAGS_DMAOPERATION_HOST_PI;
	void *sge=NULL;
	u8 stop = 0;
	u16 sge_size =sizeof(struct mpi3_sge_common);
	u8 data_type = 0;
	
	
	if (meta_sg)
		sge = &scsiio_request->sgl[MPI3_SCSIIO_METASGL_INDEX];
	else
		sge = &scsiio_request->sgl;

	if (scsiio_request->sgl[0].eedp.flags ==
			MPI3_SGE_FLAGS_ELEMENT_TYPE_EXTENDED &&
		!meta_sg)
	{
		sge += sizeof(struct mpi3_sge_common);
		/* Reserve 1st segment (scsiio_req->sgl[0]) for eedp */
	}

	do {
		data_type = analyse_sge(sge, sge_type, &data_addr, &len, &stop);
		/* get next sge */
		if (data_type == REQUEST_DATA) {
			append_to_blob(ioc, data_type, len, data_addr, pkt_hdr);
			sge += sge_size;
		} else if (data_type == REQUEST_SGL) {
			sge = data_addr;
		} else {
			break;
		}
	} while (!stop);
}

/**
 * trace_sgl_factdata - trace sgl and data of fact request frame.
 * @ioc:			mpi3mr_ioc object
 * @mpi_request:	request frame
 * @pkt_hdr:		the packet header pointer to append
 */
static void trace_sgl_factdata(struct mpi3mr_ioc *ioc,
		 void * mpi_request, u8 sge_type,
		 pcaprec_hdr_t * pkt_hdr)
{
	struct mpi3_ioc_facts_request *fact_req=NULL;
	void *data_addr = NULL;
	u32 len = 0;
	struct mpi3_sge_common* sge=NULL;		
	fact_req = (struct mpi3_ioc_facts_request *)mpi_request;
	
	sge=(struct mpi3_sge_common*)&fact_req->sgl;

	//获取地址和长度
	if(sge)
	{
		data_addr=bus_to_virt(le64_to_cpu(sge->address));
		len=le64_to_cpu(sge->length);
	}

	if(len)
		append_to_blob(ioc,REQUEST_DATA,len,data_addr,pkt_hdr);
}

static void trace_sgl_ci_download_data(struct mpi3mr_ioc *ioc,
		 void * mpi_request, u8 sge_type,
		 pcaprec_hdr_t * pkt_hdr)
{
	struct mpi3_ci_download_request* ci_dowmnload_req=NULL;
	void *data_addr = NULL;
	u32 len = 0;
	struct mpi3_sge_common* sge=NULL;		
	ci_dowmnload_req = (struct mpi3_ci_download_request *)mpi_request;
	sge=(struct mpi3_sge_common*)&ci_dowmnload_req->sgl;

	//获取地址和长度
	if(sge)
	{
		data_addr=bus_to_virt(le64_to_cpu(sge->address));
		len=le64_to_cpu(sge->length);
	}

	if(len)
		append_to_blob(ioc,REQUEST_DATA,len,data_addr,pkt_hdr);
	
}

static void trace_sgl_ci_upload_data(struct mpi3mr_ioc *ioc,
		 void * mpi_request, u8 sge_type,
		 pcaprec_hdr_t * pkt_hdr)
{
	struct mpi3_ci_upload_request* ci_upload_req =NULL;
	void *data_addr = NULL;
	u32 len = 0;
	struct mpi3_sge_common* sge=NULL;		
	ci_upload_req = (struct mpi3_ci_upload_request *)mpi_request;
	sge=(struct mpi3_sge_common*)&ci_upload_req->sgl;

	//获取地址和长度
	if(sge)
	{
		data_addr=bus_to_virt(le64_to_cpu(sge->address));
		len=le64_to_cpu(sge->length);
	}

	if(len)
		append_to_blob(ioc,REQUEST_DATA,len,data_addr,pkt_hdr);
}

static void trace_sgl_congig_data(struct mpi3mr_ioc *ioc,
		 void * mpi_request, u8 sge_type,
		 pcaprec_hdr_t * pkt_hdr)		
{
	struct mpi3_config_request* config_req =NULL;
	void *data_addr = NULL;
	u32 len = 0;
	struct mpi3_sge_common* sge=NULL;		
	config_req = (struct mpi3_config_request *)mpi_request;
	sge=(struct mpi3_sge_common*)&config_req->sgl;

	//获取地址和长度
	if(sge)
	{
		data_addr=bus_to_virt(le64_to_cpu(sge->address));
		len=le64_to_cpu(sge->length);
	}

	if(len)
		append_to_blob(ioc,REQUEST_DATA,len,data_addr,pkt_hdr);
}

static void trace_sgl_smp_passthrough_data(struct mpi3mr_ioc *ioc,
		 void * mpi_request, u8 sge_type,
		 pcaprec_hdr_t * pkt_hdr)
{
	struct mpi3_smp_passthrough_request* smp_pass_req=NULL;
	void *data_addr = NULL;
	u32 len = 0;	
	struct mpi3_sge_common* sge=NULL;
	smp_pass_req = (struct mpi3_smp_passthrough_request *)mpi_request;
	sge=(struct mpi3_sge_common*)&smp_pass_req->request_sge;
	//获取地址和长度
	if(sge)
	{
		data_addr=bus_to_virt(le64_to_cpu(sge->address));
		len=le64_to_cpu(sge->length);
	}
	if(len)
		append_to_blob(ioc,REQUEST_DATA,len,data_addr,pkt_hdr);
	
	sge=(struct mpi3_sge_common*)&smp_pass_req->response_sge;
	//获取地址和长度
	if(sge)
	{
		data_addr=bus_to_virt(le64_to_cpu(sge->address));
		len=le64_to_cpu(sge->length);
	}
	if(len)
		append_to_blob(ioc,REQUEST_DATA,len,data_addr,pkt_hdr);

}

// static void trace_sgl_data(struct mpi3mr_ioc *ioc,
// 		 void * mpi_request, u8 sge_type,
// 		 pcaprec_hdr_t * pkt_hdr)
// {

// }


/**
 * trace_config_page - trace config page of request frame.
 * @ioc:			mpi3mr_ioc object
 * @mpi_request:	request frame
 * @sge_type: 		sge format type
 * @pkt_hdr:		the packet header pointer to append
 */
// static void
// trace_upload_fw(struct mpi3mr_ioc *ioc,
// 		struct mpi3_request_header * mpi_request, u8 sge_type,
// 		pcaprec_hdr_t * pkt_hdr)
// {
// 	u32 len;
// 	dma_addr_t fw_data_dma;
// 	struct mpi3_sge_common  *mpi_sge;
// 	struct mpi3_sge_common  *ieee_sge;
// 	Mpi25FWUploadRequest_t *upfw_request =
// 	    (Mpi25FWUploadRequest_t *) mpi_request;

// 	switch (sge_type) {
// 	case SGE_MPI:
// 		mpi_sge = (struct mpi3_sge_common  *) & upfw_request->SGL;
// 		len = le32_to_cpu(mpi_sge->FlagsLength) & MPI2_SGE_LENGTH_MASK;
// 		fw_data_dma = le64_to_cpu(mpi_sge->Address);
// 		break;
// 	case SGE_IEEE:
// 		ieee_sge = (struct mpi3_sge_common  *) & upfw_request->SGL;
// 		len = le32_to_cpu(ieee_sge->Length);
// 		fw_data_dma = le64_to_cpu(ieee_sge->Address);
// 		break;
// 	default:
// 		pr_err("%s: unknow sge format\n", __func__);
// 		break;
// 	}

// 	if (len) {
// 		void *fw_data_buffer = bus_to_virt(fw_data_dma);
// 		append_to_blob(ioc, REQUEST_DATA, len, fw_data_buffer, pkt_hdr);
// 	}

// }

/**
 * trace_smp_data - trace smp data of request frame.
 * @ioc:			mpi3mr_ioc object
 * @mpi_request:	request frame
 * @sge_type: 		sge format type
 * @pkt_hdr:		the packet header pointer to append
 */
// static void
// trace_smp_data(struct mpi3mr_ioc *ioc,
// 	       struct mpi3_request_header * mpi_request, u8 sge_type,
// 	       pcaprec_hdr_t * pkt_hdr)
// {
// 	void *data_addr = NULL;
// 	u32 len = 0;
// 	u8 stop = 0;
// 	u8 data_type = 0;
// 	Mpi2SmpPassthroughRequest_t *smp_request =
// 	    (Mpi2SmpPassthroughRequest_t *) mpi_request;
// 	void *sge = &smp_request->SGL;

// 	/* not immediate mode  */
// 	if (!(smp_request->PassthroughFlags &
// 	      MPI2_SMP_PT_REQ_PT_FLAGS_IMMEDIATE)) {
// 		data_type = analyse_sge(sge, sge_type, &data_addr, &len, &stop);
// 		if (data_type == REQUEST_DATA) {
// 			append_to_blob(ioc, data_type, len, data_addr, pkt_hdr);
// 		}
// 	}
// }

/**
 * trace_sata_data - trace sata data of request frame.
 * @ioc:			mpi3mr_ioc object
 * @mpi_request:	request frame
 * @sge_type: 		sge format type
 * @pkt_hdr:		the packet header pointer to append
 */
// static void
// trace_sata_data(struct mpi3mr_ioc *ioc,
// 		struct mpi3_request_header * mpi_request, u8 sge_type,
// 		pcaprec_hdr_t * pkt_hdr)
// {
// 	Mpi2SataPassthroughRequest_t *sata_request =
// 	    (Mpi2SataPassthroughRequest_t *) mpi_request;
// 	void *data_addr = NULL;
// 	u32 len = 0;
// 	void *sge = &sata_request->SGL;
// 	u8 stop = 0;
// 	u16 sge_size =sizeof(struct mpi3_sge_common);
// 	u8 data_type = 0;
// 	do {
// 		data_type = analyse_sge(sge, sge_type, &data_addr, &len, &stop);
// 		/* get next sge */
// 		if (data_type == REQUEST_DATA) {
// 			append_to_blob(ioc, data_type, len, data_addr, pkt_hdr);
// 			sge += sge_size;
// 		} else if (data_type == REQUEST_SGL) {
// 			sge = data_addr;
// 		} else {
// 			break;
// 		}
// 	} while (!stop);
// }

/**
 * trace_reqfm_sge_data - trace request frame and it's related SGE and data .
 * @ioc:			mpi3mr_ioc object
 * @mpi_request:	request frame
 */
static void
trace_reqfm_sge_data(struct mpi3mr_ioc *ioc,
		     struct mpi3_request_header* mpi_request)
{
	/**
	 *  ieee sge addr must be 64-bit
	 *  ref : ioc->sge_size_ieee = sizeof(Mpi2IeeeSgeSimple64_t); -- mpt3sas_base.c 
	 *  mpi sge just consider as 64-bit
	 * */
	pcaprec_hdr_t *pkt_hdr;

	u8 sge_type=SGE_MPI;
	/* todo, now only trace config page */
	switch (mpi_request->function) {
	case MPI3_FUNCTION_SCSI_IO:
		save_to_blob(ioc, ((sge_type << 4) | REQUEST_FRAME),
			     MPI3MR_ADMIN_REQ_FRAME_SZ, mpi_request, &pkt_hdr);
		trace_sgl_iodata(ioc, mpi_request, sge_type, pkt_hdr);
		break;
	case MPI3_FUNCTION_IOC_FACTS:
		save_to_blob(ioc, (sge_type << 4 | REQUEST_FRAME),
					 sizeof(struct mpi3_ioc_facts_request), mpi_request, &pkt_hdr);
		trace_sgl_factdata(ioc, mpi_request, sge_type, pkt_hdr);
		break;
	case MPI3_FUNCTION_IOC_INIT:
		save_to_blob(ioc, (REQUEST_FRAME),
					 sizeof(struct mpi3_ioc_init_request), mpi_request, &pkt_hdr);
		break;
	case MPI3_FUNCTION_PORT_ENABLE:
		save_to_blob(ioc, (REQUEST_FRAME),
					 sizeof(struct mpi3_port_enable_request), mpi_request, &pkt_hdr);
		break;
	case MPI3_FUNCTION_EVENT_NOTIFICATION:
		save_to_blob(ioc, (REQUEST_FRAME),
					 sizeof(struct mpi3_event_notification_request), mpi_request, &pkt_hdr);
		break;
	case MPI3_FUNCTION_EVENT_ACK:
		save_to_blob(ioc, (REQUEST_FRAME),
					 sizeof(struct mpi3_event_ack_request), mpi_request, &pkt_hdr);
		break;
	case MPI3_FUNCTION_CI_DOWNLOAD:
		save_to_blob(ioc, ((sge_type << 4) | REQUEST_FRAME),
					 sizeof(struct mpi3_ci_download_request), mpi_request, &pkt_hdr);
		trace_sgl_ci_download_data(ioc, mpi_request, sge_type, pkt_hdr);			
		break;
	case MPI3_FUNCTION_CI_UPLOAD:
		save_to_blob(ioc, ((sge_type << 4) | REQUEST_FRAME),
					 sizeof(struct mpi3_ci_upload_request), mpi_request, &pkt_hdr);
		trace_sgl_ci_upload_data(ioc, mpi_request, sge_type, pkt_hdr);			
		break;
	case MPI3_FUNCTION_IO_UNIT_CONTROL:
		save_to_blob(ioc, (REQUEST_FRAME),
					 sizeof(struct mpi3_iounit_control_request), mpi_request, &pkt_hdr);
		break;
	case MPI3_FUNCTION_PERSISTENT_EVENT_LOG:																		//---------------------------------
		save_to_blob(ioc, (REQUEST_FRAME),
					 sizeof(struct mpi3_event_notification_request), mpi_request, &pkt_hdr);
		break;
	case MPI3_FUNCTION_MGMT_PASSTHROUGH:
		save_to_blob(ioc, (REQUEST_FRAME),
					 sizeof(struct mpi3_mgmt_passthrough_request), mpi_request, &pkt_hdr);
		break;
	case MPI3_FUNCTION_CONFIG:
		save_to_blob(ioc, ((sge_type << 4) | REQUEST_FRAME),
					 sizeof(struct mpi3_config_request), mpi_request, &pkt_hdr);
		trace_sgl_congig_data(ioc, mpi_request, sge_type, pkt_hdr);			
		break;
	case MPI3_FUNCTION_SCSI_TASK_MGMT:
		save_to_blob(ioc, (REQUEST_FRAME),
					 sizeof(struct mpi3_scsi_task_mgmt_request), mpi_request, &pkt_hdr);
		break;
	case MPI3_FUNCTION_SMP_PASSTHROUGH:
		save_to_blob(ioc, (REQUEST_FRAME),
					 sizeof(struct mpi3_smp_passthrough_request), mpi_request, &pkt_hdr);
		trace_sgl_smp_passthrough_data(ioc, mpi_request, sge_type, pkt_hdr);	
		break;
	// case MPI3_FUNCTION_NVME_ENCAPSULATED:
	// 	save_to_blob(ioc, (REQUEST_FRAME),
	// 				 sizeof(struct mpi3_event_notification_request), mpi_request, &pkt_hdr);
	// 	break;
	// case MPI3_FUNCTION_TARGET_ASSIST:
	// 	save_to_blob(ioc, (REQUEST_FRAME),
	// 				 sizeof(struct mpi3_event_notification_request), mpi_request, &pkt_hdr);
	// 	break;
	// case MPI3_FUNCTION_TARGET_STATUS_SEND:
	// 	save_to_blob(ioc, (REQUEST_FRAME),
	// 				 sizeof(struct mpi3_event_notification_request), mpi_request, &pkt_hdr);
	// 	break;
	// case MPI3_FUNCTION_TARGET_MODE_ABORT:
	// 	save_to_blob(ioc, (REQUEST_FRAME),
	// 				 sizeof(struct mpi3_event_notification_request), mpi_request, &pkt_hdr);
	// 	break;
	// case MPI3_FUNCTION_TARGET_CMD_BUF_POST_BASE:
	// 	save_to_blob(ioc, (REQUEST_FRAME),
	// 				 sizeof(struct mpi3_event_notification_request), mpi_request, &pkt_hdr);
	// 	break;
	// case MPI3_FUNCTION_TARGET_CMD_BUF_POST_LIST:
	// 	save_to_blob(ioc, (REQUEST_FRAME),
	// 				 sizeof(struct mpi3_event_notification_request), mpi_request, &pkt_hdr);
	// 	break;
	case MPI3_FUNCTION_CREATE_REQUEST_QUEUE:
		save_to_blob(ioc, (REQUEST_FRAME),
					 sizeof(struct mpi3_create_request_queue_request), mpi_request, &pkt_hdr);
		break;
	case MPI3_FUNCTION_DELETE_REQUEST_QUEUE:
		save_to_blob(ioc, (REQUEST_FRAME),
					 sizeof(struct mpi3_delete_request_queue_request), mpi_request, &pkt_hdr);
		break;
	case MPI3_FUNCTION_CREATE_REPLY_QUEUE:
		save_to_blob(ioc, (REQUEST_FRAME),
					 sizeof(struct mpi3_create_reply_queue_request), mpi_request, &pkt_hdr);
		break;
	case MPI3_FUNCTION_DELETE_REPLY_QUEUE:
		save_to_blob(ioc, (REQUEST_FRAME),
					 sizeof(struct mpi3_delete_reply_queue_request), mpi_request, &pkt_hdr);
		break;
	// case MPI3_FUNCTION_TOOLBOX:
	// 	save_to_blob(ioc, (REQUEST_FRAME),
	// 				 sizeof(struct mpi3_event_notification_request), mpi_request, &pkt_hdr);
	// 	break;
	// case MPI3_FUNCTION_DIAG_BUFFER_POST:
	// 	save_to_blob(ioc, (REQUEST_FRAME),
	// 				 sizeof(struct mpi3_event_notification_request), mpi_request, &pkt_hdr);
	// 	break;
	// case MPI3_FUNCTION_DIAG_BUFFER_MANAGE:
	// 	save_to_blob(ioc, (REQUEST_FRAME),
	// 				 sizeof(struct mpi3_event_notification_request), mpi_request, &pkt_hdr);
	// 	break;
	// case MPI3_FUNCTION_DIAG_BUFFER_UPLOAD:
	// 	save_to_blob(ioc, (REQUEST_FRAME),
	// 				 sizeof(struct mpi3_event_notification_request), mpi_request, &pkt_hdr);
	// 	break;
	// case MPI3_FUNCTION_MIN_IOC_USE_ONLY:
	// 	save_to_blob(ioc, (REQUEST_FRAME),
	// 				 sizeof(struct mpi3_event_notification_request), mpi_request, &pkt_hdr);
	// 	break;
	// case MPI3_FUNCTION_MAX_IOC_USE_ONLY:
	// 	save_to_blob(ioc, (REQUEST_FRAME),
	// 				 sizeof(struct mpi3_event_notification_request), mpi_request, &pkt_hdr);
	// 	break;
	// case MPI3_FUNCTION_MIN_PRODUCT_SPECIFIC:
	// 	save_to_blob(ioc, (REQUEST_FRAME),
	// 				 sizeof(struct mpi3_event_notification_request), mpi_request, &pkt_hdr);
	// 	break;
	// case MPI3_FUNCTION_MAX_PRODUCT_SPECIFIC:
	// 	save_to_blob(ioc, (REQUEST_FRAME),
	// 				 sizeof(struct mpi3_event_notification_request), mpi_request, &pkt_hdr);
	// 	break;
	default:
		save_to_blob(ioc, REQUEST_FRAME,
					 MPI3MR_ADMIN_REQ_FRAME_SZ, mpi_request, NULL);
		pr_err("%s: unknow function, function code = %d\n", __func__,
			   mpi_request->function);
		break;
	}
}

/**
 * trace_mpi - trace a reply-descriptor and related request-frame,sgl,data,reply-frame
 * @ioc:	mpi3mr_ioc object
 * @rpf:	ReplyDescriptor to be trace
 */
void trace_mpi(struct mpi3mr_ioc *ioc, union mpi3_reply_descriptors_union * rpf,u16 qidx)
{
	// u16 host_tag;
	// struct mpi3_scsi_io_request* scsiio_req = NULL;
	// struct scsi_cmnd *scmd = NULL;
	// struct scmd_priv *priv = NULL;
	
	u64 reply_dma;		//回复地址
	u16 request_descript_type;
	struct mpi3_default_reply_descriptor* def_reply=NULL;
	struct mpi3_request_header* req_head=NULL;
	struct mpi3_default_reply* default_reply=NULL;

	//存放数据的空间
	if (!ioc->mpi_blob) {
		return;
	}

	request_descript_type = le16_to_cpu(rpf->default_reply.reply_flags) &
	MPI3_REPLY_DESCRIPT_FLAGS_TYPE_MASK;
	/* only have reply, no request. For example, event data. */
	if (request_descript_type ==
	    	MPI3_REPLY_DESCRIPT_FLAGS_TYPE_TARGET_COMMAND_BUFFER) {
	goto reply;
	}
	/*
		中断处理:
		mpi3mr_process_admin_reply_q
		mpi3mr_process_op_reply_q
		上述两种处理方式获取请求的方法不一致
	*/

	//为admin模式处理
	if(ioc->is_admin)
	{
		req_head=(struct mpi3_request_header*)ioc->admin_req_base +
	    ((ioc->admin_req_pi-1) * MPI3MR_ADMIN_REQ_FRAME_SZ);
	}
	else{
		//获取host_tag
		// host_tag = le16_to_cpu(rpf->default_reply.descriptor_type_dependent2);
		struct segments *segments=NULL;
		u16 req_q_idx=0;
		struct op_req_qinfo *op_req_q=NULL;			//请求队列
		void *data_addr=NULL;
		struct op_reply_qinfo* op_reply_q=NULL;		//回复队列
		struct mpi3_default_reply_descriptor *reply_desc=NULL;
		void *segment_base_addr=NULL;
		/*
		reply_q
		获取请求帧
		1.获取scmd
		2.获取私有部分数据
		3.从私有数据中获取请求帧数据
	 	*/
		// scmd = mpi3mr_scmd_from_host_tag(ioc, host_tag, qidx);
		// priv = scsi_cmd_priv(scmd);
		// req_head = (struct mpi3_request_header*)priv->mpi3mr_scsiio_req;
		
		//获取回复队列
		op_reply_q=ioc->intr_info[qidx+1].op_reply_q;
		segment_base_addr = segments[op_reply_q->ci / op_reply_q->segment_qd].segment;
		reply_desc = (struct mpi3_default_reply_descriptor *)segment_base_addr +
	    (op_reply_q->ci % op_reply_q->segment_qd);

		req_q_idx = le16_to_cpu(reply_desc->request_queue_id) - 1;

		op_req_q = &ioc->req_qinfo[req_q_idx];
		
		segments=op_req_q->q_segments;

		//取道请求帧的起始地址
		data_addr=segments[(op_req_q->pi-1) / op_req_q->segment_qd].segment+(((op_req_q->pi-1) % op_req_q->segment_qd) * ioc->facts.op_req_sz);
	
		req_head=(struct mpi3_request_header*)data_addr;
	}

	trace_reqfm_sge_data(ioc,req_head);
	
reply:
	/* reply */

	//todo: save_to_blol第三个参数 还需要更改
	if (request_descript_type == MPI3_REPLY_DESCRIPT_FLAGS_TYPE_ADDRESS_REPLY) {
		reply_dma = le64_to_cpu(rpf->address_reply.reply_frame_address);
		def_reply = mpi3mr_get_reply_virt_addr(ioc, reply_dma);
		save_to_blob(ioc, REPLY_FRAME, ioc->facts.reply_sz,
			     (void *)default_reply, NULL);
	}

	/* reply descriptor */
	save_to_blob(ioc, REPLY_DESC, 16, (void *)rpf, NULL);
}

/*
 * _debugfs_mpidump_read - copy mpi dump from debugfs buffer
 * @filep:	File Pointer
 * @ubuf:	Buffer to fill data
 * @cnt:	Length of the buffer
 * @ppos:	Offset in the file
 */

static ssize_t
_debugfs_mpidump_read(struct file *filp, char __user * ubuf, size_t cnt,
		      loff_t * ppos)
{
	struct mpt3sas_debugfs_buffer *debug = filp->private_data;

	if (!debug || !debug->buf)
		return 0;

	return simple_read_from_buffer(ubuf, cnt, ppos, debug->buf, debug->len);
}

/*
 * _debugfs_mpidump_open :	open the mpi_dump debugfs attribute file
 */
static int _debugfs_mpidump_open(struct inode *inode, struct file *file)
{
	struct mpi3mr_ioc *ioc = inode->i_private;
	struct mpt3sas_debugfs_buffer *debug;

	debug = kzalloc(sizeof(struct mpt3sas_debugfs_buffer), GFP_KERNEL);
	if (!debug)
		return -ENOMEM;

	debug->buf = ioc->mpi_blob;
	debug->len = ioc->mpi_blob_sz;
	file->private_data = debug;

	return 0;
}

static loff_t _debugfs_mpidump_llseek(struct file *file, loff_t off, int whence)
{
	loff_t newpos = 0;
	struct mpt3sas_debugfs_buffer *debug = file->private_data;

	if (!debug)
		return -EINVAL;

	switch (whence) {
	case SEEK_SET:
		newpos = off;
		break;
	case SEEK_CUR:
		newpos = file->f_pos + off;
		break;
	case SEEK_END:
		newpos = debug->len - off;
		break;
	default:		/* can't happen */
		return -EINVAL;
	}
	if (newpos < 0)
		return -EINVAL;
	file->f_pos = newpos;

	return newpos;
}

/*
 * _debugfs_mpidump_release :	release the mpi_dump debugfs attribute
 * @inode: inode structure to the corresponds device
 * @file: File pointer
 */
static int _debugfs_mpidump_release(struct inode *inode, struct file *file)
{
	struct mpt3sas_debugfs_buffer *debug = file->private_data;

	if (!debug)
		return 0;

	file->private_data = NULL;
	kfree(debug);
	return 0;
}

static const struct file_operations leapio_debugfs_mpidump_fops = {
	.owner = THIS_MODULE,
	.open = _debugfs_mpidump_open,
	.read = _debugfs_mpidump_read,
	.llseek = _debugfs_mpidump_llseek,
	.release = _debugfs_mpidump_release,
};

/*
 * leapio_init_debugfs :	Create debugfs root for debug mpi
 */
void leapio_init_debugfs(void)
{
	leapio_mpi_root = debugfs_create_dir("leapio_mpi", NULL);
	if (!leapio_mpi_root)
		pr_info("leapio: Cannot create debugfs root\n");
}

/*
 * leapio_exit_debugfs :	Remove debugfs root for debug mpi
 */
void leapio_exit_debugfs(void)
{
	debugfs_remove_recursive(leapio_mpi_root);
}

/*
 * leapio_setup_debugfs :	Setup debugfs per HBA adapter
 * ioc:				mpi3mr_ioc object
 */
void leapio_setup_debugfs(struct mpi3mr_ioc *ioc)
{
	char name[64];

	ioc->mpi_blob_sz = 0;
	ioc->mpi_blob = vmalloc(MAX_BUF_SZ);
	if (!ioc->mpi_blob) {
		dev_err(&ioc->pdev->dev, "No memory for mpi_dump buffer\n");
		return;
	}

	pcap_init_ghdr(ioc);

	snprintf(name, sizeof(name), "mpi_dump%d.pcap", ioc->shost->host_no);
	ioc->mpi_dump = debugfs_create_file(name, 0444,
					    leapio_mpi_root, ioc,
					    &leapio_debugfs_mpidump_fops);
	if (!ioc->mpi_dump) {
		dev_err(&ioc->pdev->dev,
			"Cannot create %s debugfs file\n", name);
		return;
	}

}

/*
 * leapio_destroy_debugfs :	Remove debugfs for a HBA adapter
 */
void leapio_destroy_debugfs(struct mpi3mr_ioc *ioc)
{
	if (ioc->mpi_blob) {
		vfree(ioc->mpi_blob);
	}

	if (ioc->mpi_dump) {
		debugfs_remove(ioc->mpi_dump);
	}
}
