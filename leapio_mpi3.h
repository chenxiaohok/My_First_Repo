#ifndef LEAPIO_MPI3_H_INCLUDED
#define LEAPIO_MPI3_H_INCLUDED

#include <linux/debugfs.h>
#include <linux/time64.h>
#include "mpi3mr.h"
#include"./mpi/mpi30_init.h"

/**
 * pcap file format
*/
typedef struct pcap_hdr_s {
	uint32_t magic_number;	/* magic number */
	uint16_t version_major;	/* major version number */
	uint16_t version_minor;	/* minor version number */
	int32_t thiszone;	/* GMT to local correction */
	uint32_t sigfigs;	/* accuracy of timestamps */
	uint32_t snaplen;	/* max length of captured packets, in octets */
	uint32_t network;	/* data link type */
} pcap_hdr_t;

typedef struct pcaprec_hdr_s {
	uint32_t ts_sec;	/* timestamp seconds */
	uint32_t ts_usec;	/* timestamp microseconds */
	uint32_t incl_len;	/* number of octets of packet saved in file */
	uint32_t orig_len;	/* actual length of packet */
} pcaprec_hdr_t;


void trace_mpi(struct mpi3mr_ioc *ioc, union mpi3_reply_descriptors_union * rpf,u16 qidx);

void leapio_init_debugfs(void);
void leapio_exit_debugfs(void);

void leapio_setup_debugfs(struct mpi3mr_ioc *ioc);
void leapio_destroy_debugfs(struct mpi3mr_ioc *ioc);

#endif /* LEAPIO_MPI_H_INCLUDED */
