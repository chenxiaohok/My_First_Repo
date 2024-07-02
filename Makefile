# mpi3mr makefile
obj-m += leapmr.o
leapmr-y +=  mpi3mr_os.o     \
		mpi3mr_fw.o \
		leapio_mpi3.o

KERNEL_DIR = /lib/modules/$(shell uname -r)/build
all:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules
init:
	sudo rmmod mpi3mr
install:
	sudo insmod leapmr
unintall:
	sudo rmmod leapmr
clean:
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
