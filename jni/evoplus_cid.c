#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "mmc.h"

#define MMC_CMD_BLKL 16  
#define MMC_CMD_LOCK 42  

int mmc_cmd(int fd, unsigned int opcode, unsigned int arg, int flags, char const*const data, char len) {
	int ret = 0;
	struct mmc_ioc_cmd idata = {0};

	idata.data_timeout_ns = 0x10000000;
	idata.write_flag = 1;
	idata.opcode = opcode;
	idata.arg = arg;
	idata.flags = flags;

	if (data && len) {
		idata.blksz = len;
		idata.blocks = 1;
		mmc_ioc_cmd_set_data(idata, data);
	}

	ret = ioctl(fd, MMC_IOC_CMD, &idata);

	return ret;
}

int mmc_change_lock(int fd, int lock, char const*const password) {
	char data[500];

	//set block size
	int ret = mmc_cmd(fd, MMC_CMD_BLKL, 512, MMC_RSP_R1 | MMC_RSP_SPI_R1 | MMC_CMD_AC, 0, 0);

	if (ret) {
		printf("set block length failed: %d\n", ret);
		return ret;
	}
	
	char len = strlen(password);
	
	data[0] = 0xFE;
	data[1] = lock ? 0x01 : 0x02;
	data[2] = len;
	memcpy(&(data[3]), password, len);
	data[len+3] = 0xff;
	data[len+4] = 0xff;

	ret = mmc_cmd(fd, MMC_CMD_LOCK, 0, MMC_RSP_R1 | MMC_RSP_SPI_R1 | MMC_CMD_ADTC, data, len+5);	//set password

	if (ret && lock) {
		data[1] = 0x04;
		mmc_cmd(fd, MMC_CMD_LOCK, 0, MMC_RSP_R1 | MMC_RSP_SPI_R1 | MMC_CMD_ADTC, data, len+5);	//set password
	}

	if (!ret) {
		printf("lock/unlock failed: %d\n", ret);
	}

	return ret;
}

int main(int argc, const char **argv) {
	int fd, ret, i, len;

	if (argc != 4) { //check parameter length
		printf("Invalid parameter count\n");
		return -1;
	}

	// open device
	fd = open(argv[2], O_RDWR);
	if (fd < 0){
		printf("Unable to open device %s\n", argv[2]);
		return -1;
	}

	//lock/unlock
	if (strcmp(argv[1], "lock") == 0) {\
		printf("trying to lock...\n");
		mmc_change_lock(fd, 1, argv[3]);
	} else if (strcmp(argv[1], "unlock") == 0) {
		printf("trying to unlock...\n");
		mmc_change_lock(fd, 0, argv[3]);
	} else {
		printf("Unknown parameter\n");
	}

	close(fd);

	return 0;
}

