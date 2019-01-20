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

int mmc_cmd(int fd, unsigned int opcode, unsigned int arg, int flags, char const*const data, unsigned int len, unsigned int* response, int rlen) {
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

	if (response && rlen) {
		memcpy(response, idata.response, sizeof(idata.response) * (rlen%4));
	}

	return ret;
}

int mmc_change_lock(int fd, int lock, char const*const password, int len) {
	char data[512];
	unsigned int response;

	if (len < 1 || len > 16) {
		printf("Invalid password length: %d\n", len);
		return 0;
	}

	//set block length
	int ret = mmc_cmd(fd, MMC_CMD_BLKL, 512, MMC_RSP_R1 | MMC_RSP_SPI_R1 | MMC_CMD_AC, 0, 0, &response, 1);

	if (ret) {
		printf("set block length failed: %d\n", ret);
		return ret;
	}

	printf("Block length response %x\n", response);

	memset(data, 0xff, 512);
	
	data[0] = 0xFE;
	data[1] = lock ? 0x05 : 0x02;
	data[2] = len;
	memcpy(&(data[3]), password, len);

	ret = mmc_cmd(fd, MMC_CMD_LOCK, 0, MMC_RSP_R1 | MMC_RSP_SPI_R1 | MMC_CMD_ADTC, data, 512, &response, 1);	//set password

	printf("lock/unlock response %x\n", response);	

	if (!ret) {
		printf("lock/unlock failed: %d\n", ret);
	}

	return ret;
}

static int charToHex(char c) {
	if (c >= '0' && c <= '9') {
		return c - '0';
	} else if (c >= 'a' && c <= 'f') {
		return c - 'a' + 0xa;
	} else if (c >= 'A' && c <= 'F') {
		return c - 'A' + 0xA;
	} else {
		printf("Invalid character %c 0x%02.2x\n", c, c);
		return 0;
	}
}

static int readHex(char const * const in, char * const out, int olen) {
	int ilen = strlen(in);

	if ((olen << 1) < ilen) {
		printf("Hex output not large enough");
		return 0;
	}

	int len = 0;

	char const * ptr = in;

	while (*ptr) {
		out[len] = charToHex(*(ptr++));

		if (len > 0 || (ilen%2 == 0)) {
			out[len] = (out[len] << 4) + charToHex(*(ptr++));
		}

		len++;
	}

	return len;
}

int main(int argc, const char **argv) {

	if (argc != 4) { //check parameter length
		printf("Invalid parameter count\n");
		return -1;
	}

	// open device
	int fd = open(argv[2], O_RDWR);
	if (fd < 0){
		printf("Unable to open device %s\n", argv[2]);
		return -1;
	}

	char password[100];
	int len = readHex(argv[3], password, 100);

	printf("Password (len = %i): ", len);
	for (int i = 0; i < len; i++) {
		printf("%2.2x", password[i]);
	}
	printf("\n");

	//lock/unlock
	if (strcmp(argv[1], "lock") == 0) {\
		printf("trying to lock...\n");
		mmc_change_lock(fd, 1, password, len);
	} else if (strcmp(argv[1], "unlock") == 0) {
		printf("trying to unlock...\n");
		mmc_change_lock(fd, 0, password, len);
	} else {
		printf("Unknown parameter\n");
	}

	close(fd);

	return 0;
}

