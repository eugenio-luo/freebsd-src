#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netinet/in.h>

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define IPPROTO_SDTP		146
#define SDTP_CMSG_TYPE		1

#define SDTP_MAX_MESSAGE_LENGTH 1000000
#define SDTP_BPAGE_SHIFT	16
#define SDTP_BPAGE_SIZE		(1 << SDTP_BPAGE_SHIFT)
#define SDTP_MAX_BPAGES \
	((SDTP_MAX_MESSAGE_LENGTH + SDTP_BPAGE_SIZE - 1) >> SDTP_BPAGE_SHIFT)

#define SDTP_RECVMSG_REQUEST	 0x01
#define SDTP_RECVMSG_RESPONSE	 0x02
#define SDTP_RECVMSG_NONBLOCKING 0x04
#define SDTP_RECVMSG_VALID_FLAGS 0x07

struct sdtp_recvmsg_args {
	uint64_t id;
	uint64_t completion_cookie;
	int flags;
	uint32_t num_bpages;
	uint32_t _pad[2];
	uint32_t bpage_offsets[SDTP_MAX_BPAGES];
};

struct sdtp_sendmsg_args {
	uint64_t id;
	uint64_t completion_cookie;
};

union sdtp_send_cmsgbuf {
	struct cmsghdr hdr;
	unsigned char buf[CMSG_SPACE(sizeof(struct sdtp_sendmsg_args))];
};

union sdtp_recv_cmsgbuf {
	struct cmsghdr hdr;
	unsigned char buf[CMSG_SPACE(sizeof(struct sdtp_recvmsg_args))];
};

static void
usage(const char *prog)
{
	fprintf(stderr,
	    "Usage: %s -a <peer_ip> -p <peer_port> -m <message> "
	    "[-b <bind_ip>] [-l <local_port>] [-c cookie] [-t timeout_secs] "
	    "[-n count] [-q]\n"
	    "  -a peer IPv4 address\n"
	    "  -p peer port\n"
	    "  -m request payload\n"
	    "  -b local bind IPv4 address (default 0.0.0.0)\n"
	    "  -l local bind port (default 0)\n"
	    "  -c completion cookie base (default 1)\n"
	    "  -t receive timeout in seconds (default 5)\n"
	    "  -n number of request/response exchanges (default 1)\n"
	    "  -q quiet (do not print response payloads)\n",
	    prog);
}

static int
parse_u16(const char *s, uint16_t *value)
{
	char *end;
	unsigned long v;

	errno = 0;
	v = strtoul(s, &end, 10);
	if (errno != 0 || *end != '\0' || v > 65535)
		return (-1);

	*value = (uint16_t)v;
	return (0);
}

static int
parse_u64(const char *s, uint64_t *value)
{
	char *end;
	unsigned long long v;

	errno = 0;
	v = strtoull(s, &end, 10);
	if (errno != 0 || *end != '\0')
		return (-1);

	*value = (uint64_t)v;
	return (0);
}

static int
parse_int_range(const char *s, int minv, int maxv, int *value)
{
	char *end;
	long v;

	errno = 0;
	v = strtol(s, &end, 10);
	if (errno != 0 || *end != '\0' || v < minv || v > maxv)
		return (-1);

	*value = (int)v;
	return (0);
}

static int
extract_recv_args(struct msghdr *msg, struct sdtp_recvmsg_args *out)
{
	struct cmsghdr *cmsg;

	for (cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL;
	    cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level == IPPROTO_SDTP &&
		    cmsg->cmsg_type == SDTP_CMSG_TYPE &&
		    cmsg->cmsg_len >= CMSG_LEN(sizeof(*out))) {
			memcpy(out, CMSG_DATA(cmsg), sizeof(*out));
			return (0);
		}
	}

	return (-1);
}

static int
send_one(int fd, struct sockaddr_in *peer, char *message,
    uint64_t completion_cookie)
{
	union sdtp_send_cmsgbuf control;
	struct sdtp_sendmsg_args send_args;
	struct iovec iov;
	struct msghdr msg;
	struct cmsghdr *cmsg;
	ssize_t sent;
	size_t msglen;

	msglen = strlen(message);

	memset(&control, 0, sizeof(control));
	memset(&msg, 0, sizeof(msg));
	memset(&send_args, 0, sizeof(send_args));

	send_args.id = 0;
	send_args.completion_cookie = completion_cookie;

	iov.iov_base = message;
	iov.iov_len = msglen;

	msg.msg_name = peer;
	msg.msg_namelen = sizeof(*peer);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control.buf;
	msg.msg_controllen = sizeof(control.buf);

	cmsg = &control.hdr;
	cmsg->cmsg_level = IPPROTO_SDTP;
	cmsg->cmsg_type = SDTP_CMSG_TYPE;
	cmsg->cmsg_len = CMSG_LEN(sizeof(send_args));

	memcpy(CMSG_DATA(cmsg), &send_args, sizeof(send_args));

	sent = sendmsg(fd, &msg, 0);
	if (sent < 0) {
		perror("sendmsg(request)");
		return (-1);
	}
	if ((size_t)sent != msglen) {
		fprintf(stderr, "short send: sent=%zd expected=%zu\n", sent,
		    msglen);
		return (-1);
	}

	return (0);
}

static int
recv_one(int fd, int quiet, const char *expected_message)
{
	char data_buf[SDTP_MAX_MESSAGE_LENGTH];
	union sdtp_recv_cmsgbuf control;
	struct iovec iov;
	struct msghdr msg;
	struct sockaddr_in from;
	struct sdtp_recvmsg_args recv_args;
	ssize_t n;
	size_t expected_len;

	expected_len = strlen(expected_message);

	memset(&from, 0, sizeof(from));
	memset(&msg, 0, sizeof(msg));
	memset(&control, 0, sizeof(control));
	memset(&recv_args, 0, sizeof(recv_args));

	iov.iov_base = data_buf;
	iov.iov_len = sizeof(data_buf);

	msg.msg_name = &from;
	msg.msg_namelen = sizeof(from);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control.buf;
	msg.msg_controllen = sizeof(control.buf);

	n = recvmsg(fd, &msg, SDTP_RECVMSG_RESPONSE);
	if (n < 0) {
		perror("recvmsg(response)");
		return (-1);
	}

	if (extract_recv_args(&msg, &recv_args) != 0) {
		fprintf(stderr, "missing SDTP control message in response\n");
		return (-1);
	}

	if ((size_t)n != expected_len ||
	    memcmp(data_buf, expected_message, expected_len) != 0) {
		fprintf(stderr, "response payload mismatch\n");
		return (-1);
	}

	if (!quiet) {
		fwrite(data_buf, 1, (size_t)n, stdout);
		fputc('\n', stdout);
		fflush(stdout);
	}

	return (0);
}

int
main(int argc, char **argv)
{
	int ch;
	int fd;
	int quiet;
	int timeout_secs;
	int count;
	uint16_t peer_port;
	uint16_t local_port;
	uint64_t completion_cookie_base;
	char *peer_ip;
	const char *bind_ip;
	char *message;
	struct sockaddr_in local, peer;
	struct timeval tv;

	fd = -1;
	quiet = 0;
	timeout_secs = 5;
	count = 1;
	peer_port = 0;
	local_port = 0;
	completion_cookie_base = 1;
	peer_ip = NULL;
	bind_ip = "0.0.0.0";
	message = NULL;

	while ((ch = getopt(argc, argv, "a:p:m:b:l:c:t:n:q")) != -1) {
		switch (ch) {
		case 'a':
			peer_ip = optarg;
			break;
		case 'p':
			if (parse_u16(optarg, &peer_port) != 0) {
				fprintf(stderr, "invalid peer port: %s\n",
				    optarg);
				return (2);
			}
			break;
		case 'm':
			message = optarg;
			break;
		case 'b':
			bind_ip = optarg;
			break;
		case 'l':
			if (parse_u16(optarg, &local_port) != 0) {
				fprintf(stderr, "invalid local port: %s\n",
				    optarg);
				return (2);
			}
			break;
		case 'c':
			if (parse_u64(optarg, &completion_cookie_base) != 0) {
				fprintf(stderr,
				    "invalid completion cookie: %s\n", optarg);
				return (2);
			}
			break;
		case 't':
			if (parse_int_range(optarg, 1, 3600, &timeout_secs) !=
			    0) {
				fprintf(stderr, "invalid timeout: %s\n",
				    optarg);
				return (2);
			}
			break;
		case 'n':
			if (parse_int_range(optarg, 1, 1000000, &count) != 0) {
				fprintf(stderr, "invalid count: %s\n", optarg);
				return (2);
			}
			break;
		case 'q':
			quiet = 1;
			break;
		default:
			usage(argv[0]);
			return (2);
		}
	}

	if (peer_ip == NULL || peer_port == 0 || message == NULL) {
		usage(argv[0]);
		return (2);
	}

	if (strlen(message) > SDTP_MAX_MESSAGE_LENGTH) {
		fprintf(stderr, "message too large\n");
		return (2);
	}

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_SDTP);
	if (fd < 0) {
		perror("socket");
		return (1);
	}

	tv.tv_sec = timeout_secs;
	tv.tv_usec = 0;
	if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
		perror("setsockopt(SO_RCVTIMEO)");
		close(fd);
		return (1);
	}

	memset(&local, 0, sizeof(local));
	local.sin_family = AF_INET;
	local.sin_port = htons(local_port);
	if (inet_pton(AF_INET, bind_ip, &local.sin_addr) != 1) {
		fprintf(stderr, "invalid bind IPv4 address: %s\n", bind_ip);
		close(fd);
		return (2);
	}

	if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
		perror("bind");
		close(fd);
		return (1);
	}

	memset(&peer, 0, sizeof(peer));
	peer.sin_family = AF_INET;
	peer.sin_port = htons(peer_port);
	if (inet_pton(AF_INET, peer_ip, &peer.sin_addr) != 1) {
		fprintf(stderr, "invalid peer IPv4 address: %s\n", peer_ip);
		close(fd);
		return (2);
	}

	for (int i = 0; i < count; i++) {
		if (send_one(fd, &peer, message,
			completion_cookie_base + (uint64_t)i) != 0) {
			close(fd);
			return (1);
		}
		if (recv_one(fd, quiet, message) != 0) {
			close(fd);
			return (1);
		}
	}

	close(fd);
	return (0);
}
