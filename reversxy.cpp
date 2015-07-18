#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#ifdef WIN32
#include <windows.h>
#else
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include "txall.h"

#ifndef WIN32
#include <unistd.h>
#define closesocket(s) close(s)
#define SD_BOTH SHUT_RDWR
#endif

#define STDIN_FILE_FD 0
#define FAILURE_SAFEEXIT(cond, fmt, args...) do { if ((cond) == 0) break; fprintf(stderr, fmt, args); exit(0); } while ( 0 )

struct listen_context {
    int flags;
    unsigned int port;

    tx_aiocb file;
    tx_task_t task;
};

struct relay_data {
    int off;
    int len;
#define RDF_EOF 0x01
#define RDF_FIN 0x02
    int flag;
    char buf[4096];

	tx_task_t rtask;
	tx_task_t wtask;
};

int fill_relay_data(struct relay_data *d, tx_aiocb *f)
{
	int len;
	int change = 0;

	if (d->off >= d->len) d->off = d->len = 0;

	if (tx_readable(f) &&
			d->len < (int)sizeof(d->buf) && !d->flag) {
		len = recv(f->tx_fd, d->buf + d->len, sizeof(d->buf) - d->len, 0);
		tx_aincb_update(f, len);

	fprintf(stderr, "len: %d\n", len);
		change |= (len > 0);
		if (len > 0)
			d->len += len;
		else if (len == 0)
			d->flag |= RDF_EOF;
		else if (tx_readable(f)) // socket meet error condiction
			return 0x2;
	}

	return change;
}

int write_relay_data(struct relay_data *d, tx_aiocb *f)
{
	int len;
	int change = 0;

	if (tx_writable(f) && d->off < d->len) {
		do {
			len = tx_outcb_write(f, d->buf + d->off, d->len - d->off);
			if (len > 0) {
				change |= (len > 0);
				d->off += len;
			} else if (tx_writable(f)) {
				return 0x2;
			}
		} while (len > 0 && d->off < d->len);
	}

	return change;
}

int try_shutdown_relay(struct relay_data *d, tx_aiocb *f)
{
	if (d->off >= d->len) {
		d->off = d->len = 0;

		if (d->flag == RDF_EOF && tx_writable(f)) {
			shutdown(f->tx_fd, SD_BOTH);
			d->flag |= RDF_FIN;
		}
	}

	return 0;
}

int relay_fill_prepare(struct relay_data *d, tx_aiocb *f)
{
	int error = 0;

	if ((d->flag == 0) && !tx_readable(f) &&
			d->len < (int)sizeof(d->buf)) {
		tx_aincb_active(f, &d->rtask);
		error = 1;
	}

	return error;
}

int relay_write_prepare(struct relay_data *d, tx_aiocb *f)
{
	int error = 0;

	if ((d->off < d->len || d->flag == RDF_EOF) && !tx_writable(f)) {
		tx_outcb_prepare(f, &d->wtask, 0);
		error = 1;
	}

	return error;
}

struct channel_context {
	int flags;
	int pxy_stat;
	tx_aiocb file;
	tx_aiocb remote;
	tx_task_t task;

	int port;
	in_addr target;
	char domain[128];
	int (*proxy_handshake)(struct channel_context *up);

	struct relay_data c2r;
	struct relay_data r2c;
};

static void do_channel_release(struct channel_context *up)
{
	int fd;
	tx_aiocb *cb = &up->file;
	tx_outcb_cancel(cb, 0);
	tx_aincb_stop(cb, 0);

	fd = cb->tx_fd;
	tx_aiocb_fini(cb);
	closesocket(fd);

	cb = &up->remote;
	tx_outcb_cancel(cb, 0);
	tx_aincb_stop(cb, 0);

	fd = cb->tx_fd;
	tx_aiocb_fini(cb);
	closesocket(fd);

	tx_task_drop(&up->c2r.rtask);
	tx_task_drop(&up->c2r.wtask);
	tx_task_drop(&up->r2c.rtask);
	tx_task_drop(&up->r2c.wtask);

	delete up;
}

static int do_channel_poll(struct channel_context *up)
{
	int error = 0;
	int change = 0;

	do {
		change = fill_relay_data(&up->c2r, &up->file);
		if (change & 0x02) return 0;
		change |= write_relay_data(&up->c2r, &up->remote);
		if (change & 0x02) return 0;
	} while (change);

	do {
		change = fill_relay_data(&up->r2c, &up->remote);
		if (change & 0x02) return 0;
		change |= write_relay_data(&up->r2c, &up->file);
		if (change & 0x02) return 0;
	} while (change);

	try_shutdown_relay(&up->c2r, &up->remote);
	try_shutdown_relay(&up->r2c, &up->file);

	error  = relay_fill_prepare(&up->c2r, &up->file);
	error |= relay_fill_prepare(&up->r2c, &up->remote);

	error |= relay_write_prepare(&up->c2r, &up->remote);
	error |= relay_write_prepare(&up->r2c, &up->file);

	return error;
}

static void do_channel_wrapper(void *up)
{
	int err;
	struct channel_context *upp;

	upp = (struct channel_context *)up;
	err = do_channel_poll(upp);

	if (err == 0) {
		fprintf(stderr, "channel release\n");
		do_channel_release(upp);
		return;
	}

	return;
}

static void do_channel_prepare(struct channel_context *up, int newfd, unsigned short port)
{
	int peerfd, error;
	struct sockaddr sa0;
	struct sockaddr_in sin0;
	tx_loop_t *loop = tx_loop_default();

	tx_aiocb_init(&up->file, loop, newfd);
	tx_task_init(&up->task, loop, do_channel_wrapper, up);
	tx_task_init(&up->c2r.rtask, loop, do_channel_wrapper, up);
	tx_task_init(&up->c2r.wtask, loop, do_channel_wrapper, up);
	tx_task_init(&up->r2c.rtask, loop, do_channel_wrapper, up);
	tx_task_init(&up->r2c.wtask, loop, do_channel_wrapper, up);

	up->port = port;
	up->domain[0] = 0;
	tx_setblockopt(newfd, 0);

	peerfd = socket(AF_INET, SOCK_STREAM, 0);

	memset(&sa0, 0, sizeof(sa0));
	sa0.sa_family = AF_INET;
	error = bind(peerfd, &sa0, sizeof(sa0));

	tx_setblockopt(peerfd, 0);
	tx_aiocb_init(&up->remote, loop, peerfd);

	sin0.sin_family = AF_INET;
	sin0.sin_port   = htons(80);
	sin0.sin_addr.s_addr = inet_addr("103.235.46.39");
	tx_aiocb_connect(&up->remote, (struct sockaddr *)&sin0, sizeof(sin0), &up->task);

	up->flags = 0;
	up->c2r.flag = 0;
	up->c2r.len = up->c2r.off = 0;
	up->r2c.flag = 0;
	up->r2c.len = up->r2c.off = 0;

	fprintf(stderr, "newfd: %d to here\n", newfd);
	return;
}

static void do_listen_accepted(void *up)
{
	const char *name;
	struct listen_context *lp0;
	struct channel_context *cc0;
	union { struct sockaddr sa; struct sockaddr_in si; } local;

	lp0 = (struct listen_context *)up;

	int newfd = tx_listen_accept(&lp0->file, NULL, NULL);
	TX_PRINT(TXL_DEBUG, "new fd: %d\n", newfd);
	tx_listen_active(&lp0->file, &lp0->task);

	if (newfd != -1) {
		cc0 = new channel_context;
		if (cc0 == NULL) {
			TX_CHECK(cc0 != NULL, "new channel_context failure\n");
			closesocket(newfd);
			return;
		}

		do_channel_prepare(cc0, newfd, lp0->port);
	}

	return;
}

struct listen_context * txlisten_create(struct tcpip_info *info)
{
    int fd;
    int err;
    int option = 1;
    tx_loop_t *loop;
    struct sockaddr_in sa0;
    struct listen_context *up;

    fd = socket(AF_INET, SOCK_STREAM, 0);

    tx_setblockopt(fd, 0);

    setsockopt(fd,SOL_SOCKET, SO_REUSEADDR, (char*)&option,sizeof(option));

    sa0.sin_family = AF_INET;
    sa0.sin_port   = info->port;
    sa0.sin_addr.s_addr = info->address;

    err = bind(fd, (struct sockaddr *)&sa0, sizeof(sa0));
    if (err != 0) fprintf(stderr, "bind tcp port failure: port=%d\n", htons(info->port));
    assert(err == 0);

    err = listen(fd, 5);
    assert(err == 0);

    loop = tx_loop_default();
    up = new listen_context();
    up->port = info->port;
    tx_listen_init(&up->file, loop, fd);
    tx_task_init(&up->task, loop, do_listen_accepted, up);
    tx_listen_active(&up->file, &up->task);

    return up;
}

int main(int argc, char *argv[])
{
	int err;
	struct tcpip_info info = {0};
	struct listen_context *upp;
	unsigned int last_tick = 0;

	tx_loop_t *loop = tx_loop_default();
	tx_poll_t *poll = tx_epoll_init(loop);
	tx_poll_t *poll1 = tx_completion_port_init(loop);
	tx_timer_ring *provider = tx_timer_ring_get(loop);
	tx_timer_ring *provider1 = tx_timer_ring_get(loop);
	tx_timer_ring *provider2 = tx_timer_ring_get(loop);

	TX_CHECK(provider1 == provider, "timer provider not equal");
	TX_CHECK(provider2 == provider, "timer provider not equal");

	err = get_target_address(&info, argv[1]);
	TX_CHECK(err == 0, "get target address failure");

	upp = txlisten_create(&info);

	tx_loop_main(loop);
	tx_loop_delete(loop);

	TX_UNUSED(last_tick);
	TX_UNUSED(provider2);
	TX_UNUSED(provider1);

	return 0;
}

