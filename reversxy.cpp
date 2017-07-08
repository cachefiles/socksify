#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <regex.h>
#ifdef WIN32
#include <windows.h>
#else
#include <netdb.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#endif

#include "txall.h"
#include "buf_checker.h"

#ifndef WIN32
#include <unistd.h>
#define closesocket(s) close(s)
#define SD_BOTH SHUT_RDWR
#endif

#define RDF_MASK(ff) ((ff) & (RDF_FIN| RDF_EOF))
#define STACK2TASK(s) (&(s)->tx_sched)

#define LOG_ERROR(fmt, args...) fprintf(stderr, fmt, ##args)
#define LOG_WARNN(fmt, args...) fprintf(stderr, fmt, ##args)
#define LOG_DEBUG(fmt, args...) fprintf(stderr, fmt, ##args)
// #define LOG_VERBOSE(fmt, args...) fprintf(stderr, fmt, ##args)

#ifndef LOG_ERROR
#define LOG_ERROR(fmt, args...)
#endif

#ifndef LOG_WARNN
#define LOG_WARNN(fmt, args...)
#endif

#ifndef LOG_DEBUG
#define LOG_DEBUG(fmt, args...)
#endif

#ifndef LOG_VERBOSE
#define LOG_VERBOSE(fmt, args...)
#endif

// #define USE_JUST_FORWARD
#define STDIN_FILE_FD 0
#define FAILURE_SAFEEXIT(cond, fmt, args...) do { if ((cond) == 0) break; fprintf(stderr, fmt, args); exit(0); } while ( 0 )

struct listen_context {
	int flags;
	int just_forward;
	unsigned int port;

	tx_aiocb file;
	tx_task_t task;
};

struct relay_data {
	int off;
	int len;

#define RDF_EOF 0x01
#define RDF_FIN 0x02

	int limit;
	int content_length;
#define RDF_LENGTH 0x04
#define RDF_CHUNKED 0x08
#define RDF_CHUNKED_EOF 0x10

	int flag;
	char buf[4096];
	int padding;

	int stat_total;
};

static int _connect_total = 0;

int _protect_req = 0;
int _protect_count = 0;
int _protect_socks[1024];
int _protect_initialize = 0;
struct tx_task_t _protect_task;
struct tx_task_q _protect_cond;
struct tx_task_q _stop_queue;

static void on_loop_cleanup(tx_task_t *task)
{
	tx_task_record(&_stop_queue, task);
	return;
}

static void wait_protected_socket(tx_task_t *task)
{
	tx_loop_t *loop = tx_loop_default();

	if (_protect_count > 0) {
		tx_task_active(task);
		return;
	}

	tx_task_record(&_protect_cond, task);
	if (_protect_req == 0) {
		tx_task_active(&_protect_task);
		tx_loop_break(loop);
	}

	_protect_req++;
}

extern "C" int get_protect_socket()
{
	if (_protect_count > 0)
		return _protect_socks[--_protect_count];
	return -1;
}

void check_protect_socks(void *upp)
{
	tx_loop_t *loop = tx_loop_default();

	if (!tx_taskq_empty(&_protect_cond)
			&& _protect_count < 1024) {
		tx_task_active(&_protect_task);
		tx_loop_break(loop);
	}

	return;
}

extern "C" int main_loop_stoped()
{
	tx_loop_t *loop = tx_loop_default();
	return loop->tx_stop;
}

static long long _data_usage = 0;
extern "C" long long main_data_usage()
{
	return _data_usage;
}

static struct sockaddr_in _relay0;

void set_socksify_addr(struct sockaddr_in *relay)
{
	memcpy(&_relay0, relay, sizeof(_relay0));
	return;
}

struct listen_context * txlisten_create(struct tcpip_info *info);
extern "C" int main_loop_prepare(const char *local)
{
	int err;
	struct tcpip_info info = {0};
	static struct listen_context *upp = NULL;

	tx_loop_t *loop = tx_loop_default();
	tx_poll_t *poll = tx_epoll_init(loop);
	tx_timer_ring *provider = tx_timer_ring_get(loop);
	TX_UNUSED(provider);
	TX_UNUSED(poll);

	err = get_target_address(&info, local);
	TX_CHECK(err == 0, "get target address failure");

	if (_protect_initialize == 0) {
		tx_taskq_init(&_stop_queue);
		tx_taskq_init(&_protect_cond);
		tx_task_init(&_protect_task, loop, check_protect_socks, loop);

		assert(upp == NULL);
		upp = txlisten_create(&info);
		_protect_initialize = 1;
	}

	return 0;
}

extern "C" int main_loop_cleanup(void)
{
	tx_loop_t *loop = tx_loop_default();

	_protect_count = 0;
	_protect_req = 0;
	for (int i = 0; i < _protect_count; i++) {
		close(_protect_socks[i]);
	}

	tx_task_drop(&_protect_task);
	tx_task_wakeup(&_stop_queue);
	tx_loop_break(loop);

	if (!tx_taskq_empty(&_protect_cond)) {
		abort();
	}

	return 0;
}

extern "C" int main_loop_break()
{
	tx_loop_t *loop = tx_loop_default();
	tx_loop_break(loop);
	return 0;
}

extern "C" int main_loop_loop()
{
	tx_loop_t *loop = tx_loop_default();
	tx_loop_main(loop);
	return loop->tx_stop;
}

extern "C" int get_socket()
{
	if (_protect_req <= 0
			&& _protect_count > 5) {
		printf("empty socket\n");
		return -1;
	}

	return socket(AF_INET, SOCK_STREAM, 0);
}

extern "C" void drop_protect_socket(void)
{
	for (int i = 0; i < _protect_count; i++) {
		close(_protect_socks[i]);
	}
	_protect_count = 0;
	return;
}

extern "C" void add_protect_socket(int newfd)
{
	if (newfd >= 0) {
		_protect_socks[_protect_count++] = newfd;
		if (_protect_req > 0) _protect_req--;
		tx_task_wakeup(&_protect_cond);
	}

	return;
}

int fill_relay_data(struct relay_data *d, tx_aiocb *f)
{
	int len;
	int change = 0;

	if (d->off >= d->len) d->off = d->len = 0;

	while (tx_readable(f) &&
			d->len < (int)sizeof(d->buf) && !RDF_MASK(d->flag)) {
		len = recv(f->tx_fd, d->buf + d->len, sizeof(d->buf) - d->len, 0);
		tx_aincb_update(f, len);

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

int write_relay_data(struct relay_data *d, tx_aiocb *f, int ismobile)
{
	int len;
	int change = 0;

	if (tx_writable(f) && d->off < d->len) {
		do {
			len = tx_outcb_write(f, d->buf + d->off, d->len - d->off);
			if (len > 0) {
				change |= (len > 0);
				d->off += len;
				d->stat_total += len;
				if (ismobile) _data_usage += len;
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

		if (RDF_MASK(d->flag) == RDF_EOF && tx_writable(f)) {
			shutdown(f->tx_fd, SD_BOTH);
			d->flag |= RDF_FIN;
		}
	}

	return 0;
}

struct channel_context {
	int flags;
	int pxy_stat;
	int is_mobile;
	tx_aiocb file;
	tx_aiocb remote;
	tx_task_t on_stop;
	tx_timer_t on_dead;
	tx_task_stack_t task;

	int port;
	in_addr target;
	char domain[128];
	int (*proxy_handshake)(struct channel_context *up);

	struct relay_data c2r;
	struct relay_data r2c;
};

struct channel_context *_dbg_ctx = NULL;

int relay_fill_prepare(struct relay_data *d, tx_aiocb *f, tx_task_stack_t *t)
{
	int error = 0;
	int flags = RDF_MASK(d->flag);

	if ((flags == 0) && !tx_readable(f) &&
			d->len < (int)sizeof(d->buf)) {
		tx_aincb_active(f, &t->tx_sched);
		error = 1;
	} else {
		printf("fallback %x %d %d: %s\n", d->flag, tx_readable(f), d->len, _dbg_ctx? _dbg_ctx->domain: "");
	}

	return error;
}

int relay_write_prepare(struct relay_data *d, tx_aiocb *f, tx_task_stack_t *t)
{
	int error = 0;
	int flags = RDF_MASK(d->flag);

	if ((d->off < d->len || flags == RDF_EOF) && !tx_writable(f)) {
		tx_outcb_prepare(f, STACK2TASK(t), 0);
		error = 1;
	}

	return error;
}

enum {
	NONE_PROTO = 0,
	UNKOWN_PROTO = (1 << 0),
	SOCKV4_PROTO = (1 << 1),
	SOCKV5_PROTO = (1 << 2),

	HTTP_PROTO = (1 << 3),
	HTTPS_PROTO = (1 << 4),
	FORWARD_PROTO = (1 << 5),

	START_PROTO = (1 << 6),
	DIRECT_PROTO = (1 << 7),

	HTTP_REQUEST = (1 << 8),
	HTTP_RESPONSE = (1 << 9),
	CLOSE_PROTO = (1 << 10),
};

static const int SUPPORTED_PROTO = UNKOWN_PROTO| SOCKV4_PROTO| SOCKV5_PROTO| HTTP_PROTO| HTTPS_PROTO| FORWARD_PROTO| DIRECT_PROTO ;

static int check_proxy_proto(struct relay_data *d)
{
	int flags = 0;
	struct buf_match m;

	buf_init(&m, d->buf, d->len);
	if (buf_equal(&m, 0, 0x04) && buf_find(&m, 8, 0)) {
		flags |= SOCKV4_PROTO;
		return flags;
	}

	if (buf_equal(&m, 0, 0x05) && buf_valid(&m, 1)) {
		int len = (m.base[1] & 0xFF);
		if (memchr(&m.base[2], 0x0, len)) {
			flags |= SOCKV5_PROTO;
			return flags;
		}

		if (memchr(&m.base[2], 0x2, len)) {
			flags |= SOCKV5_PROTO;
			return flags;
		}
	}

	if (buf_equal(&m, 0, 'C')) {
		int off = 0;
		const char *op = "CONNECT ";
		while (*++op != 0) {
			if (!buf_equal(&m, ++off, *op))
				break;
		}
		if (*op == 0) {
			flags |= HTTPS_PROTO;
			return flags;
		}
	}

	if (buf_equal(&m, 0, 'G')) {
		int off = 0;
		const char *op = "GET ";
		while (*++op != 0) {
			if (!buf_equal(&m, ++off, *op))
				break;
		}
		if (*op == 0) {
			flags |= HTTP_PROTO;
			return flags;
		}
	}

	if (buf_equal(&m, 0, 'P')) {
		int off = 0;
		const char *op = "POST ";
		while (*++op != 0) {
			if (!buf_equal(&m, ++off, *op))
				break;
		}
		if (*op == 0) {
			flags |= HTTP_PROTO;
			return flags;
		}
	}

	if (!buf_overflow(&m) && d->len > 0) {
		flags |= UNKOWN_PROTO;
		return flags;
	}

	if (d->len == sizeof(d->buf)) {
		flags |= UNKOWN_PROTO;
		return flags;
	}

	if (d->flag & RDF_EOF) {
		flags |= UNKOWN_PROTO;
		return flags;
	}

	return 0;
}


static void do_channel_release(struct channel_context *up)
{
	int fd;
	_connect_total--;
	tx_aiocb *cb = &up->file;
	tx_timer_stop(&up->on_dead);
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

	tx_task_stack_drop(&up->task);
	tx_task_drop(&up->on_stop);

	delete up;
}

static void do_channel_release_wrapper(void *up)
{
	struct channel_context *ctx = (struct channel_context *)up;
	do_channel_release(ctx);
	return;
}

static int parse_https_target(struct relay_data *d, char *host, size_t len)
{
	char buf[128] =  {};
	sscanf(d->buf, "CONNECT %127s", buf);

	strncpy(host, buf, len -1);
	return 0;
}

#define N 10

static int parse_http_target(struct relay_data *d, char *host, size_t len)
{
	char *p, *delter;
	char uri[512], method[16], ver[16];
	sscanf(d->buf, "%16s %511s %15s", method, uri, ver);

	LOG_DEBUG("off: %d\n", d->off);
	assert(d->off == 0);
	if ((memmem(d->buf, d->len, "\r\n\r\n", 4) == NULL) &&
			((memcmp(uri, "http://", 7) && memcmp(uri, "https://", 8)) || (memmem(d->buf, d->len, "\r\n", 2) == NULL))) {
		LOG_VERBOSE("request not finish: ##|%s|## %d %s %s %s\n", d->buf, d->len, method, uri, ver);
		return 1;
	}

	delter = (uri + 7);
	if (*uri == '/' && d->len < sizeof(d->buf)) {
		assert(d->len <= sizeof(d->buf));
		d->buf[d->len] = 0;

		char host[512] = {}, path[512] = {};
		p = strcasestr(d->buf, "\nHost: ");
		if (p != NULL) {
			strncpy(path, uri, sizeof(path) -1);
			sscanf(p + 7, "%511s", host);
			snprintf(uri, sizeof(uri), "http://%s%s", host, path);
		}
	}

	p = strchr(delter, '/');
	if (p) {
		assert(p - delter < len);
		memcpy(host, delter, p - delter);
		host[p - delter] = 0;
		delter = p;
	} else {
		strncpy(host, delter, len -1);
	}

#if 0
	p = (char *)memmem(d->buf, d->len, "\r\n", 2);
	if (p != NULL) {
		char *line_limit = p;
		p = (char *)memmem(d->buf, line_limit - d->buf, " http://", 8);
		if (p != NULL) {
			char *next = (char *)memmem(p + 8, line_limit - p - 8, "/", 1);
			if (next == NULL) {
				next = (char *)memmem(p + 8, line_limit - p - 8, " ", 1);
				if (next) { next = next -1; *next = '/'; }
			}

			if (next != NULL) {
				char *limit = d->buf + d->len;
				memmove(p + 1, next, limit - next);
				d->len -= (next - p - 1);
			}
		}
	}
#endif

	return 0;
}

static int do_forward_connect(int peerfd, tx_aiocb *s, char *domain, tx_task_t *t)
{
	int error;
	struct sockaddr_in sin0 = {};
	tx_loop_t *loop = tx_loop_default();

#if 0
	struct tcpip_info info = {0};
	struct sockaddr_in sin1 = {};
	error = get_target_address(&info, domain);
	if (error != 0) {
		fprintf(stderr, "failure targethost: %s\n", domain);
		return -1;
	}

	sin1.sin_family = AF_INET;
	sin1.sin_port   = (info.port);
	sin1.sin_addr.s_addr = (info.address);
	fprintf(stderr, "connect to %s: %x:%d\n", domain, info.address, htons(info.port));
#endif

	sin0.sin_family = AF_INET;
	error = bind(peerfd, (struct sockaddr *)&sin0, sizeof(sin0));
	TX_CHECK(error == 0, "bind failure");

	tx_setblockopt(peerfd, 0);
	tx_aiocb_init(s, loop, peerfd);
	return tx_aiocb_connect(s, (struct sockaddr *)&_relay0, sizeof(_relay0), t);
}

static int do_host_connect(tx_aiocb *s, char *domain, int port, tx_task_stack_t *t)
{
	int error = -1;
	struct sockaddr_in sin0;
	struct tcpip_info info = {0};
	tx_loop_t *loop = tx_loop_default();

	info.port = htons(port);
	error = get_target_address(&info, domain);
	if (error != 0) {
		LOG_WARNN("failure target host: %s\n", domain);
		return -1;
	}

	int peerfd = socket(AF_INET, SOCK_STREAM, 0);

	tx_setblockopt(peerfd, 0);

	memset(&sin0, 0, sizeof(sin0));
	sin0.sin_family = AF_INET;
	error = bind(peerfd, (struct sockaddr *)&sin0, sizeof(sin0));

	closesocket(s->tx_fd);
	tx_aiocb_fini(s);

	tx_aiocb_init(s, loop, peerfd);

	sin0.sin_family = AF_INET;
	sin0.sin_port   = (info.port);
	sin0.sin_addr.s_addr = (info.address);
	error = tx_aiocb_connect(s, (struct sockaddr *)&sin0, sizeof(sin0), STACK2TASK(t));

	LOG_WARNN("do_host_connect: connect to %s: %x:%d %d\n", domain, info.address, htons(info.port), error);
	return error;
}

static struct tcpip_info _remote_target = {0};

static int parse_http_response(struct channel_context *up, struct relay_data *r)
{
	const char *ptr;
	int temp_flags = 0;
	const char content_length[] = "Content-Length:";
	const char transfer_encoding[] = "Transfer-Encoding:";

	assert(r->len <= sizeof(r->buf));
	r->buf[r->len] = 0;

	if ((ptr = strstr(r->buf, transfer_encoding)) != NULL) {
		ptr += strlen(transfer_encoding);
		while (*ptr == ' ') ptr++;

		if (strncmp(ptr, "chunked", 7) == 0) r->flag |= RDF_CHUNKED;
		LOG_VERBOSE("TE %s %s\n", transfer_encoding, ptr);

		r->content_length = 0;
	} else if ((ptr = strstr(r->buf, content_length)) != NULL) {
		ptr += strlen(content_length);
		while (*ptr == ' ') ptr++;

		r->flag |= RDF_LENGTH;
		r->content_length = atoi(ptr);
		LOG_VERBOSE("CL %s %s |%d\n", content_length, ptr, r->content_length);
	} else {
		r->content_length = 1000000;
		temp_flags |= CLOSE_PROTO;
	}

	if ((ptr = strstr(r->buf, "\r\n\r\n")) != NULL) {
		r->limit = (ptr + 4 - r->buf);
		LOG_VERBOSE("parse_http_response: %p %x \n%.*s\n", up, r->flag, r->limit, r->buf);
		up->flags |= temp_flags;
		return 0;
	}

	if (r->flag & RDF_EOF) {
		LOG_VERBOSE("unexpected End of file %d %d %s\n", r->off, r->len, r->buf);
		up->flags |= CLOSE_PROTO;
		return 1;
	}

	return -1;
}

static void block_transfer(void *upp, tx_task_stack_t *sta)
{
	struct channel_context *up = (struct channel_context *)upp;
	struct relay_data *d = &up->r2c;
	tx_aiocb *f = &up->file;
	int change = 0;
	int len;

	_dbg_ctx = up;
	tx_timer_reset(&up->on_dead, 300000);
	LOG_VERBOSE("block_transfer enter: %p %d\n", upp, d->limit);
	do {
		change = fill_relay_data(&up->r2c, &up->remote);
		if (change & 0x02) {
			LOG_VERBOSE("block_transfer write failure\n");
			goto exception;
		}

		if (tx_writable(f) && d->off < d->len && d->limit) {
			do {
				int limit = d->len - d->off;
				if (limit > d->limit) limit = d->limit;

				len = tx_outcb_write(f, d->buf + d->off, limit);
				if (len > 0) {
					change |= (len > 0);
					d->off += len;
					d->limit -= len;
					d->stat_total += len;
				} else if (tx_writable(f)) {
					LOG_VERBOSE("block_transfer write failure\n");
					goto exception;
				}
			} while (len > 0 && d->off < d->len && d->limit);
		}

	} while (change);

	LOG_VERBOSE("block_transfer fast leave: %d %d %d %d\n", d->limit, d->off, d->len, change);
	if (d->limit > 0 && !(up->r2c.flag & RDF_EOF)) {
		int error = relay_fill_prepare(&up->r2c, &up->remote, &up->task);
		error |= relay_write_prepare(&up->r2c, &up->file, &up->task);
		assert (error != 0);
		return;
	}

	LOG_VERBOSE("block_transfer full leave: %p %d\n", upp, d->limit);
	tx_task_stack_pop1(&up->task, 0);
	tx_task_stack_active(&up->task);
	d->limit = 0;
	return;

exception:
	LOG_DEBUG("block_transfer exception: %p %d\n", upp, d->limit);
	up->flags |= UNKOWN_PROTO;
	tx_task_stack_raise(sta);
	return;
}

int parse_http_chunk(struct channel_context *up, struct relay_data *r)
{
	int chunk_len;
	const char *ptr;
	const char *base = &r->buf[r->off];
	assert(r->len <= sizeof(r->buf));
	r->buf[r->len] = 0;

	if ((ptr = strstr(base, "\r\n")) != NULL) {
		sscanf(base, "%x", &chunk_len);
		if (chunk_len == 0) r->flag |= RDF_CHUNKED_EOF;
		r->limit = (ptr + 2 - base) + chunk_len + 2;
		LOG_VERBOSE("chunk length: %d %x %.4s\n", chunk_len, chunk_len, base);
		return 0;
	}

	if (r->flag & RDF_EOF) {
		LOG_ERROR("unexpected End of file\n");
		assert(0);
	}

	return -1;
}

static void chunk_transfer(void *upp, tx_task_stack_t *sta)
{
	struct channel_context *up = (struct channel_context *)upp;
	int change;

	_dbg_ctx = up;
	tx_timer_reset(&up->on_dead, 300000);
	change = fill_relay_data(&up->r2c, &up->remote);
	if (change & 0x02) goto exception;

	if (up->r2c.limit > 0) {
		tx_task_stack_push(&up->task, block_transfer, up);
		tx_task_stack_active(&up->task);
		return;
	}

	if (0 == (up->r2c.flag & RDF_CHUNKED_EOF) && parse_http_chunk(up, &up->r2c) < 0) {
		int error = relay_fill_prepare(&up->r2c, &up->remote, &up->task);
		assert (error != 0);
		return;
	}

	if (up->r2c.limit > 0) {
		tx_task_stack_push(&up->task, block_transfer, up);
		tx_task_stack_active(&up->task);
		return;
	}

	tx_task_stack_pop1(&up->task, 0);
	tx_task_stack_active(&up->task);
	up->r2c.flag &= ~RDF_CHUNKED_EOF;
	up->r2c.flag &= ~RDF_CHUNKED;
	return;

exception:
	LOG_DEBUG("chunk_transfer exception: %p\n", up);
	up->flags |= UNKOWN_PROTO;
	tx_task_stack_raise(sta);
	return;
}

static void https_proto_transfer(void *upp, tx_task_stack_t *sta)
{
	struct channel_context *up = (struct channel_context *)upp;
	int change = 0;
	int error = 0;
	
	_dbg_ctx = up;
	tx_timer_reset(&up->on_dead, 300000);
	LOG_DEBUG("https_proto_transfer enter: %p %s\n", up, up->domain);
	do {
		change = fill_relay_data(&up->r2c, &up->remote);
		if (change & 0x02) goto exception;

		change |= write_relay_data(&up->r2c, &up->file, 0);
		if (change & 0x02) goto exception;

	} while (change);

	do {
		change = fill_relay_data(&up->c2r, &up->file);
		if (change & 0x02) goto exception;

		change |= write_relay_data(&up->c2r, &up->remote, 0);
		if (change & 0x02) goto exception;

	} while (change);

	try_shutdown_relay(&up->c2r, &up->remote);
	try_shutdown_relay(&up->r2c, &up->file);

	error  = relay_fill_prepare(&up->c2r, &up->file, &up->task);
	error |= relay_fill_prepare(&up->r2c, &up->remote, &up->task);

	error |= relay_write_prepare(&up->c2r, &up->remote, &up->task);
	error |= relay_write_prepare(&up->r2c, &up->file, &up->task);
	if (error) return;

exception:
	LOG_DEBUG("https_proto_input exception\n");
	up->flags |= UNKOWN_PROTO;
	tx_task_stack_raise(sta);
	return;
}

static void https_proto_input(void *upp, tx_task_stack_t *sta)
{
	char target[128];
	const char resp[] = "HTTP/1.0 200 OK\r\n\r\n";
	struct channel_context *up = (struct channel_context *)upp;
	
	_dbg_ctx = up;
	LOG_DEBUG("https_proto_input enter: %p %s\n", up, up->domain);
	if (fill_relay_data(&up->c2r, &up->file) == 2) {
		goto exception;
	}

	if (parse_https_target(&up->c2r, target, sizeof(target)) == 1) {
		if (up->c2r.flag & RDF_EOF) goto exception;
		int error = relay_fill_prepare(&up->c2r, &up->file, &up->task);
		assert (error != 0);
		return;
	}

	strcpy(up->domain, target);
	if (do_host_connect(&up->remote, target, 80, &up->task) == -1) {
		LOG_WARNN("http target: %s\n", target);
		goto exception;
	}

	strcpy(up->r2c.buf, resp);
	up->r2c.len = strlen(resp);
	up->c2r.len = 0;
	up->c2r.off = 0;

	tx_task_stack_push(&up->task, https_proto_transfer, up);
	tx_task_stack_active(&up->task);

	up->flags &= ~HTTP_REQUEST;
	up->r2c.content_length = 0;
	up->r2c.limit = 0;

	return;

exception:
	LOG_VERBOSE("https_proto_input exception\n");
	up->flags |= UNKOWN_PROTO;
	tx_task_stack_raise(sta);
	return;
}

static void http_proto_transfer(void *upp, tx_task_stack_t *sta)
{
	int change = 1;
	struct channel_context *up = (struct channel_context *)upp;

	_dbg_ctx = up;
	LOG_VERBOSE("http_proto_transfer enter: %p %s\n", up, up->domain);
	while ((change == 1) 
			&& (up->flags & HTTP_REQUEST) == 0) {
		change = fill_relay_data(&up->c2r, &up->file);
		if (change & 0x02) {
			LOG_DEBUG("http_proto_transfer exception on read: %p %s\n", up, up->domain);
			goto exception;
		}

		change |= write_relay_data(&up->c2r, &up->remote, up->is_mobile);
		if (change & 0x02) {
			LOG_DEBUG("http_proto_transfer exception on write: %p %s\n", up, up->domain);
			goto exception;
		}
	}

	change = fill_relay_data(&up->r2c, &up->remote);
	if (change & 0x02) goto exception;

	if ((up->flags & HTTP_RESPONSE) == 0
			&& parse_http_response(up, &up->r2c) < 0) {
		int error = relay_fill_prepare(&up->r2c, &up->remote, &up->task);
		assert (error != 0);
		return;
	}

	up->flags |= HTTP_RESPONSE;
	up->flags |= HTTP_REQUEST;

	if (up->r2c.limit > 0) {
		tx_task_stack_push(&up->task, block_transfer, up);
		tx_task_stack_active(&up->task);
		return;
	}

	if (up->r2c.content_length > 0) {
		up->r2c.limit = up->r2c.content_length;
		up->r2c.content_length = 0;

		tx_task_stack_push(&up->task, block_transfer, up);
		tx_task_stack_active(&up->task);
		return;
	}

	if (up->r2c.flag & RDF_CHUNKED) {
		tx_task_stack_push(&up->task, chunk_transfer, up);
		tx_task_stack_active(&up->task);
		return;
	}

	LOG_VERBOSE("http_proto_transfer full leave: %p %s\n", up, up->domain);
	if (up->flags & CLOSE_PROTO) {
		LOG_DEBUG("http_proto_transfer exception on proto close: %p %s\n", up, up->domain);
		goto exception;
	}

	tx_task_stack_pop1(&up->task, 0);
	tx_task_stack_active(&up->task);
	return;

exception:
	LOG_DEBUG("http_proto_transfer exception: %p %s\n", up, up->domain);
	up->flags |= UNKOWN_PROTO;
	tx_task_stack_raise(sta);
	return;
}

static void http_proto_input(void *upp, tx_task_stack_t *sta)
{
	char target[128];
	struct channel_context *up = (struct channel_context *)upp;
	
	_dbg_ctx = up;
	LOG_DEBUG("http_proto_input enter: %p %s\n", up, up->domain);
	if (fill_relay_data(&up->c2r, &up->file) == 2) {
	    LOG_DEBUG("http_proto_input read exception: %p %s\n", up, up->domain);
		goto exception;
	}

	if (parse_http_target(&up->c2r, target, sizeof(target)) == 1) {
		if (up->c2r.flag & RDF_EOF) {
	    	LOG_DEBUG("http_proto_input EOF exception: %p %s\n", up, up->domain);
			goto exception;
		}

		int error = relay_fill_prepare(&up->c2r, &up->file, &up->task);
		assert (error != 0);
		return;
	}

	strcpy(up->domain, target);
	if (do_host_connect(&up->remote, target, 80, &up->task) == -1) {
		LOG_WARNN("http target: %s\n", target);
		goto exception;
	}

	tx_task_stack_push(&up->task, http_proto_transfer, up);
	tx_task_stack_active(&up->task);

	up->flags &= ~(HTTP_REQUEST| HTTP_RESPONSE);
	up->r2c.flag = 0;
	up->r2c.limit = 0;
	up->r2c.content_length = 0;

	return;

exception:
	LOG_VERBOSE("http_proto_input exception\n");
	up->flags |= UNKOWN_PROTO;
	tx_task_stack_raise(sta);
	return;
}

static int do_channel_poll(struct channel_context *up)
{
	tx_timer_reset(&up->on_dead, 300000);

	_dbg_ctx = up;
	if ((NONE_PROTO == (up->flags & SUPPORTED_PROTO))
			&& fill_relay_data(&up->c2r, &up->file) == 1) {
		up->flags |= check_proxy_proto(&up->c2r);
	}

	if (up->flags & UNKOWN_PROTO) {
		LOG_WARNN("conn: %p raise exception\n", up);
		return 0;
	}

	if (up->flags & HTTP_PROTO) {
		tx_task_stack_push(&up->task, http_proto_input, up);
		tx_task_stack_active(&up->task);
		return 1;
	}

	if (up->flags & HTTPS_PROTO) {
		tx_task_stack_push(&up->task, https_proto_input, up);
		tx_task_stack_active(&up->task);
		return 1;
	}

	try_shutdown_relay(&up->r2c, &up->file);
	return relay_fill_prepare(&up->c2r, &up->file, &up->task);
}

static void do_channel_wrapper(void *up, tx_task_stack_t *sta)
{
	int err;
	struct channel_context *upp;

	upp = (struct channel_context *)up;
	err = do_channel_poll(upp);

	_dbg_ctx = 0;
	if (err == 0) {
		LOG_DEBUG("channel release %p/%d %d %d\n",
				upp, _connect_total, upp->c2r.stat_total, upp->r2c.stat_total);
		do_channel_release(upp);
		return;
	}

	return;
}

static void do_channel_prepare(struct channel_context *up, int newfd, unsigned short port)
{
	tx_loop_t *loop = tx_loop_default();

	_connect_total++;
	tx_aiocb_init(&up->file, loop, newfd);
	tx_task_init(&up->on_stop, loop, do_channel_release_wrapper, up);

	tx_task_stack_init(&up->task, loop);
	tx_task_stack_push(&up->task, do_channel_wrapper, up);

	tx_timer_init(&up->on_dead, loop, &up->on_stop);
	on_loop_cleanup(&up->on_stop);
	up->is_mobile = 1;

	up->port = port;
	up->domain[0] = 0;
	tx_setblockopt(newfd, 0);

	tx_aiocb_init(&up->remote, loop, -1);
	tx_task_stack_active(&up->task);

	up->flags = 0;
	up->c2r.flag = 0;
	up->c2r.len = up->c2r.off = 0;
	up->r2c.flag = 0;
	up->r2c.len = up->r2c.off = 0;
	strcpy(up->domain, "HELO");

	LOG_DEBUG("newfd: %d to here\n", newfd);
	return;
}

static void do_listen_accepted(void *up)
{
	struct listen_context *lp0;
	struct channel_context *cc0;

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
		if (lp0->just_forward) {
			cc0->flags |= FORWARD_PROTO;
		}
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
	int just_forward = 0;
	int i, err, bind_ok = 0;
	struct tcpip_info info = {0};
	struct listen_context *upp;
	unsigned int last_tick = 0;

	tx_loop_t *loop = tx_loop_default();
	tx_poll_t *poll = tx_epoll_init(loop);
	tx_poll_t *poll2 = tx_kqueue_init(loop);
	tx_poll_t *poll1 = tx_completion_port_init(loop);
	tx_timer_ring *provider = tx_timer_ring_get(loop);

	for (i = 1; i < argc; i++) {
		if (strncmp(argv[i], "-l", 2) == 0) {
			const char *bind_info = &argv[i][2];
			if (*bind_info == 0) {
				TX_CHECK(i + 1 < argc, "missing bind argument info");
				bind_info = argv[++i];
			} else if (*bind_info == '=') {
				TX_CHECK(i + 1 < argc, "missing argument");
				bind_info++;
			}

			err = get_target_address(&info, bind_info);
			TX_CHECK(err == 0, "get target address failure");
			bind_ok = 1;
		} else if (strncmp(argv[i], "-h", 2) == 0) {
			fprintf(stderr, "%s [-h] [-l bind_info] <target>\n", argv[0]);
			fprintf(stderr, "\t-l bind_info bind listen address to bind_info format <host:port>\n");
			fprintf(stderr, "\t<target> connect target\n");
			fprintf(stderr, "\t-h print this help\n");
			fprintf(stderr, "\n");
			exit(0);
		} else if (strncmp(argv[i], "-f", 2) == 0) {
			TX_CHECK(i + 1 < argc, "missing argument");
			err = get_target_address(&_remote_target, argv[++i]);
			TX_CHECK(err == 0, "get target address failure");
			just_forward = 1;
		} else if (*argv[i] == '-') {
			fprintf(stderr, "unkown option: %s\n", argv[i]);
			exit(0);
		} else {
			err = get_target_address(&_remote_target, argv[i]);
			TX_CHECK(err == 0, "get target address failure");
			just_forward = 1;
		}
	}

	TX_CHECK(bind_ok == 1, "get target address failure");
	if (bind_ok == 0) exit(0);

	tx_taskq_init(&_protect_cond);
	tx_task_init(&_protect_task, loop, check_protect_socks, loop);
	upp = txlisten_create(&info);
	upp->just_forward = just_forward;

	signal(SIGPIPE, SIG_IGN);
	for ( ; ; ) {
		int fd;
		tx_loop_main(loop);

		fd = get_socket();
		if (fd == -1) {
			perror("socket");
			break;
		}

		do {
			/* protect socket */
			add_protect_socket(fd);
			fd = get_socket();
		} while (fd != -1);
	}

#if 0
	fprintf(stderr, "Hello World protect %d %d %d %d\n",
			tx_taskq_empty(&_protect_cond), _protect_req, _protect_count, getdtablesize());
#endif
	tx_loop_delete(loop);

	TX_UNUSED(last_tick);
	TX_UNUSED(provider);
	TX_UNUSED(poll2);
	TX_UNUSED(poll1);
	TX_UNUSED(poll);

	return 0;
}

