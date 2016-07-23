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
#endif

#include "txall.h"
#include "buf_checker.h"

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

	int stat_total;
};

int _protect_req = 0;
int _protect_count = 0;
int _protect_socks[1024];
struct tx_task_t _protect_task;
struct tx_task_q _protect_cond;

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

	if (!LIST_EMPTY(&_protect_cond)
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

struct listen_context * txlisten_create(struct tcpip_info *info);
extern "C" int main_loop_prepare(const char *local)
{
    int err;
    struct tcpip_info info = {0};
    static struct listen_context *upp = NULL;

    tx_loop_t *loop = tx_loop_default();
    tx_poll_t *poll = tx_epoll_init(loop);
    tx_timer_ring *provider = tx_timer_ring_get(loop);

    err = get_target_address(&info, local);
    TX_CHECK(err == 0, "get target address failure");

    tx_taskq_init(&_protect_cond);
    tx_task_init(&_protect_task, loop, check_protect_socks, loop);

	assert(upp == NULL);
    upp = txlisten_create(&info);

	return 0;
}

extern "C" int main_loop_stop()
{
	tx_loop_t *loop = tx_loop_default();
	tx_loop_stop(loop);
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

void add_protect_socket(int newfd)
{
	if (newfd >= 0) {
		_protect_socks[_protect_count++] = newfd;
		tx_task_wakeup(&_protect_cond);
		if (_protect_req > 0) _protect_req--;
	}

	return;
}

int fill_relay_data(struct relay_data *d, tx_aiocb *f)
{
	int len;
	int change = 0;

	if (d->off >= d->len) d->off = d->len = 0;

	while (tx_readable(f) &&
			d->len < (int)sizeof(d->buf) && !d->flag) {
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
				d->stat_total += len;
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
	} else {
		printf("fallback %x %d %d\n", d->flag, tx_readable(f), d->len);
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

	if (!buf_overflow(&m)) {
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
	tx_task_drop(&up->task);

	delete up;
}

static int parse_https_target(struct relay_data *d, char *host)
{
	char buf[128];
	sscanf(d->buf, "CONNECT %s", buf);
	fprintf(stderr, "https target %s\n", buf);

	const char *_https_map[] = {
		"openapi.youku.com",
		"61.135.196.99",
		"220.181.185.150",
		"111.13.127.46",
		"211.151.50.10",
		"123.126.99.57",
		"123.126.99.39",
		"220.181.154.137",
		"httpbin.org",
		NULL
	};

	for (int i = 0; _https_map[i]; i++) {
		if (strcmp(_https_map[i], buf) == 0) {
			strcpy(host, "@");
			strcat(host, buf);
			return 0;
		}
	}

	strcpy(host, buf);
	return 0;
}

#define N 10
#define DEBUG(msg, ...)

static int is_ipcheck_url(const char *host, const char *fulluri, const char *regex)
{
	int insub;
	regex_t reg;
	regmatch_t pm[N];

	const char *di;
	char *sp, sub_regex[512];

	sp = sub_regex;
	insub = 0;

	di = strchr(fulluri, '/');
	if (di != NULL) fulluri = di;

	for (const char *p = regex; *p; p++) {
		if (insub == 0 && *p != '/') {
			DEBUG("ignore char %c\n", *p);
			continue;
		}

		if (insub == 0 && *p == '/') {
			insub = 1;
			continue;
		}

		if (*p == '\\' && *p != 0) {
			*sp++ = *p++;
			*sp++ = *p;
			continue;
		}

		if (*p != ',') {
			*sp++ = *p;
			continue;
		}

		*sp = 0;
		if (sp > (sub_regex + 2) &&
				*(sp - 1) == 'i' && *(sp - 2) == '/') {
			*(sp - 2) = 0;
		}

		DEBUG("regex is: %s\n", sub_regex);
		int z = REG_NOMATCH;
		int error = regcomp(&reg, sub_regex + 1, REG_EXTENDED|REG_NOSUB|REG_NOTEOL);
		if (0 == error) {
			z = regexec(&reg, fulluri, N, pm, REG_NOTBOL);
			regfree(&reg);
		} else {
			fprintf(stderr, "regex %d failure: %s\n", error, sub_regex);
		}

		if (z != REG_NOMATCH) {
			fprintf(stderr, "regex is match: %s %s %s\n", host, fulluri, regex);
			return 1;
		}

		sp = sub_regex;
		insub = 0;
	}

	if (insub) {
		*sp = 0;
		if (sp > (sub_regex + 2) &&
				*(sp - 1) == 'i' && *(sp - 2) == '/') {
			*(sp - 2) = 0;
		}

		DEBUG("regex is: %s\n", sub_regex);
		int z = REG_NOMATCH;
		int error = regcomp(&reg, sub_regex + 1, REG_EXTENDED|REG_NOSUB|REG_NOTEOL|REG_NOTBOL);
		if (0 == error) {
			z = regexec(&reg, fulluri, N, pm, REG_NOTBOL);
			regfree(&reg);
		} else {
			fprintf(stderr, "regex %d failure: %s\n", error, sub_regex);
		}

		if (z != REG_NOMATCH) {
			fprintf(stderr, "regex is match: %s %s %s\n", host, fulluri, regex);
			return 1;
		}

		sp = sub_regex;
		insub = 0;
	}

	fprintf(stderr, "regex not match: %s %s %s\n", host, fulluri, regex);
	return 0;
}

static int parse_http_target(struct relay_data *d, char *host)
{
	char *p, *delter;
	char uri[512], method[16], ver[16];
	sscanf(d->buf, "%s %s %s", method, uri, ver);

	if (memmem(d->buf, d->len, "\r\n\r\n", 4) == NULL &&
			(memcmp(uri, "http://", 7) && memcmp(uri, "https://", 8) || memmem(d->buf, d->len, "\r\n", 2) == NULL)) {
		fprintf(stderr, "request not finish: ##|%s|## %d %s %s %s\n", d->buf, d->len, method, uri, ver);
		return 1;
	}

	delter = (uri + 7);
	if (*uri == '/' && d->len < sizeof(d->buf)) {
		d->buf[d->len] = 0;

		char host[512], path[512];
		p = strcasestr(d->buf, "\nHost: ");
		if (p != NULL) {
			strcpy(path, uri);
			sscanf(p + 7, "%s", host);
			sprintf(uri, "http://%s%s", host, path);
		}
	}

	p = strchr(delter, '/');
	if (p) {
		memcpy(host, delter, p - delter);
		host[p - delter] = 0;
		delter = p;
	} else {
		strcpy(host, delter);
	}

	const char *any = "/^[^/]*\\.dpool\\.sina\\.com\\.cn\\/iplookup/i, /^[^/]*/vrs_flash\\.action/i";
	const char *list[] = {
		"v.youku.com","/^\\/player\\//i",
		"api.youku.com","/^\\/player\\//i",
		"play.youku.com","/^\\/play\\/get\\.json/i",
		"v2.tudou.com","/^\\//i",
		"www.tudou.com","/^\\/a\\//i,/^\\/v\\//i,/^\\/outplay\\/goto\\/getTvcCode/i,/^\\/tvp\\/alist\\.action/i",
		"s.plcloud.music.qq.com","/^\\/fcgi\\-bin\\/p\\.fcg/i",
		"i.y.qq.com","/^\\/s\\.plcloud\\/fcgi\\-bin\\/p\\.fcg/i",
		"hot.vrs.sohu.com","/^\\//i",
		"live.tv.sohu.com","/^\\/live\\/player/i",
		"pad.tv.sohu.com","/^\\/playinfo/i",
		"my.tv.sohu.com","/^\\/play\\/m3u8version\\.do/i",
		"hot.vrs.letv.com","/^\\//i",
		"data.video.qiyi.com","/^\\/v\\./i,/^\\/videos\\//i,/^\\/.*\\/videos\\//i",
		"cache.video.qiyi.com","/^\\/vms\\?/i,/^\\/vp\\/.*\\/.*\\/\\?src=/i,/^\\/vps\\?/i,/^\\/liven\\//i",
		"cache.vip.qiyi.com","/^\\/vms\\?/i",
		"v.api.hunantv.com","/^\\/player\\/video/i",
		"vv.video.qq.com","/^\\//i,/^\\/getvinfo/i,/^\\/getinfo/i,/^\\/geturl/i",
		"tt.video.qq.com","/^\\/getvinfo/i",
		"ice.video.qq.com","/^\\/getvinfo/i",
		"tjsa.video.qq.com","/^\\/getvinfo/i",
		"a10.video.qq.com","/^\\/getvinfo/i",
		"xyy.video.qq.com","/^\\/getvinfo/i",
		"vcq.video.qq.com","/^\\/getvinfo/i",
		"vsh.video.qq.com","/^\\/getvinfo/i",
		"vbj.video.qq.com","/^\\/getvinfo/i",
		"bobo.video.qq.com","/^\\/getvinfo/i",
		"flvs.video.qq.com","/^\\/getvinfo/i",
		"bkvv.video.qq.com","/^\\/getvinfo/i",
		"info.zb.qq.com","/^\\/\\?/i",
		"geo.js.kankan.xunlei.com","/^\\//i",
		"web-play.pptv.com","/^\\//i",
		"web-play.pplive.cn","/^\\//i",
		"dyn.ugc.pps.tv","/^\\//i",
		"v.pps.tv","/^\\/ugc\\/ajax\\/aj_html5_url\\.php/i",
		"inner.kandian.com","/^\\//i",
		"ipservice.163.com","/^\\//i",
		"so.open.163.com","/^\\/open\\/info\\.htm/i",
		"zb.s.qq.com","/^\\//i",
		"ip.kankan.xunlei.com","/^\\//i",
		"vxml.56.com","/^\\/json\\//i",
		"music.sina.com.cn","/^\\/yueku\\/intro\\//i,/^\\/radio\\/port\\/webFeatureRadioLimitList\\.php/i",
		"play.baidu.com","/^\\/data\\/music\\/songlink/i",
		"v.iask.com","/^\\/v_play\\.php/i,/^\\/v_play_ipad\\.cx\\.php/i",
		"tv.weibo.com","/^\\/player\\//i",
		"wtv.v.iask.com","/^\\/.*\\.m3u8/i,/^\\/mcdn\\.php$/i,/^\\/player\\/ovs1_idc_list\\.php/i",
		"video.sina.com.cn","/^\\/interface\\/l\\/u\\/getFocusStatus\\.php/i",
		"www.yinyuetai.com","/^\\/insite\\//i,/^\\/main\\/get\\-/i",
		"api.letv.com","/^\\/streamblock/i,/^\\/mms\\/out\\/video\\/play/i,/^\\/mms\\/out\\/common\\/geturl/i,/^\\/geturl/i,/^\\/api\\/geturl/i,/^\\/getipgeo$/i",
		"st.live.letv.com","/^\\/live\\//i",
		"live.gslb.letv.com","/^\\/gslb\\?/i",
		"static.itv.letv.com","/^\\/api/i",
		"ip.apps.cntv.cn","/^\\/js\\/player\\.do/i",
		"vdn.apps.cntv.cn","/^\\/api\\/get/i,/^\\/api\\/getLiveUrlCommonApi\\.do\\?pa:\\/\\/cctv_p2p_hdcctv5/i,/^\\/api\\/getLiveUrlCommonApi\\.do\\?pa:\\/\\/cctv_p2p_hdcctv6/i,/^\\/api\\/getLiveUrlCommonApi\\.do\\?pa:\\/\\/cctv_p2p_hdcctv8/i,/^\\/api\\/getLiveUrlCommonApi\\.do\\?pa:\\/\\/cctv_p2p_hdbtv6/i",
		"vdn.live.cntv.cn","/^\\/api2\\/liveHtml5\\.do\\?channel=pa:\\/\\/cctv_p2p_hdcctv5/i,/^\\/api2\\/liveHtml5\\.do\\?channel=pa:\\/\\/cctv_p2p_hdcctv6/i,/^\\/api2\\/liveHtml5\\.do\\?channel=pa:\\/\\/cctv_p2p_hdcctv8/i,/^\\/api2\\/liveHtml5\\.do\\?channel=pa:\\/\\/cctv_p2p_hdbtv6/i,/^\\/api2\\/live\\.do\\?channel=pa:\\/\\/cctv_p2p_hdcctv5/i,/^\\/api2\\/live\\.do\\?channel=pa:\\/\\/cctv_p2p_hdcctv6/i,/^\\/api2\\/live\\.do\\?channel=pa:\\/\\/cctv_p2p_hdcctv8/i,/^\\/api2\\/live\\.do\\?channel=pa:\\/\\/cctv_p2p_hdbtv6/i",
		"vip.sports.cntv.cn","/^\\/check\\.do/i,/^\\/play\\.do/i,/^\\/servlets\\/encryptvideopath\\.do/i",
		"211.151.157.15","/^\\//i",
		"a.play.api.3g.youku.com","/^\\/common\\/v3\\/play\\?/i",
		"i.play.api.3g.youku.com","/^\\/common\\/v3\\/play\\?/i,/^\\/common\\/v3\\/hasadv\\/play\\?/i",
		"api.3g.youku.com","/^\\/layout/i,/^\\/v3\\/play\\/address/i,/^\\/openapi\\-wireless\\/videos\\/.*\\/download/i,/^\\/videos\\/.*\\/download/i,/^\\/common\\/v3\\/play/i",
		"tv.api.3g.youku.com","/^\\/openapi\\-wireless\\/v3\\/play\\/address/i,/^\\/common\\/v3\\/hasadv\\/play/i,/^\\/common\\/v3\\/play/i",
		"play.api.3g.youku.com","/^\\/common\\/v3\\/hasadv\\/play/i,/^\\/common\\/v3\\/play/i,/^\\/v3\\/play\\/address/i",
		"play.api.3g.tudou.com","/^\\/v/i",
		"tv.api.3g.tudou.com","/^\\/tv\\/play\\?/i",
		"api.3g.tudou.com","/^\\//i",
		"api.tv.sohu.com","/^\\/mobile_user\\/device\\/clientconf\\.json\\?/i",
		"access.tv.sohu.com","/^\\//i",
		"iface.iqiyi.com","/^\\/api\\/searchIface\\?/i",
		"iface2.iqiyi.com","/^\\/php\\/xyz\\/iface\\//i,/^\\/php\\/xyz\\/entry\\/galaxy\\.php\\?/i,/^\\/php\\/xyz\\/entry\\/nebula\\.php\\?/i",
		"cache.m.iqiyi.com","/^\\/jp\\/tmts\\//i",
		"dynamic.app.m.letv.com","/^\\/.*\\/dynamic\\.php\\?.*ctl=videofile/i",
		"dynamic.meizi.app.m.letv.com","/^\\/.*\\/dynamic\\.php\\?.*ctl=videofile/i",
		"dynamic.search.app.m.letv.com","/^\\/.*\\/dynamic\\.php\\?.*ctl=videofile/i",
		"dynamic.live.app.m.letv.com","/^\\/.*\\/dynamic\\.php\\?.*act=canplay/i",
		"listso.m.areainfo.ppstream.com","/^\\/ip\\/q\\.php/i",
		"epg.api.pptv.com","/^\\/detail\\.api\\?/i",
		"play.api.pptv.com","/^\\/boxplay\\.api\\?/i",
		"m.letv.com","/^\\/api\\/geturl\\?/i",
		"api.mob.app.letv.com","/^\\/play/i",
		"interface.bilibili.com","/^\\/playurl\\?/i",
		"3g.music.qq.com","/^\\//i",
		"mqqplayer.3g.qq.com","/^\\//i",
		"proxy.music.qq.com","/^\\//i",
		"proxymc.qq.com","/^\\//i",
		"ip2.kugou.com","/^\\/check\\/isCn\\//i",
		"ip.kugou.com","/^\\/check\\/isCn\\//i",
		"client.api.ttpod.com","/^\\/global/i",
		"mobi.kuwo.cn","/^\\//i",
		"mobilefeedback.kugou.com","/^\\//i",
		"tingapi.ting.baidu.com","/^\\/v1\\/restserver\\/ting\\?.*method=baidu\\.ting\\.song/i",
		"music.baidu.com","/^\\/data\\/music\\/links\\?/i",
		"serviceinfo.sdk.duomi.com","/^\\/api\\/serviceinfo\\/getserverlist/i",
		"music.163.com","/^\\/api\\/copyright\\/restrict\\/\\?/i,/^\\/api\\/batch$/i",
		"www.xiami.com","/^\\/web\\/spark/i,/^\\/web\\/.*\\?.*xiamitoken=/i",
		"spark.api.xiami.com","/^\\/api\\?.*method=AuthIp/i,/^\\/api\\?.*method=Start\\.init/i,/^\\/api\\?.*method=Songs\\.getTrackDetail/i,/^\\/api\\?.*method=Songs\\.detail/i",
		"iplocation.geo.qiyi.com","/^\\/cityjson$/i",
		"sns.video.qq.com","/^\\/tunnel\\/fcgi\\-bin\\/tunnel/i",
		"v5.pc.duomi.com","/^\\/single\\-ajaxsingle\\-isban/i",
		"tms.is.ysten.com","/^:8080\\/yst\\-tms\\/login\\.action\\?/i",
		"chrome.2345.com","/^\\/dianhua\\/mobileApi\\/check\\.php$/i",
		"internal.check.duokanbox.com","/^\\/check\\.json/i",

		"180.153.225.136", "/^\\//i",
		"118.244.244.124", "/^\\//i",
		"210.129.145.150", "/^\\//i",
		"182.16.230.98", "/^\\//i"
	};

	char all_regex_list[1024];
	strcpy(all_regex_list, any);

	for (int i = 0; i < sizeof(list)/sizeof(list[0]); i++) {
		if (strcmp(list[i], host) == 0) {
			strcat(all_regex_list, ", ");
			strcat(all_regex_list, list[i + 1]);
			break;
		}

		i++;
	}

	if (is_ipcheck_url(host, delter, all_regex_list)) {
		char *p;
		char savehost[128], followlines[4096];
		strcpy(savehost, host);
		sprintf(host, "@%s", savehost);

		p = (char *)memmem(d->buf, d->len, "\r\n", 2);
		if (p != NULL) {
			memcpy(followlines, p, d->buf + d->len - p);
			followlines[d->buf + d->len - p] = 0;
			d->len = sprintf(d->buf, "%s %s %s%s", method, uri, ver, followlines);
			fprintf(stderr, "rebuild data ###[%s]##\n", d->buf);
		}
	}

	//fprintf(stderr, "http target %s, method %s\n", buf, method);
	return 0;
}

static int do_forward_connect(int peerfd, tx_aiocb *s, char *domain, tx_task_t *t)
{
	int error = -1;
	struct sockaddr_in sin0;
	struct tcpip_info info = {0};
	tx_loop_t *loop = tx_loop_default();

	error = get_target_address(&info, domain);
	if (error != 0) {
		fprintf(stderr, "failure targethost: %s\n", domain);
		return -1;
	}

	tx_setblockopt(peerfd, 0);

	memset(&sin0, 0, sizeof(sin0));
	sin0.sin_family = AF_INET;
	error = bind(peerfd, (struct sockaddr *)&sin0, sizeof(sin0));

	tx_aiocb_init(s, loop, peerfd);

	sin0.sin_family = AF_INET;
	sin0.sin_port   = (info.port);
	sin0.sin_addr.s_addr = (info.address);
	fprintf(stderr, "connect to %s: %x:%d\n", domain, info.address, htons(info.port));
	return tx_aiocb_connect(s, (struct sockaddr *)&sin0, sizeof(sin0), t);
}

static int do_host_connect(tx_aiocb *s, char *domain, int port, tx_task_t *t)
{
	int error = -1;
	struct sockaddr_in sin0;
	struct tcpip_info info = {0};
	tx_loop_t *loop = tx_loop_default();

	info.port = htons(port);
	if (*domain == '@') domain = "proxy.uku.im:443";
	error = get_target_address(&info, domain);
	if (error != 0) {
		fprintf(stderr, "failure targethost: %s\n", domain);
		return -1;
	}

	int peerfd = socket(AF_INET, SOCK_STREAM, 0);

	tx_setblockopt(peerfd, 0);

	memset(&sin0, 0, sizeof(sin0));
	sin0.sin_family = AF_INET;
	error = bind(peerfd, (struct sockaddr *)&sin0, sizeof(sin0));

	tx_aiocb_init(s, loop, peerfd);

	sin0.sin_family = AF_INET;
	sin0.sin_port   = (info.port);
	sin0.sin_addr.s_addr = (info.address);
	fprintf(stderr, "connect to %s: %x:%d\n", domain, info.address, htons(info.port));
	return tx_aiocb_connect(s, (struct sockaddr *)&sin0, sizeof(sin0), t);
}

static int do_channel_poll(struct channel_context *up)
{
	int error = 0;
	int change = 0;

	if (up->flags & START_PROTO) {
		if (!tx_writable(&up->remote)) {
			return 1;
		}

		fprintf(stderr, "connect is finish\n");
		up->flags &= ~START_PROTO;
	}

	if (NONE_PROTO == (up->flags & SUPPORTED_PROTO)) {
		change = fill_relay_data(&up->c2r, &up->file);
		up->flags |= check_proxy_proto(&up->c2r);
		if (NONE_PROTO == (up->flags & SUPPORTED_PROTO)) {
			int prep = relay_fill_prepare(&up->c2r, &up->file);
			fprintf(stderr, "%p proto detected return : %x \n", up, prep);
			return prep;
		}

		fprintf(stderr, "proto detected: %x\n", up->flags);
	}

	if (up->flags &  HTTPS_PROTO) {
		char targethost[128];
		change = fill_relay_data(&up->c2r, &up->file);
		if (parse_https_target(&up->c2r, targethost)) {
			return relay_fill_prepare(&up->c2r, &up->file);
		}

		if (do_host_connect(&up->remote, targethost, 443, &up->task) == -1) {
			fprintf(stderr,  "xxtargethost: %s\n", targethost);
			return 0;
		}

		char resp[] = "HTTP/1.0 200 OK\r\n\r\n";
		strcpy(up->r2c.buf, resp);
		up->r2c.len = strlen(resp);
		up->c2r.len = 0;
		up->c2r.off = 0;
	
		fprintf(stderr, "https targethost: %s\n", targethost);
		up->flags |= (START_PROTO| DIRECT_PROTO);
		up->flags &= ~HTTPS_PROTO;
		return 1;
	}

	if (up->flags &  HTTP_PROTO) {
		char targethost[128];
		change = fill_relay_data(&up->c2r, &up->file);
		if (parse_http_target(&up->c2r, targethost)) {
			return relay_fill_prepare(&up->c2r, &up->file);
		}

		if (do_host_connect(&up->remote, targethost, 80, &up->task) == -1) {
			fprintf(stderr,  "xxtargethost: %s\n", targethost);
			return 0;
		}
	
		fprintf(stderr, "targethost: %s\n", targethost);
		up->flags |= (START_PROTO| DIRECT_PROTO);
		up->flags &= ~HTTP_PROTO;
		return 1;
	}

	if (FORWARD_PROTO & up->flags) {
		int peerfd = get_protect_socket();
		if (peerfd == -1) {
			wait_protected_socket(&up->task);
			return 1;
		}

		if (do_forward_connect(peerfd, &up->remote, "192.168.1.1:7777", &up->task) == -1) {
			return 0;
		}

		up->flags |= (START_PROTO| DIRECT_PROTO);
		up->flags &= ~FORWARD_PROTO;
		return 1;
	}

	if (DIRECT_PROTO != (up->flags & DIRECT_PROTO)) {
		fprintf(stderr, "proto handle error: %x \n", up->flags);
		return 0;
	}

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
		fprintf(stderr, "channel release %d %d\n", upp->c2r.stat_total, upp->r2c.stat_total);
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

#if 0
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
#else
	tx_aiocb_init(&up->remote, loop, -1);
	tx_task_active(&up->task);
#endif

	up->flags = 0;
	up->c2r.flag = 0;
	up->c2r.len = up->c2r.off = 0;
	up->r2c.flag = 0;
	up->r2c.len = up->r2c.off = 0;
#if defined(USE_JUST_FORWARD)
	up->flags |= FORWARD_PROTO;
#endif

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
	tx_poll_t *poll2 = tx_kqueue_init(loop);
	tx_poll_t *poll1 = tx_completion_port_init(loop);
	tx_timer_ring *provider = tx_timer_ring_get(loop);
	tx_timer_ring *provider1 = tx_timer_ring_get(loop);
	tx_timer_ring *provider2 = tx_timer_ring_get(loop);

	TX_CHECK(provider1 == provider, "timer provider not equal");
	TX_CHECK(provider2 == provider, "timer provider not equal");

	err = get_target_address(&info, argv[1]);
	TX_CHECK(err == 0, "get target address failure");

	tx_taskq_init(&_protect_cond);
	tx_task_init(&_protect_task, loop, check_protect_socks, loop);
	upp = txlisten_create(&info);

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

	fprintf(stderr, "Hello World protect %d %d %d %d\n",
			tx_taskq_empty(&_protect_cond), _protect_req, _protect_count, getdtablesize());
	tx_loop_delete(loop);

	TX_UNUSED(last_tick);
	TX_UNUSED(provider2);
	TX_UNUSED(provider1);

	return 0;
}

