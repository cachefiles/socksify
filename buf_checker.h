#ifndef _BUF_CHECKER_H_
#define _BUF_CHECKER_H_

struct buf_match { 
    int flags; 
    int limit; 
    char *base; 
}; 
 
const int BUF_OVERFLOW = 1; 
static int buf_init(struct buf_match *m, void *buf, int limit) 
{ 
    m->flags = 0; 
    m->base  = (char *)buf; 
    m->limit = limit; 
    return 0; 
} 
 
static int buf_equal(struct buf_match *m, int off, int val) 
{ 
    if (off < m->limit) 
        return (val == m->base[off]); 
    m->flags |= BUF_OVERFLOW; 
    return 0; 
} 
 
static int buf_valid(struct buf_match *m, int off) 
{ 
    if (off < m->limit) 
        return (1); 
    m->flags |= BUF_OVERFLOW; 
    return 0; 
} 
 
static int buf_find(struct buf_match *m, int off, int val) 
{ 
    const void *p = 0; 
    m->flags |= BUF_OVERFLOW; 
    if (off < m->limit) 
        p = memchr(m->base + off, val, m->limit - off); 
    return !(p == NULL); 
} 
 
static int buf_overflow(struct buf_match *m)
{
    /* XXXX */
    return (m->flags & BUF_OVERFLOW);
}

#endif
