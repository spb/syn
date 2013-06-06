#ifndef syn_hooktypes_h
#define syn_hooktypes_h

typedef struct {
    sourceinfo_t *si;
    user_t *user;
    const char *oldvhost;
} hook_incoming_host_change_t;

#endif
