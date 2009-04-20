#include "atheme.h"

#include "syn.h"

DECLARE_MODULE_V1
(
        "syn/gateways", false, _modinit, _moddeinit,
        "$Revision$",
        "Stephen Bennett <stephen -at- freenode.net>"
);

static void gateway_newuser(void *v);

void _modinit(module_t *m)
{
    user_t *u;
    mowgli_patricia_iteration_state_t state;

    use_syn_main_symbols(m);
    use_syn_kline_symbols(m);

    hook_add_event("user_add");
    hook_add_hook("user_add", gateway_newuser);

    MOWGLI_PATRICIA_FOREACH(u, &state, userlist)
    {
        gateway_newuser(u);
    }
}

void _moddeinit()
{
    hook_del_hook("user_add", gateway_newuser);
}

const char *decode_hex_ip(const char *hex)
{
    static char buf[16];
    unsigned int ip = 0;

    buf[0] = '\0';

    sscanf(hex, "%x", &ip);

    if (ip == 0)
        return NULL;

    sprintf(buf, "%hhu.%hhu.%hhu.%hhu", (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, ip & 0xff);
    return buf;
}

static void gateway_newuser(void *v)
{
    user_t *u = v;
    kline_t *k = NULL;

    char *ident = u->user;
    if (*ident == '~')
        ++ident;

    const char *identhost = decode_hex_ip(ident);

    if (identhost)
    {
        k = syn_find_kline(NULL, identhost);

        if (k)
        {
            syn_report("Killing user [%s]; hex ident matches K:line [%s@%s] (%s)", u->nick, k->user, k->host, k->reason);
            kill_user(syn->me, u, "Your reported IP [%s] is banned: %s", identhost, k->reason);
            return;
        }
    }
}
