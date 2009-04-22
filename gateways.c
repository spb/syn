#include "atheme.h"

#include "syn.h"

DECLARE_MODULE_V1
(
        "syn/gateways", false, _modinit, _moddeinit,
        "$Revision$",
        "Stephen Bennett <stephen -at- freenode.net>"
);

static void gateway_newuser(void *v);

static void check_all_users(void *v)
{
    user_t *u;
    mowgli_patricia_iteration_state_t state;

    MOWGLI_PATRICIA_FOREACH(u, &state, userlist)
    {
        gateway_newuser(u);
    }
}

void _modinit(module_t *m)
{
    use_syn_main_symbols(m);
    use_syn_kline_symbols(m);

    hook_add_event("user_add");
    hook_add_hook("user_add", gateway_newuser);
    hook_add_event("syn_kline_added");
    hook_add_hook("syn_kline_added", check_all_users);

    check_all_users(NULL);
}

void _moddeinit()
{
    hook_del_hook("user_add", gateway_newuser);
    hook_del_hook("syn_kline_add", check_all_users);
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
            syn_report("Killing user %s; hex ident matches K:line [%s@%s] (%s)", u->nick, k->user, k->host, k->reason);
            syn_kill(u, "Your reported IP [%s] is banned: %s", identhost, k->reason);
            return;
        }
    }

    char gecos[GECOSLEN];
    strncpy(gecos, u->gecos, GECOSLEN);
    char *p = strchr(gecos, ' ');
    if (p != NULL)
        *p = '\0';

    p = strchr(gecos, '/');
    if (p != NULL)
        *p++ = '\0';

    if (k = syn_find_kline(NULL, gecos))
    {
        syn_report("Killing user %s; realname host matches K:line [%s@%s] (%s)", u->nick, k->user, k->host, k->reason);
        syn_kill(u, "Your reported hostname [%s] is banned: %s", gecos, k->reason);
        return;
    }
    else if (k = syn_find_kline(NULL, p))
    {
        syn_report("Killing user %s; realname host matches K:line [%s@%s] (%s)", u->nick, k->user, k->host, k->reason);
        syn_kill(u, "Your reported hostname [%s] is banned: %s", p, k->reason);
        return;
    }
}
