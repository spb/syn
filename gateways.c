#include "atheme.h"
#include "uplink.h"

#include "syn.h"

DECLARE_MODULE_V1
(
        "syn/gateways", false, _modinit, _moddeinit,
        "$Revision$",
        "Stephen Bennett <stephen -at- freenode.net>"
);

static void check_user(hook_user_nick_t *data, bool isnewuser);

static void check_all_users(void *v)
{
    user_t *u;
    mowgli_patricia_iteration_state_t state;

    MOWGLI_PATRICIA_FOREACH(u, &state, userlist)
    {
        hook_user_nick_t data = { .u = u };
        check_user(&data, false);
    }
}

static void gateway_newuser(hook_user_nick_t *data)
{
    check_user(data, true);
}

void _modinit(module_t *m)
{
    use_syn_main_symbols(m);
    use_syn_util_symbols(m);
    use_syn_kline_symbols(m);

    hook_add_event("user_add");
    hook_add_user_add(gateway_newuser);
    hook_add_event("syn_kline_added");
    hook_add_hook("syn_kline_added", check_all_users);
    hook_add_event("syn_kline_check");

    check_all_users(NULL);
}

void _moddeinit(module_unload_intent_t intent)
{
    hook_del_user_add(gateway_newuser);
    hook_del_hook("syn_kline_added", check_all_users);
}

static void check_user(hook_user_nick_t *data, bool isnewuser)
{
    user_t *u = data->u;
    kline_t *k = NULL;

    /* If the user has already been killed, don't try to do anything */
    if (!u)
        return;

    // If they've been marked as not having a decodeable IP address, don't try again.
    if (u->flags & SYN_UF_NO_GATEWAY_IP)
        return;

    const char *ident = u->user;
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
            data->u = NULL;
            return;
        }

        // Ident not K:lined(yet); check whether it should be
        // Note that this happens after the K:line check; if this hook adds a
        // new kline, then we'll be called again through the syn_kline_add hook
        syn_kline_check_data_t d = { identhost, u, 0 };
        hook_call_event("syn_kline_check", &d);

        // If a kline was added by this, then we got called again and have already killed the user if we should.
        // Don't do any more.
        if (d.added)
        {
            // On the off-chance that a kline was added that doesn't in fact kill this user, this will cause
            // subsequent checks (facilities etc) to be skipped. That's better than crashing or running amok
            // because we tried to gateway-cloak an already-dead user, though.
            data->u = NULL;
            return;
        }

        if (isnewuser)
        {
                // They weren't already K:lined, and we didn't K:line them. BOPM may want to, though...
                sts(":%s ENCAP * SNOTE F :Client connecting: %s (%s@%s) [%s] {%s} [%s]",
                                ME, u->nick, u->user, u->host, identhost, "?", u->gecos);
        }
    }
    else
    {
        // Performance hack: if we can't decode a hex IP, assume that this user is not connecting through a
        // gateway that makes any attempt to identify them, and skip them for all future checks.
        u->flags |= SYN_UF_NO_GATEWAY_IP;
        return;
    }

    char gecos[GECOSLEN];
    strncpy(gecos, u->gecos, GECOSLEN);
    char *p = strchr(gecos, ' ');
    if (p != NULL)
        *p = '\0';

    p = strchr(gecos, '/');
    if (p != NULL)
        *p++ = '\0';

    if ((k = syn_find_kline(NULL, gecos)))
    {
        syn_report("Killing user %s; realname host matches K:line [%s@%s] (%s)", u->nick, k->user, k->host, k->reason);
        syn_kill(u, "Your reported hostname [%s] is banned: %s", gecos, k->reason);
        data->u = NULL;
        return;
    }
    else if (p && (k = syn_find_kline(NULL, p)))
    {
        syn_report("Killing user %s; realname host matches K:line [%s@%s] (%s)", u->nick, k->user, k->host, k->reason);
        syn_kill(u, "Your reported hostname [%s] is banned: %s", p, k->reason);
        data->u = NULL;
        return;
    }

    char looked_up_hostname[HOSTLEN];

    if (!p)
    {
        syn_debug(3, "no hostname found for %s!%s@%s[%s]; doing reverse lookup", u->nick, u->user, u->host, u->gecos);

        // There was no hostname, only an IP. This can happen when the hostname is too long to fit in a gecos field.
        // Do a reverse lookup and see whether the hostname is also klined.
        // Because we're decoding this from an eight-char hex ip, it can only be ipv4.
        struct sockaddr_in sa;
        sa.sin_family = AF_INET;
       sa.sin_port = 6667;
        inet_aton(identhost, &sa.sin_addr);

        if (0 == getnameinfo((struct sockaddr *)&sa, sizeof sa, looked_up_hostname, sizeof looked_up_hostname, NULL, 0, NI_NAMEREQD))
        {
            syn_debug(3, "got reverse lookup: %s", looked_up_hostname);
            if ((k = syn_find_kline(NULL, looked_up_hostname)))
            {
                syn_report("Killing user %s; realname host matches K:line [%s@%s] (%s)", u->nick, k->user, k->host, k->reason);
                syn_kill(u, "Your reported hostname [%s] is banned: %s", p, k->reason);
                data->u = NULL;
                return;
            }

            p = looked_up_hostname;
        }
        else
            syn_debug(3, "no reverse lookup");
    }

    // As above, but for gecos hostnames
    syn_kline_check_data_t d = { gecos, u };
    hook_call_event("syn_kline_check", &d);
    d.ip = p;
    hook_call_event("syn_kline_check", &d);
}
