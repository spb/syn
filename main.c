#include "atheme.h"

DECLARE_MODULE_V1
(
        "syn/main", false, _modinit, _moddeinit,
        "$Revision$",
        "Stephen Bennett <stephen -at- freenode.net>"
);

static void syn_handler(sourceinfo_t *si, int parc, char *parv[]);
static void syn_join_channel(void *unused);

service_t *syn;
list_t syn_cmdtree;
list_t syn_helptree;
list_t syn_conftable;

struct
{
    char *channel;
    char *debugchannel;
    unsigned int debug;
    unsigned int verbosity;
} syn_config;

void _modinit(module_t *m)
{
//  command_add(&syn_help, &syn_cmdtree);

    help_addentry(&syn_helptree, "HELP", "help/help", NULL);
    help_addentry(&syn_helptree, "LIST", "help/syn/list", NULL);

    hook_add_event("config_ready");
    hook_add_config_ready((void(*)(void*))syn_join_channel);
    hook_add_server_eob((void(*)(server_t*))syn_join_channel);

    add_dupstr_conf_item("CHANNEL", &syn_conftable, &syn_config.channel);
    add_dupstr_conf_item("DEBUGCHANNEL", &syn_conftable, &syn_config.debugchannel);
    add_uint_conf_item("DEBUG", &syn_conftable, &syn_config.debug, 0, 15);
    add_uint_conf_item("VERBOSE", &syn_conftable, &syn_config.verbosity, 0, 15);

    syn = service_add("syn", syn_handler, &syn_cmdtree, &syn_conftable);
    service_set_chanmsg(syn, true);
}

void _moddeinit()
{
//  command_delete(&syn_help, &syn_cmdtree);

    help_delentry(&syn_helptree, "HELP");
    help_delentry(&syn_helptree, "LIST");

    del_conf_item("CHANNEL", &syn_conftable);
    del_conf_item("DEBUGCHANNEL", &syn_conftable);
    del_conf_item("DEBUG", &syn_conftable);
    del_conf_item("VERBOSE", &syn_conftable);

    hook_del_config_ready((void(*)(void*))syn_join_channel);
    hook_del_server_eob((void(*)(server_t*))syn_join_channel);

    service_delete(syn);
}

static void syn_cmd_success_nodata(sourceinfo_t *si, const char *text)
{
    if (si->c)
        notice_channel_sts(si->service->me, si->c, text);
    else
        notice_user_sts(si->service->me, si->su, text);
}


static void syn_cmd_success_string(sourceinfo_t *si, const char *string, const char *text)
{
    if (si->c)
        notice_channel_sts(si->service->me, si->c, text);
    else
        notice_user_sts(si->service->me, si->su, text);
}


static void syn_cmd_fail(sourceinfo_t *si, faultcode_t fault, const char *text)
{
    if (si->c)
        notice_channel_sts(si->service->me, si->c, text);
    else
        notice_user_sts(si->service->me, si->su, text);
}

struct sourceinfo_vtable syn_si_vtable = { "syn", syn_cmd_fail, syn_cmd_success_nodata, syn_cmd_success_string };


static void syn_handler(sourceinfo_t *si, int parc, char *parv[])
{
    char *cmd;
    char *text;
    char orig[BUFSIZE];

    /* this should never happen */
    if (parv[0][0] == '&')
    {
        slog(LG_ERROR, "services(): got parv with local channel: %s", parv[0]);
        return;
    }

    /* make a copy of the original for debugging */
    strlcpy(orig, parv[parc - 1], BUFSIZE);

    // Is this a message to a channel?
    if (parv[0][0] == '#')
    {
        if (!syn_config.channel || 0 != strcmp(syn_config.channel, parv[0]))
            return;

        char *firstarg = strtok(parv[parc-1], " ");
        if (!firstarg || 0 != strncmp(si->service->nick, firstarg, strlen(si->service->nick)))
            return;

        si->c = channel_find(parv[0]);

        cmd = strtok(NULL, " ");
        text = strtok(NULL, "");
    }
    else
    {
        cmd = strtok(parv[parc - 1], " ");
        text = strtok(NULL, "");
    }

    if (!cmd)
        return;
    if (*cmd == '\001')
    {
        handle_ctcp_common(si, cmd, text);
        return;
    }

    si->v = &syn_si_vtable;

    /* take the command through the hash table */
    command_exec_split(si->service, si, cmd, text, &syn_cmdtree);
}

static void syn_join_channel(void *unused)
{
    if (syn_config.channel && me.connected)
        join(syn_config.channel, syn->nick);
    if (syn_config.debugchannel && me.connected)
        join(syn_config.debugchannel, syn->nick);
}

void syn_debug(int debuglevel, char *fmt, ...)
{
    if (debuglevel > syn_config.debug)
        return;

    va_list ap;
    char buf[BUFSIZE];

    char *debugchannel = syn_config.debugchannel;

    if (!debugchannel)
        debugchannel = syn_config.channel;

    if (!debugchannel)
        return;

    if (!channel_find(debugchannel))
        return;

    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZE, fmt, ap);
    va_end(ap);

    msg(syn->nick, debugchannel, "[debug%d] %s", debuglevel, buf);
}

void syn_vreport(char *fmt, va_list ap)
{
    char buf[BUFSIZE];

    if (!syn_config.channel)
        return;

    if (!channel_find(syn_config.channel))
        return;

    vsnprintf(buf, BUFSIZE, fmt, ap);

    msg(syn->nick, syn_config.channel, "%s", buf);
}

void syn_report(char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    syn_vreport(fmt, ap);
    va_end(ap);
}

void syn_report2(unsigned int level, char *fmt, ...)
{
    if (syn_config.verbosity < level)
        return;

    va_list ap;
    va_start(ap, fmt);
    syn_vreport(fmt, ap);
    va_end(ap);
}

