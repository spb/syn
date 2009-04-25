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
    unsigned int debug;
} syn_config;

void _modinit(module_t *m)
{
//  command_add(&syn_help, &syn_cmdtree);

    help_addentry(&syn_helptree, "HELP", "help/help", NULL);
    help_addentry(&syn_helptree, "LIST", "help/syn/list", NULL);

    hook_add_event("config_ready");
    hook_add_hook("config_ready", syn_join_channel);
    hook_add_hook("server_eob", syn_join_channel);

    add_dupstr_conf_item("CHANNEL", &syn_conftable, &syn_config.channel);
    add_uint_conf_item("DEBUG", &syn_conftable, &syn_config.debug, 0, 15);

    syn = service_add("syn", syn_handler, &syn_cmdtree, &syn_conftable);
}

void _moddeinit()
{
//  command_delete(&syn_help, &syn_cmdtree);

    help_delentry(&syn_helptree, "HELP");
    help_delentry(&syn_helptree, "LIST");

    del_conf_item("CHANNEL", &syn_conftable);
    del_conf_item("DEBUG", &syn_conftable);

    hook_del_hook("config_ready", syn_join_channel);
    hook_del_hook("server_eob", syn_join_channel);

    service_delete(syn);
}

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

    /* lets go through this to get the command */
    cmd = strtok(parv[parc - 1], " ");
    text = strtok(NULL, "");

    if (!cmd)
        return;
    if (*cmd == '\001')
    {
        handle_ctcp_common(si, cmd, text);
        return;
    }

    /* take the command through the hash table */
    command_exec_split(si->service, si, cmd, text, &syn_cmdtree);
}

static void syn_join_channel(void *unused)
{
    if (syn_config.channel && me.connected)
        join(syn_config.channel, syn->nick);
}

void syn_debug(int debuglevel, char *fmt, ...)
{
    if (debuglevel > syn_config.debug)
        return;

    va_list ap;
    char buf[BUFSIZE];

    if (!syn_config.channel)
        return;

    if (!channel_find(syn_config.channel))
        return;

    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZE, fmt, ap);
    va_end(ap);

    msg(syn->nick, syn_config.channel, "[debug%d] %s", debuglevel, buf);
}

void syn_report(char *fmt, ...)
{
    va_list ap;
    char buf[BUFSIZE];

    if (!syn_config.channel)
        return;

    if (!channel_find(syn_config.channel))
        return;

    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZE, fmt, ap);
    va_end(ap);

    msg(syn->nick, syn_config.channel, "%s", buf);
}
