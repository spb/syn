#include "atheme.h"

DECLARE_MODULE_V1
(
        "syn/main", false, _modinit, _moddeinit,
        "$Revision$",
        "Stephen Bennett <stephen -at- freenode.net>"
);

static void syn_handler(sourceinfo_t *si, int parc, char *parv[]);

service_t *syn;
list_t syn_cmdtree;
list_t syn_helptree;
list_t syn_conftable;

void _modinit(module_t *m)
{
//  command_add(&syn_help, &syn_cmdtree);

    help_addentry(&syn_helptree, "HELP", "help/help", NULL);
    help_addentry(&syn_helptree, "LIST", "help/syn/list", NULL);

    syn = service_add("syn", syn_handler, &syn_cmdtree, &syn_conftable);
}

void _moddeinit()
{
//  command_delete(&syn_help, &syn_cmdtree);

    help_delentry(&syn_helptree, "HELP");
    help_delentry(&syn_helptree, "LIST");

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

