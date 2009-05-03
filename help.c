#include "atheme.h"

#include "syn.h"

DECLARE_MODULE_V1
(
        "syn/help", false, _modinit, _moddeinit,
        "$Revision$",
        "Stephen Bennett <stephen -at- freenode.net>"
);

static void syn_cmd_help(sourceinfo_t *si, int parc, char *parv[]);

command_t syn_help = { "HELP", N_("Displays contextual help information."), "syn:general", 1, syn_cmd_help };

void _modinit(module_t *m)
{
    use_syn_main_symbols(m);

    command_add(&syn_help, syn_cmdtree);
    help_addentry(syn_helptree, "HELP", "help/help", NULL);
}

void _moddeinit()
{
    command_delete(&syn_help, syn_cmdtree);
    help_delentry(syn_helptree, "HELP");
}

/* HELP <command> [params] */
void syn_cmd_help(sourceinfo_t *si, int parc, char *parv[])
{
    char *command = parv[0];

    if (!command)
    {
        command_success_nodata(si, "***** \2%s Help\2 *****", syn->nick);

        command_success_nodata(si, "\2%s\2 is a utility service to control access to the network.", syn->nick);
        command_success_nodata(si, " ");

        command_help(si, syn_cmdtree);

        command_success_nodata(si, _("***** \2End of Help\2 *****"));

        return;
    }

    /* take the command through the hash table */
    help_display(si, command, syn_helptree);
}
