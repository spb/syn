#include "atheme.h"

#include "syn.h"

DECLARE_MODULE_V1
(
        "syn/masks", false, _modinit, _moddeinit,
        "$Revision$",
        "Stephen Bennett <stephen -at- freenode.net>"
);

static void masks_newuser(void *v);

static void syn_cmd_addmask(sourceinfo_t *si, int parc, char **parv);
static void syn_cmd_delmask(sourceinfo_t *si, int parc, char **parv);
static void syn_cmd_setmask(sourceinfo_t *si, int parc, char **parv);

command_t syn_addmask = { "ADDMASK", N_("Adds a lethal, suspicious or exempt mask"), "syn:general", 1, syn_cmd_addmask };
command_t syn_delmask = { "DELMASK", N_("Removes a lethal, suspicious or exempt mask"), "syn:general", 1, syn_cmd_delmask };
command_t syn_setmask = { "SETMASK", N_("Modifies settings for a lethal, suspicious or exempt mask"), "syn:general", 1, syn_cmd_setmask };

static unsigned int lethal_mask_duration = 3600*24;
static char *lethal_mask_message = NULL;

typedef enum
{
    mask_exempt,
    mask_suspicious,
    mask_lethal,
    mask_unknown
} mask_type;

typedef struct
{
    char *regex;
    atheme_regex_t *re;
    int reflags;
    mask_type type;
    time_t expires;
} mask_t;

list_t masks;

struct {
    const char *s;
    mask_type t;
} mask_string_map[] = {
    { "exempt",     mask_exempt     },
    { "suspicious", mask_suspicious },
    { "lethal",     mask_lethal     },
    { NULL, 0 }
};

const char *string_from_mask_type(mask_type t)
{
    for (int i=0; mask_string_map[i].s != NULL; ++i)
        if (mask_string_map[i].t == t)
            return mask_string_map[i].s;
    return NULL;
}

mask_type mask_type_from_string(const char *s)
{
    for (int i=0; mask_string_map[i].s != NULL; ++i)
        if (0 == strcasecmp(mask_string_map[i].s, s))
            return mask_string_map[i].t;
    return mask_unknown;
}



void _modinit(module_t *m)
{
    use_syn_main_symbols(m);
    use_syn_kline_symbols(m);

    lethal_mask_message = sstrdup("Banned");

    add_uint_conf_item("lethalmask_duration", syn_conftable, &lethal_mask_duration, 0, (unsigned int)-1);
    add_dupstr_conf_item("lethalmaks_message", syn_conftable, &lethal_mask_message);

    command_add(&syn_addmask, syn_cmdtree);
    command_add(&syn_delmask, syn_cmdtree);
    command_add(&syn_setmask, syn_cmdtree);

    hook_add_event("user_add");
    hook_add_hook("user_add", masks_newuser);
}

void _moddeinit()
{
    hook_del_hook("user_add", masks_newuser);
}

void masks_newuser(void *v)
{
    user_t *u = v;

    char nuh[NICKLEN+USERLEN+HOSTLEN+GECOSLEN];
    snprintf(nuh, sizeof(nuh), "%s!%s@%s %s", u->nick, u->user, u->host, u->gecos);

    int blocked = 0, exempt = 0;
    char *suspicious_regex = NULL, *blocked_regex = NULL;

    node_t *n;
    LIST_FOREACH(n, masks.head)
    {
        mask_t *m = n->data;

        if (! regex_match(m->re, nuh))
            continue;

        switch (m->type)
        {
            case mask_exempt:
                exempt = 1;
                break;
            case mask_suspicious:
                suspicious_regex = m->regex;
                break;
            case mask_lethal:
                blocked = 1;
                blocked_regex = m->regex;
                break;
            case mask_unknown:
                break;
        }

        if (exempt)
            break;
    }

    if (exempt == 1)
        return;

    if (blocked == 1)
    {
        syn_report("Killing client %s(%s@%s) due to lethal mask %s",
                u->nick, u->user, u->host, blocked_regex);
        syn_kill_or_kline(u, lethal_mask_duration, lethal_mask_message);
        return;
    }

    if (suspicious_regex)
    {
        syn_report("Client %s(%s@%s) matches suspicious mask %s",
                u->nick, u->user, u->host, suspicious_regex);
        return;
    }
}

void syn_cmd_addmask(sourceinfo_t *si, int parc, char **parv)
{
    char *pattern;
    char *stype;
    mask_type type;
    mask_t *newmask;
    int flags;

    char *args = parv[0];

    if (args == NULL)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "ADDMASK");
        command_fail(si, fault_needmoreparams, "Syntax: ADDMASK /<regex>/[i] <type>");
        return;
    }

    pattern = regex_extract(args, &args, &flags);
    if (pattern == NULL)
    {
        command_fail(si, fault_badparams, STR_INVALID_PARAMS, "ADDMASK");
        command_fail(si, fault_badparams, "Syntax: ADDMASK /<regex>/[i] <type>");
        return;
    }

    stype = args;

    while (*stype == ' ')
        ++stype;

    if (*stype == '\0')
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "ADDMASK");
        command_fail(si, fault_needmoreparams, "Syntax: ADDMASK /<regex>/[i] <type>");
        return;
    }

    type = mask_type_from_string(stype);
    if (type == mask_unknown)
    {
        command_fail(si, fault_badparams, "Invalid mask type \2%s\2.", stype);
        return;
    }

    node_t *n;
    LIST_FOREACH(n, masks.head)
    {
        mask_t *m = n->data;

        if (0 == strcmp(m->regex, pattern))
        {
            command_fail(si, fault_nochange, "\2%s\2 was already added (%s); not re-adding", pattern, string_from_mask_type(m->type));
            return;
        }
    }

    atheme_regex_t *regex = regex_create(pattern, flags);
    if (regex == NULL)
    {
        command_fail(si, fault_badparams, "The provided regex \2%s\2 is invalid.", pattern);
        return;
    }

    newmask = malloc(sizeof(mask_t));
    newmask->regex = sstrdup(pattern);
    newmask->reflags = flags;
    newmask->re = regex;
    newmask->type = type;

    node_add(newmask, node_create(), &masks);
    command_success_nodata(si, "Added \2%s\2 to %s mask list", pattern, stype);
}

void syn_cmd_delmask(sourceinfo_t *si, int parc, char **parv)
{
}

void syn_cmd_setmask(sourceinfo_t *si, int parc, char **parv)
{
}

