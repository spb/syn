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
static void syn_cmd_listmask(sourceinfo_t *si, int parc, char **parv);

command_t syn_addmask = { "ADDMASK", N_("Adds a lethal, suspicious or exempt mask"), "syn:general", 1, syn_cmd_addmask };
command_t syn_delmask = { "DELMASK", N_("Removes a lethal, suspicious or exempt mask"), "syn:general", 1, syn_cmd_delmask };
command_t syn_setmask = { "SETMASK", N_("Modifies settings for a lethal, suspicious or exempt mask"), "syn:general", 1, syn_cmd_setmask };
command_t syn_listmask = { "LISTMASK", N_("Displays configured mask lists"), "syn:general", 1, syn_cmd_listmask };

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
    time_t added;
    char setter[NICKLEN*2+2];
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

static void check_expiry(void *v)
{
    node_t *n, *tn;
    LIST_FOREACH_SAFE(n, tn, masks.head)
    {
        mask_t *m = n->data;

        if (m->expires == 0)
            continue;
        if (m->expires > CURRTIME)
            continue;

        syn_report("Expiring %s mask \2%s\2", string_from_mask_type(m->type), m->regex);
        regex_destroy(m->re);
        free(m->regex);
        free(m);
        node_del(n, &masks);
    }
}

static void save_maskdb()
{
    node_t *n;
    FILE *f = fopen(DATADIR "/masks.db", "w");
    if (!f)
    {
        slog(LG_ERROR, "Couldn't open masks.db for writing: %s", strerror(errno));
        return;
    }

    LIST_FOREACH(n, masks.head)
    {
        mask_t *m = n->data;

        fprintf(f, "/%s/%s %d %s %lu %lu\n",
                m->regex, m->reflags & AREGEX_ICASE ? "i" : "",
                m->type, m->setter, m->added, m->expires);
    }
    fclose(f);
}

static void load_maskdb()
{
    FILE *f = fopen(DATADIR "/masks.db", "r");
    if (!f)
    {
        slog(LG_DEBUG, "Couldn't open masks db for reading: %s", strerror(errno));
        return;
    }

    char line[BUFSIZE*2];
    while(fgets(line, sizeof(line), f))
    {
        char *args = line;
        int flags = 0;
        char *regex = regex_extract(args, &args, &flags);

        atheme_regex_t *re= regex_create(regex, flags);

        if (!re || !regex)
        {
            slog(LG_DEBUG, "Invalid entry %s in masks db", line);
            continue;
        }

        char setter[BUFSIZE*2];
        int type;
        time_t added, expires;

        sscanf(args, "%d %s %lu %lu", &type, setter, &added, &expires);

        mask_t *mask = malloc(sizeof(mask_t));
        mask->regex = sstrdup(regex);
        mask->reflags = flags;
        mask->re = re;
        strncpy(mask->setter, setter, sizeof(mask->setter));
        mask->added = added;
        mask->expires = expires;
        mask->type = type;

        node_add(mask, node_create(), &masks);
    }

    fclose(f);
}

void _modinit(module_t *m)
{
    use_syn_main_symbols(m);
    use_syn_util_symbols(m);
    use_syn_kline_symbols(m);

    lethal_mask_message = sstrdup("Banned");

    add_uint_conf_item("lethalmask_duration", syn_conftable, &lethal_mask_duration, 0, (unsigned int)-1);
    add_dupstr_conf_item("lethalmaks_message", syn_conftable, &lethal_mask_message);

    command_add(&syn_addmask, syn_cmdtree);
    command_add(&syn_delmask, syn_cmdtree);
    command_add(&syn_setmask, syn_cmdtree);
    command_add(&syn_listmask, syn_cmdtree);

    hook_add_event("nick_check");
    hook_add_hook("nick_check", masks_newuser);
    hook_add_event("user_add");
    hook_add_hook("user_add", masks_newuser);

    event_add("masks_check_expiry", check_expiry, NULL, 60);

    load_maskdb();
}

void _moddeinit()
{
    save_maskdb();

    command_delete(&syn_addmask, syn_cmdtree);
    command_delete(&syn_delmask, syn_cmdtree);
    command_delete(&syn_setmask, syn_cmdtree);
    command_delete(&syn_listmask, syn_cmdtree);

    hook_del_hook("user_add", masks_newuser);
    hook_del_hook("nick_check", masks_newuser);

    event_delete(check_expiry, NULL);
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
    time_t duration = 0;

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

    stype = strtok(args, " ");

    if (!stype || *stype == '\0')
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

    char *sduration = strtok(NULL, " ");
    if (sduration && *sduration == '~')
    {
        duration = syn_parse_duration(++sduration);
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
    if (duration > 0)
        newmask->expires = CURRTIME + 60*duration;
    else
        newmask->expires = 0;

    newmask->added = CURRTIME;
    strncpy(newmask->setter, get_oper_name(si), sizeof(newmask->setter));

    node_add(newmask, node_create(), &masks);

    syn_report("\002ADDMASK\002 %s (%s) by %s, expires %s",
            pattern, stype, get_oper_name(si), syn_format_expiry(newmask->expires));
    command_success_nodata(si, "Added \2%s\2 to %s mask list, expiring %s.",
                            pattern, stype, syn_format_expiry(newmask->expires));
}

void syn_cmd_delmask(sourceinfo_t *si, int parc, char **parv)
{
    char *args = parv[0];

    if (!args)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "DELMASK");
        command_fail(si, fault_needmoreparams, "Syntax: DELMASK /<regex>/");
        return;
    }

    int flags = 0;
    char *pattern = regex_extract(args, &args, &flags);

    if (!pattern)
    {
        command_fail(si, fault_badparams, STR_INVALID_PARAMS, "DELMASK");
        command_fail(si, fault_needmoreparams, "Syntax: DELMASK /<regex>/");
        return;
    }

    node_t *n, *tn;
    LIST_FOREACH_SAFE(n, tn, masks.head)
    {
        mask_t *m = n->data;
        if (0 == strcmp(pattern, m->regex))
        {
            syn_report("\002DELMASK\002 %s (%s) by %s", pattern, string_from_mask_type(m->type), get_oper_name(si));
            command_success_nodata(si, "Removing \2%s\2 from %s mask list", pattern, string_from_mask_type(m->type));
            regex_destroy(m->re);
            free(m->regex);
            free(m);
            node_del(n, &masks);
            return;
        }
    }

    command_fail(si, fault_nochange, "\2%s\2 was not found in any mask list", pattern);
}

void syn_cmd_setmask(sourceinfo_t *si, int parc, char **parv)
{
    char *args = parv[0];

    if (!args)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "SETMASK");
        command_fail(si, fault_needmoreparams, "Syntax: SETMASK /<regex>/");
        return;
    }

    int flags = 0;
    char *pattern = regex_extract(args, &args, &flags);

    if (!pattern)
    {
        command_fail(si, fault_badparams, STR_INVALID_PARAMS, "SETMASK");
        command_fail(si, fault_needmoreparams, "Syntax: SETMASK /<regex>/");
        return;
    }

    node_t *n, *tn;
    mask_t *m;
    LIST_FOREACH_SAFE(n, tn, masks.head)
    {
        m = n->data;
        if (0 == strcmp(pattern, m->regex))
            break;
        m = NULL;
    }

    if (!m)
    {
        command_fail(si, fault_nochange, "\2%s\2 was not found in any mask list", pattern);
        return;
    }

    char *nextarg = strtok(args, " ");
    mask_type t = mask_type_from_string(nextarg);
    if (t != mask_unknown)
    {
        m->type = t;
        syn_report("\002SETMASK\002 %s type->%s by %s", pattern, nextarg, get_oper_name(si));
        command_success_nodata(si, "Changed type of mask \2%s\2 to %s", pattern, nextarg);
        return;
    }

    if (*nextarg == '~')
    {
        time_t duration = syn_parse_duration(++nextarg);
        if (duration > 0)
        {
            m->expires = CURRTIME + duration * 60;
            syn_report("\002SETMASK\002 %s duration->%d by %s", pattern, duration, get_oper_name(si));
            command_success_nodata(si, "Changed expiry of mask \2%s\2 to %ld minutes", pattern, duration);
        }
        else
        {
            m->expires = 0;
            syn_report("\002SETMASK\002 %s expiry->off by %s", pattern, get_oper_name(si));
            command_success_nodata(si, "Expiry disabled for mask \2%s\2.", pattern);
        }
        return;
    }

    command_fail(si, fault_badparams, STR_INVALID_PARAMS, "SETMASK");
    command_fail(si, fault_badparams, "Syntax: SETMASK /<regex>/ <type>");
}

void syn_cmd_listmask(sourceinfo_t *si, int parc, char **parv)
{
    mask_type t = mask_unknown;

    if (parc > 0)
    {
        t = mask_type_from_string(parv[0]);
    }

    int count = 0;

    node_t *n;
    LIST_FOREACH(n, masks.head)
    {
        mask_t *m = n->data;

        if (t != mask_unknown && t != m->type)
            continue;

        char buf[BUFSIZE];
        strncpy(buf, syn_format_expiry(m->added), BUFSIZE);
        command_success_nodata(si, "\2%s\2 (%s), set by %s on %s, expires %s",
                m->regex, string_from_mask_type(m->type), m->setter, 
                buf, syn_format_expiry(m->expires));

        ++count;
    }

    command_success_nodata(si, "%d masks found", count);
}
