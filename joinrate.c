#include "atheme.h"

#include "syn.h"

DECLARE_MODULE_V1
(
        "syn/joinrate", false, _modinit, _moddeinit,
        "$Revision$",
        "Stephen Bennett <stephen -at- freenode.net>"
);

static void syn_ratecheck(void *v);
static void update_rate_settings(void *v);

static void syn_cmd_setrate(sourceinfo_t *si, int parc, char **parv);

command_t syn_setrate = { "SETRATE", N_("Sets the join-rate monitoring thresholds"), "syn:general", 2, syn_cmd_setrate };

int rate;
int burst;
int warn_time;

typedef struct
{
    int count;
    time_t last_warn_time;
} channelentry;

mowgli_patricia_t *channellist;
BlockHeap *channelheap;
static void free_channelentry(const char *, void *data, void *);

void _modinit(module_t *m)
{
    use_syn_main_symbols(m);

    command_add(&syn_setrate, syn_cmdtree);

    hook_add_event("channel_join");
    hook_add_hook("channel_join", syn_ratecheck);

    channellist = mowgli_patricia_create(noopcanon);
    channelheap = BlockHeapCreate(sizeof(channelentry), HEAP_USER);

    rate = 5;
    burst = 5;
    warn_time = 30;

    event_add("update_rate_settings", update_rate_settings, NULL, rate);
}

void _moddeinit()
{
    mowgli_patricia_destroy(channellist, free_channelentry, NULL);
    command_delete(&syn_setrate, syn_cmdtree);
    hook_del_hook("channel_join", syn_ratecheck);
    event_delete(update_rate_settings, NULL);
}

static void free_channelentry(const char *key, void *data, void *privdata)
{
    BlockHeapFree(channelheap, data);
}

static void syn_ratecheck(void *v)
{
    hook_channel_joinpart_t *data = v;
    chanuser_t *cu = data->cu;

    // Don't warn about burst joins.
    if (me.bursting)
        return;

    channelentry *ce = mowgli_patricia_retrieve(channellist, cu->chan->name);
    if (!ce)
    {
        ce = BlockHeapAlloc(channelheap);
        mowgli_patricia_add(channellist, cu->chan->name, ce);
    }

    if (++ce->count > burst &&
            CURRTIME - ce->last_warn_time > warn_time)
    {
        ce->last_warn_time = CURRTIME;
        syn_report("Join rate in %s exceeds warning limit", cu->chan->name);
    }
}

static void update_rate_settings(void *v)
{
    channelentry *ce;
    mowgli_patricia_iteration_state_t state;

    MOWGLI_PATRICIA_FOREACH(ce, &state, channellist)
    {
        ce->count -= rate;
        if (ce->count < 0)
            ce->count = 0;
    }
}

static void syn_cmd_setrate(sourceinfo_t *si, int parc, char **parv)
{
    if (parc < 2)
    {
        command_fail(si, fault_needmoreparams, STR_INSUFFICIENT_PARAMS, "SETRATE");
        command_fail(si, fault_needmoreparams, _("Syntax: SETRATE <rate> <burst>"));
        return;
    }
    int r, b;
    r = atoi(parv[0]);
    b = atoi(parv[1]);

    if (r * b == 0)
    {
        command_fail(si, fault_badparams, STR_INVALID_PARAMS, "SETRATE");
        command_fail(si, fault_needmoreparams, _("Syntax: SETRATE <rate> <burst>"));
        return;
    }

    rate = r;
    burst = b;

    event_delete(update_rate_settings, NULL);
    event_add("update_rate_settings", update_rate_settings, NULL, rate);

    command_success_nodata(si, "Warning threshold set to %d seconds, with a burst of %d", rate, burst);
}
