#ifndef syn_h
#define syn_h

list_t *syn_cmdtree;
list_t *syn_helptree;

void (*syn_report)(char *, ...);

inline void use_syn_main_symbols(module_t *m)
{
    MODULE_USE_SYMBOL(syn_cmdtree, "syn/main", "syn_cmdtree");
    MODULE_USE_SYMBOL(syn_helptree, "syn/main", "syn_helptree");
    MODULE_USE_SYMBOL(syn_report, "syn/main", "syn_report");
}


#endif
