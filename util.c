#include "atheme.h"

DECLARE_MODULE_V1
(
        "syn/util", false, NULL, NULL,
        "$Revision$",
        "Stephen Bennett <stephen -at- freenode.net>"
);

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

const char *get_random_host_part()
{
    static char buf[19];

    strcpy(buf, "x-");

    for (int i=2; i < 18; ++i)
    {
        buf[i] = 'a' + rand() % 26;
    }
    buf[18] = 0;
    return buf;
}


