/* 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of either:
 * 
 *   a) The GNU Lesser General Public License as published by the Free
 *      Software Foundation; either version 2.1, or (at your option) any
 *      later version, 
 * 
 *   OR
 * 
 *   b) The two-clause BSD license.
 *
 * These licenses can be found with the distribution in the file LICENSES
 */

#include "spf_sys_config.h"

#ifdef STDC_HEADERS
# include <stdlib.h>       /* malloc / free */
#endif

#ifdef HAVE_STRING_H
# include <string.h>       /* strstr / strdup */
#else
# ifdef HAVE_STRINGS_H
#  include <strings.h>       /* strstr / strdup */
# endif
#endif

#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif

#include "spf.h"
#include "spf_dns.h"
#include "spf_internal.h"
#include "spf_dns_internal.h"
#include "spf_dns_test.h"
#include "spf_dns_zone.h"


    
#define USE_SPF_SPEC_ZONE
#define USE_MAILZONE_ZONE
#define USE_EXT_MAILZONE_ZONE


typedef struct
{
    const char		*domain;
    int				 rr_type;
    SPF_dns_stat_t	 herrno;
    const char		*data;
} SPF_dns_test_data_t;
    



static const SPF_dns_test_data_t SPF_dns_db[] = {
    { "localhost",
      ns_t_a,   NETDB_SUCCESS, "127.0.0.1" },

#ifdef USE_SPF_SPEC_ZONE
    { "example.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.3" },
    { "example.com",
      ns_t_mx,  NETDB_SUCCESS, "mx.example.org" },
    { "example.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 mx -all" },
    { "3.2.0.192.in-addr.arpa",
      ns_t_ptr, NETDB_SUCCESS, "mx.example.org" },
    { "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.5.d.a.0.8.0.0.0.2.5.0.f.5.in6.arpa",
      ns_t_ptr, NETDB_SUCCESS, "mx.example.org" },

    { "noexist.example.com",
      ns_t_a,   HOST_NOT_FOUND, NULL },
    { "mx.example.org",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.3" },
    { "mx.example.org",
      ns_t_aaaa, NETDB_SUCCESS, "5f05:2000:80ad:5800::1" },
    { "email.example.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 -all" },
    { "*.example.com",
      ns_t_any, HOST_NOT_FOUND, NULL },
    { "*.example.org",
      ns_t_any, HOST_NOT_FOUND, NULL },
    { "*.example.net",
      ns_t_any, HOST_NOT_FOUND, NULL },
#endif

#ifdef USE_MAILZONE_ZONE
    { "01.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1                                                             " },
    { "02.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1                                             -all       " },
    { "03.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1                                             ~all" },
    { "05.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1                                             default=deny   " },
    { "06.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1                                             ?all " },
    { "07.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf2                                             default=bogus   " },
    { "08.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1                       -all      ?all  " },
    { "09.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1    scope=header-from scope=envelope         -all  " },
    { "10.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 mx                                          -all" },
    { "10.spf1-test.mailzone.com",
      ns_t_mx,  NETDB_SUCCESS, "mx02.spf1-test.mailzone.com" },
    { "10.spf1-test.mailzone.com",
      ns_t_mx,  NETDB_SUCCESS, "mx03.spf1-test.mailzone.com" },
    { "10.spf1-test.mailzone.com",
      ns_t_mx,  NETDB_SUCCESS, "mx01.spf1-test.mailzone.com" },
    { "11.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1    mx:spf1-test.mailzone.com                          -all" },
    { "12.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 mx mx:spf1-test.mailzone.com                          -all" },
    { "12.spf1-test.mailzone.com",
      ns_t_mx,  NETDB_SUCCESS, "mx02.spf1-test.mailzone.com" },
    { "12.spf1-test.mailzone.com",
      ns_t_mx,  NETDB_SUCCESS, "mx03.spf1-test.mailzone.com" },
    { "12.spf1-test.mailzone.com",
      ns_t_mx,  NETDB_SUCCESS, "mx01.spf1-test.mailzone.com" },
    { "13.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1    mx:spf1-test.mailzone.com mx:fallback-relay.spf1-test.mailzone.com -all" },
    { "14.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 mx mx:spf1-test.mailzone.com mx:fallback-relay.spf1-test.mailzone.com -all" },
    { "14.spf1-test.mailzone.com",
      ns_t_mx,  NETDB_SUCCESS, "mx03.spf1-test.mailzone.com" },
    { "14.spf1-test.mailzone.com",
      ns_t_mx,  NETDB_SUCCESS, "mx01.spf1-test.mailzone.com" },
    { "14.spf1-test.mailzone.com",
      ns_t_mx,  NETDB_SUCCESS, "mx02.spf1-test.mailzone.com" },
    { "20.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.120" },
    { "20.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 a                                           -all" },
    { "21.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1   a:spf1-test.mailzone.com                            -all" },
    { "21.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.121" },
    { "22.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 a a:spf1-test.mailzone.com                            -all" },
    { "22.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.122" },
    { "30.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 ptr                                         -all" },
    { "30.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "208.210.124.130" },
    { "31.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1     ptr:spf1-test.mailzone.com                        -all" },
    { "31.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "208.210.124.131" },
    { "32.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 ptr ptr:spf1-test.mailzone.com                        -all" },
    { "32.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "208.210.124.132" },
    { "40.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 exists:%{ir}.%{v}._spf.%{d}                    -all" },
    { "41.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 exists:%{ir}.%{v}._spf.spf1-test.mailzone.com            -all" },
    { "42.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 exists:%{ir}.%{v}._spf.%{d} exists:%{ir}.%{v}._spf.%{d3} -all" },
    { "45.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 -a a:spf1-test.mailzone.com                           -all" },
    { "45.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.147" },
    { "45.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.145" },
    { "45.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.146" },
    { "50.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 include                                     -all" },
    { "51.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 include:42.spf1-test.mailzone.com                  -all" },
    { "52.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 include:53.spf1-test.mailzone.com                  -all" },
    { "53.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 include:42.spf1-test.mailzone.com                  -all" },
    { "54.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 include:42.spf1-test.mailzone.com                  -all" },
    { "55.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 include:56.spf1-test.mailzone.com                  -all" },
    { "57.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 include:spf1-test.mailzone.com         -all" },
    { "58.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 include:59.spf1-test.mailzone.com                  -all" },
    { "59.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 include:58.spf1-test.mailzone.com                  -all" },
    { "70.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 exists:%{lr+=}.lp._spf.spf1-test.mailzone.com -all" },
    { "80.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 a mx exists:%{ir}.%{v}._spf.80.spf1-test.mailzone.com ptr -all" },
    { "80.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "208.210.124.180" },
    { "90.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1  ip4:192.0.2.128/25 -all" },
    { "91.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 -ip4:192.0.2.128/25 ip4:192.0.2.0/24 -all" },
    { "92.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 ?ip4:192.0.2.192/26 ip4:192.0.2.128/25 -ip4:192.0.2.0/24 -all" },
    { "95.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 exists:%{p}.whitelist.spf1-test.mailzone.com -all" },
    { "96.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 -exists:%{d}.blacklist.spf1-test.mailzone.com -all" },
    { "97.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 exists:%{p}.whitelist.spf1-test.mailzone.com -exists:%{d}.blacklist.spf1-test.mailzone.com -all" },
    { "98.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 a/26 mx/26 -all" },
    { "98.spf1-test.mailzone.com",
      ns_t_mx,  NETDB_SUCCESS, "80.spf1-test.mailzone.com" },
    { "98.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.98" },
    { "99.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 -all exp=99txt.spf1-test.mailzone.com moo" },
    { "99txt.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "u=%{u} s=%{s} d=%{d} t=%{t} h=%{h} i=%{i} %% U=%{U} S=%{S} D=%{D} T=%{T} H=%{H} I=%{I} %% moo" },
    { "100.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1      redirect=98.spf1-test.mailzone.com" },
    { "101.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 -all redirect=98.spf1-test.mailzone.com" },
    { "102.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 ?all redirect=98.spf1-test.mailzone.com" },
    { "103.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1      redirect=98.%{d3}" },
    { "104.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1      redirect=105.%{d3}" },
    { "105.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1      redirect=106.%{d3}" },
    { "106.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1      redirect=107.%{d3}" },
    { "107.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1       include:104.%{d3}" },
    { "110.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 some:unrecognized=mechanism some=unrecognized:modifier -all" },
    { "111.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 mx -a gpg ~all exp=111txt.spf1-test.mailzone.com" },
    { "111.spf1-test.mailzone.com",
      ns_t_mx,  NETDB_SUCCESS, "mx01.spf1-test.mailzone.com" },
    { "111.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.200" },
    { "111txt.2.0.192.in-addr._spf.spf1-test.mailzone.com",
      ns_t_txt,   NETDB_SUCCESS, "explanation text" },
    { "112.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 a mp3 ~all" },
    { "112.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.200" },
    { "113.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 a mp3: ~all" },
    { "113.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.200" },
    { "114.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 mx -a gpg=test ~all exp=114txt.spf1-test.mailzone.com" },
    { "114.spf1-test.mailzone.com",
      ns_t_mx,  NETDB_SUCCESS, "mx01.spf1-test.mailzone.com" },
    { "114.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.200" },
    { "114txt.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "explanation text" },
    { "115.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 a mp3=yes -all" },
    { "115.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.200" },
    { "116.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 redirect=116rdr.spf1-test.mailzone.com a" },
    { "116.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.200" },
    { "116rdr.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 -all" },
    { "117.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, " v=spf1 +all" },
    { "118.spf1-test.mailzone.com",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 -all exp=" },

    { "mx01.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.10" },
    { "mx01.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.11" },
    { "mx01.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.12" },
    { "mx01.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.13" },
    { "mx02.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.20" },
    { "mx02.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.21" },
    { "mx02.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.22" },
    { "mx02.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.23" },
    { "mx03.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.30" },
    { "mx03.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.31" },
    { "mx03.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.32" },
    { "mx03.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.33" },
    { "mx04.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.40" },
    { "mx04.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.41" },
    { "mx04.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.42" },
    { "mx04.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.43" },

    { "56.spf1-test.mailzone.com",
      ns_t_txt, NO_DATA, NULL },
    { "80.spf1-test.mailzone.com",
      ns_t_mx,  NO_DATA, NULL },
    { "servfail.spf1-test.mailzone.com",
      ns_t_txt, TRY_AGAIN, NULL },
    { "spf1-test.mailzone.com",
      ns_t_mx,  NETDB_SUCCESS, "mx02.spf1-test.mailzone.com" },
    { "spf1-test.mailzone.com",
      ns_t_mx,  NETDB_SUCCESS, "mx03.spf1-test.mailzone.com" },
    { "spf1-test.mailzone.com",
      ns_t_mx,  NETDB_SUCCESS, "mx01.spf1-test.mailzone.com" },
    { "spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "208.210.124.192" },
    { "spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "192.0.2.200" },
    { "fallback-relay.spf1-test.mailzone.com",
      ns_t_mx,  NETDB_SUCCESS, "mx04.spf1-test.mailzone.com" },
    
    { "www1.cnn.com",
      ns_t_a,   NETDB_SUCCESS, "64.236.24.4" },
    { "4.24.236.64.in-addr.arpa",
      ns_t_ptr, NETDB_SUCCESS, "www1.cnn.com" },
    { "130.124.210.208.in-addr.arpa",
      ns_t_ptr, NETDB_SUCCESS, "30.spf1-test.mailzone.com" },
    { "131.124.210.208.in-addr.arpa",
      ns_t_ptr, NETDB_SUCCESS, "31.spf1-test.mailzone.com" },
    { "192.124.210.208.in-addr.arpa",
      ns_t_ptr, NETDB_SUCCESS, "spf1-test.mailzone.com" },
    { "100.2.0.192.in-addr._spf.40.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "127.0.0.2" },

    { "110.2.0.192.in-addr._spf.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "127.0.0.2" },
    { "111.2.0.192.in-addr._spf.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "127.0.0.2" },
    { "101.2.0.192.in-addr._spf.40.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "127.0.0.2" },
    { "130.2.0.192.in-addr._spf.42.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "127.0.0.2" },
    { "131.2.0.192.in-addr._spf.42.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "127.0.0.2" },
    { "80.2.0.192.in-addr._spf.80.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "127.0.0.2" },
    { "96.spf1-test.mailzone.com.blacklist.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "127.0.0.2" },
    { "97.spf1-test.mailzone.com.blacklist.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "127.0.0.2" },
    { "bob.lp._spf.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "127.0.0.2" },
    { "postmaster.lp._spf.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "127.0.0.2" },
    { "1.bob.lp._spf.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "127.0.0.2" },
    { "2.bob.lp._spf.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "127.0.0.2" },
    { "1.joe.lp._spf.spf1-test.mailzone.com",
      ns_t_a,   HOST_NOT_FOUND, NULL },
    { "100.2.0.192.in-addr._spf.42.spf1-test.mailzone.com",
      ns_t_a,   HOST_NOT_FOUND, NULL },
    { "100.2.0.192.in-addr._spf.spf1-test.mailzone.com",
      ns_t_a,   HOST_NOT_FOUND, NULL },
    { "102.2.0.192.in-addr._spf.40.spf1-test.mailzone.com",
      ns_t_a,   HOST_NOT_FOUND, NULL },
    { "110.2.0.192.in-addr._spf.42.spf1-test.mailzone.com",
      ns_t_a,   HOST_NOT_FOUND, NULL },
    { "130.2.0.192.in-addr._spf.spf1-test.mailzone.com",
      ns_t_a,   HOST_NOT_FOUND, NULL },
    { "131.2.0.192.in-addr._spf.spf1-test.mailzone.com",
      ns_t_a,   HOST_NOT_FOUND, NULL },
    { "4.24.236.64.in-addr._spf.80.spf1-test.mailzone.com",
      ns_t_a,   HOST_NOT_FOUND, NULL },
    { "droid.lp._spf.spf1-test.mailzone.com",
      ns_t_a,   HOST_NOT_FOUND, NULL },
    { "joe-2.lp._spf.spf1-test.mailzone.com",
      ns_t_a,   HOST_NOT_FOUND, NULL },
    { "moe-1.lp._spf.spf1-test.mailzone.com",
      ns_t_a,   HOST_NOT_FOUND, NULL },
    { "unknown.whitelist.spf1-test.mailzone.com",
      ns_t_a,   HOST_NOT_FOUND, NULL },

    { "180.124.210.208.in-addr.arpa",
      ns_t_ptr, NETDB_SUCCESS, "80.spf1-test.mailzone.com" },

    { "80.spf1-test.mailzone.com.whitelist.spf1-test.mailzone.com",
      ns_t_a,   NETDB_SUCCESS, "127.0.0.2" },
    { "1.124.210.208.in-addr.arpa",
      ns_t_ptr, NETDB_SUCCESS, "pobox-gw.icgroup.com" },

    { "pobox-gw.icgroup.com",
      ns_t_a,   NETDB_SUCCESS, "208.210.124.1" },
    { "pobox-gw.icgroup.com.whitelist.spf1-test.mailzone.com",
      ns_t_a,   HOST_NOT_FOUND, NULL },

    { "200.2.0.192.in-addr._spf.51.spf1-test.mailzone.com",
      ns_t_a,   HOST_NOT_FOUND, NULL },
    { "200.2.0.192.in-addr._spf.spf1-test.mailzone.com",
      ns_t_a,   HOST_NOT_FOUND, NULL },
    { "130.2.0.192.in-addr._spf.51.spf1-test.mailzone.com",
      ns_t_a,   HOST_NOT_FOUND, NULL },
    { "200.2.0.192.in-addr._spf.42.spf1-test.mailzone.com",
      ns_t_a,   HOST_NOT_FOUND, NULL },
    { "spf1-test.mailzone.com",
      ns_t_txt, HOST_NOT_FOUND, NULL },
    { "spf.trusted-forwarder.org",
      ns_t_txt, NETDB_SUCCESS, "v=spf1 exists:%{ir}.wl.trusted-forwarder.org exists:%{p}.wl.trusted-forwarder.org" },
    { "*.spf1-text.mailzone.com",
      ns_t_any, HOST_NOT_FOUND, NULL },

    { "cat.com",
      ns_t_txt, NO_DATA, NULL },
    { "bar.com",
      ns_t_txt, NO_DATA, NULL },
    

#endif

#ifdef USE_EXT_MAILZONE_ZONE
    { "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.5.d.a.0.8.0.0.0.2.5.0.f.5.in6.arpa",
      ns_t_ptr, NETDB_SUCCESS, "mx.example.org" },

#endif
};



SPF_dns_server_t *
SPF_dns_test_new(SPF_dns_server_t *layer_below,
				const char *name, int debug)
{
	SPF_dns_server_t	*spf_dns_server;
    int					 i;
    
	if (name == NULL)
		name = "test";
    spf_dns_server = SPF_dns_zone_new(layer_below, name, debug);
	if (spf_dns_server == NULL)
		return NULL;

	for( i = 0; i < array_elem( SPF_dns_db ); i++ ) {
		if (SPF_dns_zone_add_str(spf_dns_server,
						  SPF_dns_db[i].domain,
						  SPF_dns_db[i].rr_type, 
						  SPF_dns_db[i].herrno, 
						  SPF_dns_db[i].data) != SPF_E_SUCCESS)
			SPF_error( "Could not create test zone" );
	}

    return spf_dns_server;
}
