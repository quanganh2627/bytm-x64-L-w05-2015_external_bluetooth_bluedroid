/******************************************************************************
 *  Copyright (C) 2012-2013 Intel Mobile Communications GmbH *
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at:
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 ******************************************************************************/


/*****************************************************************************
 *
 *  Filename:      btif_test_testcase.c
 *
 *  Description:   Bluetooth Test implementation for Testing Lower Protocols like L2CAP, MCAP etc
 *
 *****************************************************************************/
#include <stdio.h>
#include <hardware/bluetooth.h>
#include <fcntl.h>
#include "bta_api.h"
#include "bd.h"
#include "gki.h"
#define LOG_TAG     "btif-test"

#include "btif_common.h"
#include "btif_test.h"
#include "btif_test_testcase.h"

tTC_STRUCT  tc_inst;

void TC_Init ( void *p )
{
    tc_inst.tc_cb = ( void (*) ( UINT8 ))p;
}

void TC_Select ( UINT8 tc_n )
{
    tc_inst.tc_number = tc_n;

    tc_inst.tc_d = 0;
    tc_inst.tc_depth = 0;

    memset(&tc_inst.tc_conf.tc_verdict, TC_VERDICT_FAIL, TEST_CASE_DEPTH);
}

UINT8 TC_GetTcNum (void)
{
    return tc_inst.tc_number;
}

void TC_Register  ( UINT8 tc_c, UINT8 tc_e )
{
    if ( tc_inst.tc_depth < TEST_CASE_DEPTH )
    {
        tc_inst.tc_conf.tc_cmds[tc_inst.tc_depth] = tc_c;
        tc_inst.tc_conf.tc_evts[tc_inst.tc_depth] = tc_e;
        tc_inst.tc_depth++;
    }
}

UINT8 TC_GetCmd ( void )
{
    return tc_inst.tc_conf.tc_cmds[tc_inst.tc_d];
}

UINT8 TC_GetEvt ( void )
{
    return tc_inst.tc_conf.tc_evts[tc_inst.tc_d];
}

void TC_Callback ( UINT8 tc_e )
{
    tc_inst.tc_cb(tc_e);
}

void TC_Update ( UINT8 tc_v )
{
    if( tc_inst.tc_d < tc_inst.tc_depth )
    {
        tc_inst.tc_conf.tc_verdict[tc_inst.tc_d] = tc_v;

        tc_inst.tc_d++;
        if( tc_inst.tc_d == tc_inst.tc_depth )
        {
            tc_inst.tc_cb(TC_EVENT_EXEC_EXIT);
        }
        else
        {
            tc_inst.tc_cb(TC_EVENT_EXEC_CONT);
        }
        tc_inst.tc_cb(tc_v);
    }
}

UINT8 TC_GetVerdict ( void )
{
    UINT8 c_loop;
    UINT8 tc_v = TC_VERDICT_PASS;

    for(c_loop = 0; c_loop < tc_inst.tc_depth; c_loop++)
    {
        if(tc_inst.tc_conf.tc_verdict[c_loop] != TC_VERDICT_PASS)
        {
            tc_v = tc_inst.tc_conf.tc_verdict[c_loop];
        }
    }
    return tc_v;
}
