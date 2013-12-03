/******************************************************************************
 *  Copyright (C) 2012-2013 Intel Mobile Communications GmbH
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
 *  Filename:      btif_test_testcase.h
 *
 *  Description:   Bluetooth Test implementation for Testing Lower Protocols like L2CAP, MCAP etc
 *
 *****************************************************************************/
#ifndef ANDROID_INCLUDE_BTIF_TEST_TESTCASE_H
#define ANDROID_INCLUDE_BTIF_TEST_TESTCASE_H

#include <stdio.h>

#define TEST_CASE_DEPTH                 10

#define TC_SUCCESS                      0
#define TC_FAILURE                      1
#define TC_WAIT_TIME                    30

#define TC_CMD_EXEC_WAIT                0xFF

#define TC_EVENT_EXEC_WAIT              0
#define TC_EVENT_EXEC_CONT              1
#define TC_EVENT_EXEC_EXIT              2
#define TC_EVENT_EXEC_TOUT              3
#define TC_EVENT_CONN_CFM               4
#define TC_EVENT_CONN_FAILED            5
#define TC_EVENT_VER_PASS               6
#define TC_EVENT_VER_FAIL               7
#define TC_EVENT_VER_INCONC             8


#define TC_VERDICT_PASS                 0xFE
#define TC_VERDICT_FAIL                 0xFD
#define TC_VERDICT_INCONC               0xFC

typedef void (*pf_cb) ( UINT8 );

typedef struct {
    UINT8 tc_cmds[TEST_CASE_DEPTH];
    UINT8 tc_evts[TEST_CASE_DEPTH];
    UINT8 tc_verdict[TEST_CASE_DEPTH];
} tTC_CONF;

typedef struct {
    pf_cb tc_cb;
    UINT8 tc_number;
    UINT8 tc_depth;
    UINT8 tc_d;

    tTC_CONF tc_conf;
} tTC_STRUCT;

void TC_Init ( void * );
void TC_Select ( UINT8 );
UINT8 TC_GetTcNum (void);
void TC_Register  ( UINT8, UINT8 );
UINT8 TC_GetCmd ( void );
UINT8 TC_GetEvt ( void );
void TC_Callback ( UINT8 );
void TC_Update ( UINT8 );
UINT8 TC_GetVerdict ( void );

#endif
