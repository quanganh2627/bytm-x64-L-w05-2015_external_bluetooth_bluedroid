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
 *  Filename:      btif_test_bnep_tester.c
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
#include "bnep_api.h"

/*****************************************************************************/
/* BNEP Tester */
/*****************************************************************************/
UINT8 bnep_data[25];
UINT16 p_handle = 0;
UINT8 bnep_role = 0; // Server
UINT8 bnep_data_size = 0;
UINT8 dest_address[] =   {0x00,0x01,0x02,0x03,0x04,0x05};
UINT8 source_address[] = {0x05,0x04,0x03,0x02,0x01,0x00};

#define BNEPTEST_CONTROL_UNDEFINED_MSG              0x01
#define BNEPTEST_CONTROL_SETUP_MSG                  0x02

/*****************************************************************************/
static void bnep_conn_ind_cb (
                UINT16 handle,
                BD_ADDR bd_addr,
                tBT_UUID *remote_uuid,
                tBT_UUID *local_uuid,
                BOOLEAN is_role_change )
{
    ALOGI("%s", __FUNCTION__);

    p_handle = handle;
    BNEP_ConnectResp(handle, BNEP_SUCCESS);
}

static void bnep_connect_state_cb (
                UINT16 handle,
                BD_ADDR rem_bda,
                tBNEP_RESULT result,
                BOOLEAN is_role_change )
{
    ALOGI("%s", __FUNCTION__);

    if(result == BNEP_SUCCESS)
    {
        ALOGI("BNEP Connection Success");
    }
    else if(result == BNEP_CONN_DISCONNECTED)
    {
        ALOGI("BNEP Disconnection Success");
    }
    else
    {
        ALOGE("BNEP Connection Rejected");
    }
}

static void bnep_data_ind_cb (
                UINT16 handle,
                UINT8 *src,
                UINT8 *dst,
                UINT16 protocol,
                UINT8 *p_data,
                UINT16 len,
                BOOLEAN fw_ext_present )
{
    ALOGI("%s", __FUNCTION__);
}

static void bnep_data_buf_ind_cb (
                UINT16 handle,
                UINT8 *src,
                UINT8 *dst,
                UINT16 protocol,
                BT_HDR *p_hdr,
                BOOLEAN fw_ext_present )
{
    ALOGI("%s", __FUNCTION__);

    UINT8 *p_data, len, extn, l, e_length = 0;
    UINT8 cmd, c_type, *p, e_header = 0;

    p_data = (UINT8 *)(p_hdr + 1) + p_hdr->offset;
    p = p_data;

    ALOGD("Data Length = %d", p_hdr->len);
#if 0
    for(l = 0; l < p_hdr->len; l++)
    {
        ALOGD("Data = %x", *p);
        p++;
    }
#endif
    do
    {
        cmd = *p_data++;
        extn = cmd & 0x01;
        cmd &= 0xFE;
        cmd >>= 1;
        ALOGI("cmd = %x", cmd);

        if(e_header)
        {
            e_length = *p_data++;
            ALOGI("Extn Length = %x", e_length);
        }

        if((cmd == BNEP_FRAME_CONTROL) || (cmd == BNEP_EXTENSION_FILTER_CONTROL))
        {
            c_type = *p_data++;
            switch(c_type)
            {
                case BNEP_CONTROL_COMMAND_NOT_UNDERSTOOD:
                    ALOGI("Received Control Command Not Understood");
                break;

                case BNEP_SETUP_CONNECTION_REQUEST_MSG:
                    ALOGI("Received Setup Connection Request");
                    bnep_data[0] = BNEP_FRAME_CONTROL << 1;
                    bnep_data[1] = BNEP_SETUP_CONNECTION_RESPONSE_MSG;
                    bnep_data[2] = 0x00;
                    p = &bnep_data[3];
                    UINT16_TO_BE_STREAM (p, UUID_SERVCLASS_PANU);
                    p = &bnep_data[5];
                    UINT16_TO_BE_STREAM (p, UUID_SERVCLASS_NAP);
                    bnep_data_size = 0x07;

                    for(l = 0; l < 5; l++)
                    {
                        p_data++;
                    }
                    ALOGI("Sending Setup Connection response");

                    BNEP_Write(handle, dst, bnep_data, bnep_data_size, 0x0800, src, FALSE);
                break;

                case BNEP_FILTER_NET_TYPE_SET_MSG:
                    ALOGI("Received Filter Net Set Request");
                    bnep_data[0] = BNEP_FRAME_CONTROL << 1;
                    bnep_data[1] = BNEP_FILTER_NET_TYPE_RESPONSE_MSG;
                    p = &bnep_data[2];
                    UINT16_TO_BE_STREAM (p, 0x0000);
                    bnep_data_size = 0x04;
                    for(l = 0; l < 9; l++)
                    {
                        p_data++;
                    }

                    BNEP_Write(handle, dst, bnep_data, bnep_data_size, 0x0800, src, FALSE);
                break;

                case BNEP_FILTER_MULTI_ADDR_SET_MSG:
                    ALOGI("Received Filter Multi Address Request");
                    bnep_data[0] = BNEP_FRAME_CONTROL << 1;
                    bnep_data[1] = BNEP_FILTER_MULTI_ADDR_RESPONSE_MSG;
                    p = &bnep_data[2];
                    UINT16_TO_BE_STREAM (p, 0x0000);
                    bnep_data_size = 0x04;
                    if(e_header)
                    {
                        for(l = 0; l < 10; l++)
                        {
                            p_data++;
                        }
                    }

                    BNEP_Write(handle, dst, bnep_data, bnep_data_size, 0x0800, src, FALSE);
                break;

                case BNEP_SETUP_CONNECTION_RESPONSE_MSG:
                    if(*p_data++ == 0x00)
                    {
                        ALOGI("BNEP Setup Succeded");
                    }
                    else
                    {
                        ALOGI("BNEP Setup Failed");
                    }
                break;

                case BNEP_FILTER_NET_TYPE_RESPONSE_MSG:
                break;

                case BNEP_FILTER_MULTI_ADDR_RESPONSE_MSG:
                break;

                default:
                    ALOGI("Unknown BNEP Command");
                    bnep_data[0] = BNEP_FRAME_CONTROL << 1;
                    bnep_data[1] = BNEP_CONTROL_COMMAND_NOT_UNDERSTOOD;
                    bnep_data[2] = *p_data;

                    bnep_data_size = 0x03;
                    BNEP_Write(handle, dst, bnep_data, bnep_data_size, 0x0800, src, FALSE);
                break;
            }
        }
        else if(cmd == BNEP_FRAME_GENERAL_ETHERNET)
        {
            ALOGI("BNEP_FRAME_GENERAL_ETHERNET");
            for(l = 0; l < 14; l++)
            {
                p_data++;
            }
        }
        else if(cmd == BNEP_FRAME_COMPRESSED_ETHERNET)
        {
            ALOGI("BNEP_FRAME_COMPRESSED_ETHERNET");
            p_data++;
            p_data++;
        }
        else
        {
            if(e_header == 1)
            {
                ALOGI("Unknown BNEP Command");
                bnep_data[0] = BNEP_FRAME_CONTROL << 1;
                bnep_data[1] = BNEP_CONTROL_COMMAND_NOT_UNDERSTOOD;
                bnep_data[2] = cmd;

                bnep_data_size = 0x03;
                BNEP_Write(handle, dst, bnep_data, bnep_data_size, 0x0800, src, FALSE);
            }

            for(l = 0; l < e_length; l++)
            {
                p_data++;
            }
        }
        e_header = 1;
    } while(extn);
}

static void bnep_tx_data_flow_cb (
                UINT16 handle,
                tBNEP_RESULT  event )
{
    ALOGI("%s", __FUNCTION__);
}

/*****************************************************************************/
static void BNEPTest_init ( void )
{
    ALOGI("%s", __FUNCTION__);

    tBNEP_REGISTER      reg_info;

    memset(&reg_info, 0, sizeof (tBNEP_REGISTER));
    reg_info.p_conn_ind_cb      = bnep_conn_ind_cb;
    reg_info.p_conn_state_cb    = bnep_connect_state_cb;
    reg_info.p_data_buf_cb      = bnep_data_buf_ind_cb;
    reg_info.p_data_ind_cb      = bnep_data_ind_cb;
    reg_info.p_tx_data_flow_cb  = bnep_tx_data_flow_cb;
    reg_info.p_filter_ind_cb    = NULL;
    reg_info.p_mfilter_ind_cb   = NULL;

    BNEP_Register(&reg_info);

    BTM_SetSecurityLevel (TRUE, "", BTM_SEC_SERVICE_BNEP_PANU,
        BTM_SEC_NONE, BT_PSM_BNEP, BTM_SEC_PROTO_BNEP, UUID_SERVCLASS_PANU);

    BTM_SetSecurityLevel (FALSE, "", BTM_SEC_SERVICE_BNEP_PANU,
        BTM_SEC_NONE, BT_PSM_BNEP, BTM_SEC_PROTO_BNEP, UUID_SERVCLASS_PANU);

    BTM_SetSecurityLevel (TRUE, "", BTM_SEC_SERVICE_BNEP_NAP,
        BTM_SEC_NONE, BT_PSM_BNEP, BTM_SEC_PROTO_BNEP, UUID_SERVCLASS_NAP);

    BTM_SetSecurityLevel (FALSE, "", BTM_SEC_SERVICE_BNEP_NAP,
        BTM_SEC_NONE, BT_PSM_BNEP, BTM_SEC_PROTO_BNEP, UUID_SERVCLASS_NAP);
}

static void BNEPTest_send_control_msg ( UINT8 type )
{
    ALOGI("%s : Control Type = %d", __FUNCTION__, type);

    UINT8 *p;
    switch(type)
    {
        case BNEPTEST_CONTROL_UNDEFINED_MSG:
            bnep_data[0] = BNEP_FRAME_CONTROL << 1;
            bnep_data[1] = 0xFF;

            bnep_data_size = 0x02;
        break;

        case BNEPTEST_CONTROL_SETUP_MSG:
            bnep_data[0] = BNEP_FRAME_CONTROL << 1;
            bnep_data[1] = BNEP_SETUP_CONNECTION_REQUEST_MSG;
            bnep_data[2] = 0x02;
            p = &bnep_data[3];
            UINT16_TO_BE_STREAM (p, UUID_SERVCLASS_PANU);
            p = &bnep_data[5];
            UINT16_TO_BE_STREAM (p, UUID_SERVCLASS_NAP);

            bnep_data_size = 0x07;
        break;

        default:
        break;
    }

    BNEP_Write(p_handle, dest_address, bnep_data, bnep_data_size, 0x0800, source_address, TRUE);
}

static const bnep_test_interface_t bnep_test_interface = {
    sizeof(bnep_test_interface_t),
    BNEPTest_init,
    BNEPTest_send_control_msg
};

const bnep_test_interface_t *btif_get_bnep_test_interface(void)
{
    ALOGI("%s", __FUNCTION__);
    return &bnep_test_interface;
}
