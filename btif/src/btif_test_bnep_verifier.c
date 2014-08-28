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
 *  Filename:      btif_bnep_verifier.c
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
#include "btif_test_testcase.h"

/************************************************************************************
 **  Constants & Macros
 ************************************************************************************/
BD_ADDR rbd_addr;

UINT8 bnep_data[2048];
UINT16 p_handle = 0;
UINT16 bnep_data_size = 0;

UINT8 dest_address[]   = {0x00,0x01,0x02,0x03,0x04,0x05};
UINT8 source_address[] = {0x05,0x04,0x03,0x02,0x01,0x00};

UINT16 l_uuid = UUID_SERVCLASS_NAP;
UINT16 r_uuid = UUID_SERVCLASS_PANU;

/* BNEP frame types
*/
#define BNEP_FRAME_GENERAL_ETHERNET                 0x00
#define BNEP_FRAME_CONTROL                          0x01
#define BNEP_FRAME_COMPRESSED_ETHERNET              0x02
#define BNEP_FRAME_COMPRESSED_ETHERNET_SRC_ONLY     0x03
#define BNEP_FRAME_COMPRESSED_ETHERNET_DEST_ONLY    0x04

/* BNEP filter control message types
*/
#define BNEP_CONTROL_COMMAND_NOT_UNDERSTOOD         0x00
#define BNEP_SETUP_CONNECTION_REQUEST_MSG           0x01
#define BNEP_SETUP_CONNECTION_RESPONSE_MSG          0x02
#define BNEP_FILTER_NET_TYPE_SET_MSG                0x03
#define BNEP_FILTER_NET_TYPE_RESPONSE_MSG           0x04
#define BNEP_FILTER_MULTI_ADDR_SET_MSG              0x05
#define BNEP_FILTER_MULTI_ADDR_RESPONSE_MSG         0x06

/***********************************************************************************************************************/
static void bnepv_conn_ind_cb (
                UINT16 handle,
                BD_ADDR bd_addr,
                tBT_UUID *remote_uuid,
                tBT_UUID *local_uuid,
                BOOLEAN is_role_change )
{
    // ALOGI("%s", __FUNCTION__);

    UINT16 ruuid, ruuid_len;
    UINT16 luuid, luuid_len;

    p_handle = handle;
    ALOGD("Received Connection Request");
    ALOGD("{");
    ALOGD("\t Handle = %04x", handle);
    ALOGD("\t BD_ADDR = %x:%x:%x:%x:%x:%x", bd_addr[0], bd_addr[1], bd_addr[2], bd_addr[3], bd_addr[4], bd_addr[5]);
    ALOGD("\t Remote UUID");
    ruuid_len = remote_uuid->len;
    ALOGD("\t\tRemote UUID Len = %d", remote_uuid->len);
    ruuid = remote_uuid->uu.uuid16;
    ALOGD("\t\tRemote UUID = 0x%x", ruuid);
    ALOGD("\tLocal UUID");
    luuid_len = local_uuid->len;
    ALOGD("\t\tLocal UUID Len = %d", local_uuid->len);
    luuid = local_uuid->uu.uuid16;
    ALOGD("\t\tLocal UUID = 0x%x", luuid);
    ALOGD("\tRole Change = %s", (is_role_change == TRUE) ? "TRUE" : "FALSE");
    ALOGD("}");
    ALOGD(" ");

    if((ruuid_len != 2) || (luuid_len != 2))
    {
        ALOGE("Rejecting connection due to wrong UUID size");
        BNEP_ConnectResp(handle, BNEP_CONN_FAILED_UUID_SIZE);

        return;
    }

    if(ruuid != l_uuid)
    {
        ALOGE("Rejecting connection due to wrong UUID");
        BNEP_ConnectResp(handle, BNEP_CONN_FAILED_SRC_UUID);

        return;
    }

    if(luuid != r_uuid)
    {
        ALOGE("Rejecting connection due to wrong UUID");
        BNEP_ConnectResp(handle, BNEP_CONN_FAILED_DST_UUID);

        return;
    }

    ALOGI("Accepting connection ... ");
    BNEP_ConnectResp(handle, BNEP_SUCCESS);
}

static void bnepv_connect_state_cb (
                UINT16 handle,
                BD_ADDR rem_bda,
                tBNEP_RESULT result,
                BOOLEAN is_role_change )
{
    // ALOGI("%s", __FUNCTION__);

    ALOGD("Connection State Changed");
    ALOGD("{");
    ALOGD("\tHandle = %04x", handle);
    ALOGD("\tBD ADDR = %x:%x:%x:%x:%x:%x", rem_bda[0], rem_bda[1], rem_bda[2], rem_bda[3], rem_bda[4], rem_bda[5]);
    ALOGD("\tResult = %d", result);
    ALOGD("\tRole Change = %s", (is_role_change == TRUE) ? "TRUE" : "FALSE");
    ALOGD("}");
    ALOGD(" ");

    if(result == BNEP_SUCCESS)
    {
        ALOGI("BNEP Connection Success");
        TC_Callback(TC_EVENT_CONN_CFM);
    }
    else
    {
        TC_Callback(TC_EVENT_CONN_FAILED);
        ALOGE("BNEP Connection Rejected");
    }
}

static void bnepv_data_ind_cb (
                UINT16 handle,
                UINT8 *src,
                UINT8 *dst,
                UINT16 protocol,
                UINT8 *p_data,
                UINT16 len,
                BOOLEAN fw_ext_present )
{
    // ALOGI("%s", __FUNCTION__);
}

static void bnepv_data_buf_ind_cb (
                UINT16 handle,
                UINT8 *src,
                UINT8 *dst,
                UINT16 protocol,
                BT_HDR *p_hdr,
                BOOLEAN fw_ext_present )
{
    // ALOGI("%s", __FUNCTION__);

    static UINT8 ign = 0;
    UINT8 *p_data, len, extn;
    UINT8 cmd, c_type, *p;
    UINT16 s_uuid, d_uuid, result;

    p_data = (UINT8 *)(p_hdr + 1) + p_hdr->offset;
#if 0
    p = p_data;
        ALOGI("Data Length = %d", p_hdr->len);
        for(len = 0; len < p_hdr->len; len++)
    {
        ALOGI("Data = %x", *p);
        p++;
    }
#endif
    cmd = *p_data++;
    cmd &= 0xFE;
    cmd >>= 1;

    if(cmd == BNEP_FRAME_CONTROL)
    {
        ALOGD(" ");
        ALOGD("Received Event : Received BNEP Control Frame");
        ALOGD("{");
        ALOGD("\tBNEP Frame Type = BNEP_FRAME_CONTROL");
        ALOGD("\tBNEP Frame Extension = FALSE");
        c_type = *p_data++;
        switch(c_type)
        {
            case BNEP_SETUP_CONNECTION_REQUEST_MSG:
                ALOGD("\tBNEP Control Type = BNEP_SETUP_CONNECTION_REQUEST_MSG");
                ALOGD("\tUUID Size = %x", *p_data);
                p_data++;
                BE_STREAM_TO_UINT16(s_uuid, p_data);
                ALOGD("\tSrc UUID = 0x%04x", s_uuid);
                BE_STREAM_TO_UINT16(d_uuid, p_data);
                ALOGD("\tDst UUID = 0x%04x", d_uuid);
                ALOGD("}");

                if(TC_GetEvt() != BNEP_SETUP_CONNECTION_REQUEST_MSG)
                {
                    TC_Update(TC_VERDICT_FAIL);
                    ALOGE("Received Wrong Command");
                }
                else
                {
                    if(!ign)
                    {
                        ign = 1;
                        ALOGI("Ignoring the setup message");
                    }
                    else
                    {
                        ign = 0;
                        BNEP_Write(handle, dst, bnep_data, bnep_data_size, 0x0800, src, TRUE);
                    }
                    TC_Update(TC_VERDICT_PASS);
                }
            break;

            case BNEP_SETUP_CONNECTION_RESPONSE_MSG:
                ALOGD("\tBNEP Control Type = BNEP_SETUP_CONNECTION_RESPONSE_MSG");
                ALOGD("\tResult = %x, %s", *p_data, *p_data == 0x00 ? "SUCCESS" : "FAILURE");
                ALOGD("}");
                if(TC_GetEvt() != BNEP_SETUP_CONNECTION_RESPONSE_MSG)
                {
                    TC_Update(TC_VERDICT_FAIL);
                    ALOGE("Received Wrong Command");
                }
                else
                {
                    if(*p_data++ == 0x00)
                    {
                        ALOGI("BNEP Setup Succeded");
                    }
                    else
                    {
                        ALOGI("BNEP Setup Rejected");
                    }
                    TC_Update(TC_VERDICT_PASS);
                }
            break;

            case BNEP_CONTROL_COMMAND_NOT_UNDERSTOOD:
                ALOGD("\tBNEP Control Type = BNEP_CONTROL_COMMAND_NOT_UNDERSTOOD");
                ALOGD("\tCmd = 0x%02x", *p_data);
                ALOGD("}");
                if(TC_GetEvt() != BNEP_CONTROL_COMMAND_NOT_UNDERSTOOD)
                {
                    TC_Update(TC_VERDICT_FAIL);
                    ALOGE("Wrong BNEP Command");
                }
                else
                {
                    TC_Update(TC_VERDICT_PASS);
                }
            break;

            case BNEP_FILTER_NET_TYPE_SET_MSG:
            break;

            case BNEP_FILTER_NET_TYPE_RESPONSE_MSG:
                ALOGD("\tBNEP Control Type = BNEP_FILTER_NET_TYPE_RESPONSE_MSG");
                BE_STREAM_TO_UINT16(result, p_data);
                ALOGD("\tResult = %x, %s", result, result == 0x00 ? "SUCCESS" : "FAILURE");
                ALOGD("}");
                if(TC_GetEvt() != BNEP_FILTER_NET_TYPE_RESPONSE_MSG)
                {
                    TC_Update(TC_VERDICT_FAIL);
                    ALOGE("Wrong BNEP Command");
                }
                else
                {
                    TC_Update(TC_VERDICT_PASS);
                }
            break;

            case BNEP_FILTER_MULTI_ADDR_SET_MSG:
            break;

            case BNEP_FILTER_MULTI_ADDR_RESPONSE_MSG:
                ALOGD("\tBNEP Control Type = BNEP_FILTER_MULTI_ADDR_RESPONSE_MSG");
                BE_STREAM_TO_UINT16(result, p_data);
                ALOGD("\tResult = %x, %s", result, result == 0x00 ? "SUCCESS" : "FAILURE");
                ALOGD("}");
                if(TC_GetEvt() != BNEP_FILTER_MULTI_ADDR_RESPONSE_MSG)
                {
                    TC_Update(TC_VERDICT_FAIL);
                    ALOGE("Wrong BNEP Command");
                }
                else
                {
                    TC_Update(TC_VERDICT_PASS);
                }
            break;

            default:
                ALOGE("Unknown BNEP Command");
                TC_Update(TC_VERDICT_FAIL);
            break;
        }
    }
}

static void bnepv_tx_data_flow_cb (
                UINT16 handle,
                tBNEP_RESULT  event )
{
    // ALOGI("%s", __FUNCTION__);
}

/***********************************************************************************************************************/
static void BNEPV_init ( void *p )
{
    ALOGI("%s", __FUNCTION__);

    tBNEP_REGISTER      reg_info;

    memset(&reg_info, 0, sizeof (tBNEP_REGISTER));
    reg_info.p_conn_ind_cb      = bnepv_conn_ind_cb;
    reg_info.p_conn_state_cb    = bnepv_connect_state_cb;
    reg_info.p_data_buf_cb      = bnepv_data_buf_ind_cb;
    reg_info.p_data_ind_cb      = bnepv_data_ind_cb;
    reg_info.p_tx_data_flow_cb  = bnepv_tx_data_flow_cb;
    reg_info.p_filter_ind_cb    = NULL;
    reg_info.p_mfilter_ind_cb   = NULL;

    BNEP_Register(&reg_info);

    TC_Init(p);

    BTM_SetSecurityLevel (TRUE, "", BTM_SEC_SERVICE_BNEP_PANU,
        BTM_SEC_NONE, BT_PSM_BNEP, BTM_SEC_PROTO_BNEP, UUID_SERVCLASS_PANU);

    BTM_SetSecurityLevel (FALSE, "", BTM_SEC_SERVICE_BNEP_PANU,
        BTM_SEC_NONE, BT_PSM_BNEP, BTM_SEC_PROTO_BNEP, UUID_SERVCLASS_PANU);

    BTM_SetSecurityLevel (TRUE, "", BTM_SEC_SERVICE_BNEP_NAP,
        BTM_SEC_NONE, BT_PSM_BNEP, BTM_SEC_PROTO_BNEP, UUID_SERVCLASS_NAP);

    BTM_SetSecurityLevel (FALSE, "", BTM_SEC_SERVICE_BNEP_NAP,
        BTM_SEC_NONE, BT_PSM_BNEP, BTM_SEC_PROTO_BNEP, UUID_SERVCLASS_NAP);
}

static void BNEPV_set_remote_bd_addr(BD_ADDR* p_bd_addr)
{
    // ALOGI("%s", __FUNCTION__);

    memcpy(&rbd_addr, p_bd_addr, sizeof(BD_ADDR));
}

static void BNEPV_select_test_case ( UINT8 tc, UINT8 *p_str )
{
    // ALOGI("%s : Test Case = %d", __FUNCTION__, tc);

    ALOGI("================================================================");
    ALOGI("============ Executing : %s =================", (char *)p_str);

    TC_Select(tc);

    switch(tc)
    {
        case 1:
            TC_Register(BNEP_CONTROL_COMMAND_NOT_UNDERSTOOD, BNEP_CONTROL_COMMAND_NOT_UNDERSTOOD);
            ALOGI("Unknown Control Message before BNEP_SETUP_CONNECTION");
        break;

        case 2:
            TC_Register(TC_CMD_EXEC_WAIT, BNEP_SETUP_CONNECTION_REQUEST_MSG);
            TC_Register(TC_CMD_EXEC_WAIT, BNEP_SETUP_CONNECTION_REQUEST_MSG);
            ALOGI("Setup Connection Message Lost");
        break;

        case 3:
            TC_Register(BNEP_SETUP_CONNECTION_REQUEST_MSG, BNEP_SETUP_CONNECTION_RESPONSE_MSG);
            ALOGI("Setup Connection Message");
        break;

        case 4:
            TC_Register(BNEP_SETUP_CONNECTION_REQUEST_MSG, BNEP_SETUP_CONNECTION_RESPONSE_MSG);
            TC_Register(BNEP_SETUP_CONNECTION_REQUEST_MSG, BNEP_SETUP_CONNECTION_RESPONSE_MSG);
            ALOGI("Setup Connection Message after BNEP Connection setup has completed");
        break;

        case 5:
            TC_Register(BNEP_SETUP_CONNECTION_REQUEST_MSG, BNEP_SETUP_CONNECTION_RESPONSE_MSG);
            TC_Register(BNEP_CONTROL_COMMAND_NOT_UNDERSTOOD, BNEP_CONTROL_COMMAND_NOT_UNDERSTOOD);
            ALOGI("Unknown Control Message after BNEP Setup Connection Message");
        break;

        case 6:
            TC_Register(6, BNEP_FILTER_MULTI_ADDR_RESPONSE_MSG);
            ALOGI("Extension Header Message");
        break;

        case 7:
            /* To be Verified */
            TC_Register(7, BNEP_CONTROL_COMMAND_NOT_UNDERSTOOD);
            ALOGI("RX for BNEP Type 0x00");
        break;

        case 8:
            TC_Register(8, BNEP_FILTER_MULTI_ADDR_RESPONSE_MSG);
            ALOGI("RX for BNEP Type 0x00 with extension header");
        break;

        case 9:
            TC_Register(9, BNEP_CONTROL_COMMAND_NOT_UNDERSTOOD);
            ALOGI("RX for BNEP Type 0x00 with unknown extension header");
        break;

        case 10:
            TC_Register(10, BNEP_FILTER_MULTI_ADDR_RESPONSE_MSG);
            TC_Register(TC_CMD_EXEC_WAIT, BNEP_CONTROL_COMMAND_NOT_UNDERSTOOD);
            ALOGI("RX for BNEP Type 0x00 with 1 known and 1 unknown extension header");
        break;

        case 11:
            TC_Register(11, BNEP_FILTER_MULTI_ADDR_RESPONSE_MSG);
            TC_Register(TC_CMD_EXEC_WAIT, BNEP_CONTROL_COMMAND_NOT_UNDERSTOOD);
            ALOGI("RX for BNEP Type 0x00 with two unknown extension headers");
        break;

        case 12:
            TC_Register(12, BNEP_SETUP_CONNECTION_RESPONSE_MSG);
            TC_Register(TC_CMD_EXEC_WAIT, BNEP_FILTER_NET_TYPE_RESPONSE_MSG);
            TC_Register(TC_CMD_EXEC_WAIT, BNEP_FILTER_MULTI_ADDR_RESPONSE_MSG);
            ALOGI("Setup message with two known extension headers");
        break;
    }

    ALOGI("================================================================");
    ALOGI("Initialised Test Case");
    ALOGI("Verifier will initiate an BNEP Connection to Tester");
}

static UINT8 BNEPV_get_cmd ( void )
{
    return TC_GetCmd();
}

static void BNEPV_connect ( void )
{
    // ALOGI("%s", __FUNCTION__);

    tBT_UUID src_uuid, dst_uuid;

    src_uuid.uu.uuid16 = UUID_SERVCLASS_PANU;
    dst_uuid.uu.uuid16 = UUID_SERVCLASS_NAP;
    src_uuid.len      = 2;
    dst_uuid.len      = 2;

    ALOGI("Initiating Connection Request to %x:%x:%x:%x:%x:%x",
    rbd_addr[0], rbd_addr[1], rbd_addr[2], rbd_addr[3], rbd_addr[4], rbd_addr[5]);
    BNEP_Connect(rbd_addr, &src_uuid, &dst_uuid, &p_handle);
}

static void BNEPV_disconnect(void)
{
    // ALOGI("%s", __FUNCTION__);
    UINT8 tc_v;

    ALOGI("Disconnecting BNEP connection");
    BNEP_Disconnect(p_handle);

    ALOGI("================================================================");

    tc_v = TC_GetVerdict();
    if(tc_v == TC_VERDICT_PASS)
    {
        ALOGI("Test Case : PASSED");
        TC_Callback(TC_EVENT_VER_PASS);
    }
    else if(tc_v == TC_VERDICT_INCONC)
    {
        ALOGE("Test Case : INCONCLUSIVE");
        TC_Callback(TC_EVENT_VER_INCONC);
    }
    else
    {
        ALOGE("Test Case : FAILED");
        TC_Callback(TC_EVENT_VER_FAIL);
    }

    ALOGI("================================================================");
}

static void BNEPV_send_control_msg ( UINT8 type )
{
    // ALOGI("%s : Control Type = %d", __FUNCTION__, type);

    UINT8 *p, l, v;
    BOOLEAN extn = TRUE;

    ALOGD("Send Event : Sending Control Message");
    ALOGD("{");
    switch(type)
    {
        case BNEP_CONTROL_COMMAND_NOT_UNDERSTOOD:
            /* TP/BNEP/CTRL/BV-01-C */
            bnep_data[0] = BNEP_FRAME_CONTROL << 1;
            ALOGD("\tBNEP Frame Type = BNEP_FRAME_CONTROL");
            ALOGD("\tBNEP Frame Extension = FALSE");
            bnep_data[1] = 0xFF;
            ALOGD("\tBNEP Control Type = 0xFF");

            extn = FALSE;
            bnep_data_size = 0x02;
        break;

        case BNEP_SETUP_CONNECTION_REQUEST_MSG:
            /* TP/BNEP/CTRL/BV-03-C */
            /* TP/BNEP/CTRL/BV-04-C */
            /* TP/BNEP/CTRL/BV-05-C */
            bnep_data[0] = BNEP_FRAME_CONTROL << 1;
            ALOGD("\tBNEP Frame Type = BNEP_FRAME_CONTROL");
            ALOGD("\tBNEP Frame Extension = FALSE");
            bnep_data[1] = BNEP_SETUP_CONNECTION_REQUEST_MSG;
            ALOGD("\tBNEP Control Type = BNEP_SETUP_CONNECTION_REQUEST_MSG");
            bnep_data[2] = 0x02;
            ALOGD("\tBNEP UUID Size = 2");
            p = &bnep_data[3];
            UINT16_TO_BE_STREAM (p, UUID_SERVCLASS_PANU);
            ALOGD("\tBNEP Source UUID = %04x", UUID_SERVCLASS_PANU);
            p = &bnep_data[5];
            UINT16_TO_BE_STREAM (p, UUID_SERVCLASS_NAP);
            ALOGD("\tBNEP Destination UUID = %04x", UUID_SERVCLASS_NAP);

            bnep_data_size = 0x07;
        break;

        case 6:
            /* TP/BNEP/CTRL/BV-10-C */
            bnep_data[0] = ( BNEP_FRAME_COMPRESSED_ETHERNET << 1 );
            ALOGD("\tBNEP Frame Type = BNEP_FRAME_COMPRESSED_ETHERNET");
            bnep_data[0] |= 1;
            ALOGD("\tBNEP Frame Extension = TRUE");
            p = &bnep_data[1];
            UINT16_TO_BE_STREAM (p, 0x0800);
            ALOGD("\tNetwork Protocol Type = 0x0800");
            bnep_data[3] = 0x00;
            ALOGD("\tExtension 1");
            ALOGD("\t\tExtension Header = BNEP_EXTENSION_CONTROL");
            ALOGD("\t\tFurthur Extension Present = FALSE");
            bnep_data[4] = 0x0F;
            ALOGD("\t\tExtension Length = 0x0F");
            bnep_data[5] = 0x05;
            ALOGD("\t\tBNEP Control Type = BNEP_FILTER_MULTI_ADDR_SET_MSG");
            p = &bnep_data[6];
            UINT16_TO_BE_STREAM (p, 0x000C);
            ALOGD("\t\tList Length = 0x000C");
            sprintf((char *)&bnep_data[8], "%x%x%x%x%x%x", 03, 00, 00, 20, 00, 00);
            ALOGD("\t\tRange Start = 0x030000200000");
            sprintf((char *)&bnep_data[14], "%x%x%x%x%x%x", 03, 00, 00, 20, 00, 00);
            ALOGD("\t\tRange End = 0x030000200000");

            bnep_data_size = 0x14;
        break;

        case 7:
            /* TP/BNEP/RX-TYPE-0/BV-11-C */
            bnep_data[0] = BNEP_FRAME_GENERAL_ETHERNET << 1;
            ALOGD("\tBNEP Frame Type = BNEP_FRAME_GENERAL_ETHERNET");
            ALOGD("\tBNEP Frame Extension = FALSE");
            /* To be Verified */
            sprintf((char *)&bnep_data[1], "%x%x%x%x%x%x", 01, 02, 03, 04, 05, 06);
            sprintf((char *)&bnep_data[8], "%x%x%x%x%x%x", 06, 05, 04, 03, 02, 01);

            p = &bnep_data[14];
            UINT16_TO_BE_STREAM (p, 0x0800);
            p = &bnep_data[16];
            memset(p, 1, 60);
            p = &bnep_data[76];
            for(l = 0; l < 5; l++)
            {
                for(v = 0; v < 0xFF; v++)
                {
                    *p++ = v;
                }
            }
            for(v = 0; v < 0x9F; v++)
            {
                *p++ = v;
            }

            extn = FALSE;
            bnep_data_size = 0x5EB;
        break;

        case 8:
            /* TP/BNEP/RX-TYPE-0/BV-15-C */
            bnep_data[0] = BNEP_FRAME_GENERAL_ETHERNET << 1;
            bnep_data[0] |= 1;
            ALOGD("\tBNEP Frame Type = BNEP_FRAME_GENERAL_ETHERNET");
            ALOGD("\tBNEP Frame Extension = TRUE");

            /* To be verified */
            sprintf((char *)&bnep_data[1], "%x%x%x%x%x%x", 01, 02, 03, 04, 05, 06);
            sprintf((char *)&bnep_data[7], "%x%x%x%x%x%x", 06, 05, 04, 03, 02, 01);

            p = &bnep_data[13];
            UINT16_TO_BE_STREAM (p, 0x0800);
            ALOGD("\tNetwork Protocol Type = 0x0800");
            bnep_data[15] = 0x00;
            ALOGD("\tExtension 1");
            ALOGD("\t\tExtension Header = BNEP_EXTENSION_CONTROL");
            ALOGD("\t\tFurthur Extension Present = FALSE");
            bnep_data[16] = 0x0F;
            ALOGD("\t\tExtension Length = 0x0F");
            bnep_data[17] = 0x05;
            ALOGD("\t\tBNEP Control Type = BNEP_FILTER_MULTI_ADDR_SET_MSG");
            p = &bnep_data[18];
            UINT16_TO_BE_STREAM (p, 0x000C);
            ALOGD("\t\tList Length = 0x000C");
            sprintf((char *)&bnep_data[20], "%x%x%x%x%x%x", 03, 00, 00, 20, 00, 00);
            ALOGD("\t\tRange Start = 0x030000200000");
            sprintf((char *)&bnep_data[26], "%x%x%x%x%x%x", 03, 00, 00, 20, 00, 00);
            ALOGD("\t\tRange End = 0x030000200000");
            p = &bnep_data[32];
            memset(p, 1, 60);
            p = &bnep_data[92];
            for(l = 0; l < 5; l++)
            {
                for(v = 0; v < 0xFF; v++)
                {
                    *p++ = v;
                }
            }
            for(v = 0; v < 0x9F; v++)
            {
                *p++ = v;
            }

            bnep_data_size = 0x5FC;
        break;

        case 9:
            /* TP/BNEP/RX-TYPE-0/BV-16-C */
            bnep_data[0] = BNEP_FRAME_GENERAL_ETHERNET << 1;
            bnep_data[0] |= 1;
            ALOGD("\tBNEP Frame Type = BNEP_FRAME_GENERAL_ETHERNET");
            ALOGD("\tBNEP Frame Extension = TRUE");

            /* To be Verified */
            sprintf((char *)&bnep_data[1], "%x%x%x%x%x%x", 01, 02, 03, 04, 05, 06);
            sprintf((char *)&bnep_data[7], "%x%x%x%x%x%x", 06, 05, 04, 03, 02, 01);

            p = &bnep_data[13];
            UINT16_TO_BE_STREAM (p, 0x0800);
            ALOGD("\tNetwork Protocol Type = 0x0800");
            bnep_data[15] = 0x7F;
            ALOGD("\tExtension 1");
            ALOGD("\t\tExtension Header = EXTENSION_UNKNOWN");
            ALOGD("\t\tFurthur Extension Present = FALSE");
            bnep_data[16] = 0xAE;
            ALOGD("\t\tExtension Length = 0xAE");
            p = &bnep_data[17];
            for(v = 0; v < 0xAE; v++)
            {
                *p++ = v;
            }
            for(v = 0; v < 60; v++)
            {
                *p++ = v;
            }
            for(l = 0; l < 5; l++)
            {
                for(v = 0; v < 0xFF; v++)
                {
                    *p++ = v;
                }
            }
            for(v = 0; v < 0x9F; v++)
            {
                *p++ = v;
            }

            bnep_data_size = 0x69B;
        break;

        case 10:
            /* TP/BNEP/RX-TYPE-0/BV-17-C */
            bnep_data[0] = BNEP_FRAME_GENERAL_ETHERNET << 1;
            bnep_data[0] |= 1;
            ALOGD("\tBNEP Frame Type = BNEP_FRAME_GENERAL_ETHERNET");
            ALOGD("\tBNEP Frame Extension = TRUE");

            /* To be Verified */
            sprintf((char *)&bnep_data[1], "%x%x%x%x%x%x", 01, 02, 03, 04, 05, 06);
            sprintf((char *)&bnep_data[7], "%x%x%x%x%x%x", 06, 05, 04, 03, 02, 01);
            p = &bnep_data[13];
            UINT16_TO_BE_STREAM (p, 0x0800);
            ALOGD("\tNetwork Protocol Type = 0x0800");
            bnep_data[15] = 0x01;
            ALOGD("\tExtension 1");
            ALOGD("\t\tExtension Header = BNEP_EXTENSION_CONTROL");
            ALOGD("\t\tFurthur Extension Present = TRUE");
            bnep_data[16] = 0x0F;
            ALOGD("\t\tExtension Length = 0x0F");
            bnep_data[17] = 0x05;
            ALOGD("\t\tBNEP Control Type = BNEP_FILTER_MULTI_ADDR_SET_MSG");
            p = &bnep_data[18];
            UINT16_TO_BE_STREAM (p, 0x000C);
            ALOGD("\t\tList Length = 0x000C");
            sprintf((char *)&bnep_data[20], "%x%x%x%x%x%x", 03, 00, 00, 20, 00, 00);
            ALOGD("\t\tRange Start = 0x030000200000");
            sprintf((char *)&bnep_data[26], "%x%x%x%x%x%x", 03, 00, 00, 20, 00, 00);
            ALOGD("\t\tRange End = 0x030000200000");
            bnep_data[32] = 0x7F;
            ALOGD("\tExtension 2");
            ALOGD("\t\tExtension Header = EXTENSION_UNKNOWN");
            ALOGD("\t\tFurthur Extension Present = FALSE");
            bnep_data[33] = 0x0A;
            p = &bnep_data[34];
            for(v = 0; v < 0x0A; v++)
            {
                *p++ = v;
            }
            for(v = 0; v < 60; v++)
            {
                *p++ = v;
            }
            for(l = 0; l < 5; l++)
            {
                for(v = 0; v < 0xFF; v++)
                {
                    *p++ = v;
                }
            }
            for(v = 0; v < 0x9F; v++)
            {
                *p++ = v;
            }

            bnep_data_size = 0x608;
        break;

        case 11:
            /* TP/BNEP/RX-TYPE-0/BV-18-C */
            bnep_data[0] = BNEP_FRAME_GENERAL_ETHERNET << 1;
            bnep_data[0] |= 1;
            ALOGD("\tBNEP Frame Type = BNEP_FRAME_GENERAL_ETHERNET");
            ALOGD("\tBNEP Frame Extension = TRUE");

            /* To be Verified */
            sprintf((char *)&bnep_data[1], "%x%x%x%x%x%x", 01, 02, 03, 04, 05, 06);
            sprintf((char *)&bnep_data[7], "%x%x%x%x%x%x", 06, 05, 04, 03, 02, 01);
            p = &bnep_data[13];
            UINT16_TO_BE_STREAM (p, 0x0800);
            ALOGD("\tNetwork Protocol Type = 0x0800");
            bnep_data[15] = 0xFF;
            ALOGD("\tExtension 1");
            ALOGD("\t\tExtension Header = EXTENSION_UNKNOWN");
            ALOGD("\t\tFurthur Extension Present = TRUE");
            bnep_data[16] = 0x56;
            ALOGD("\t\tExtension Length = 0x56");
            p = &bnep_data[17];
            for(v = 0; v < 0x9F; v++)
            {
                *p++ = v;
            }
            *p++ = 0x7F;
            ALOGD("\tExtension 2");
            ALOGD("\t\tExtension Header = EXTENSION_UNKNOWN");
            ALOGD("\t\tFurthur Extension Present = FALSE");
            *p++ = 0x56;
            ALOGD("\t\tExtension Length = 0x56");
            for(v = 0; v < 0x9F; v++)
            {
                *p++ = v;
            }
            for(v = 0; v < 60; v++)
            {
                *p++ = v;
            }
            for(l = 0; l < 5; l++)
            {
                for(v = 0; v < 0xFF; v++)
                {
                    *p++ = v;
                }
            }
            for(v = 0; v < 0x9F; v++)
            {
                *p++ = v;
            }

            bnep_data_size = 0x69B;
        break;

        case 12:
            /* TP/BNEP/CTRL/BV-19-C */
            bnep_data[0] = BNEP_FRAME_CONTROL << 1;
            bnep_data[0] |= 0x01;
            ALOGD("\tBNEP Frame Type = BNEP_FRAME_CONTROL");
            ALOGD("\tBNEP Frame Extension = TRUE");
            bnep_data[1] = BNEP_SETUP_CONNECTION_REQUEST_MSG;
            ALOGD("\tBNEP Control Type = BNEP_SETUP_CONNECTION_REQUEST_MSG");
            bnep_data[2] = 0x02;
            ALOGD("\tBNEP UUID Size = 2");
            p = &bnep_data[3];
            UINT16_TO_BE_STREAM (p, UUID_SERVCLASS_NAP);
            ALOGD("\tBNEP Source UUID = %04x", UUID_SERVCLASS_NAP);
            p = &bnep_data[5];
            UINT16_TO_BE_STREAM (p, UUID_SERVCLASS_PANU);
            ALOGD("\tBNEP Destination UUID = %04x", UUID_SERVCLASS_PANU);
            bnep_data[7] = 0x01;
            ALOGD("\tExtension 1");
            ALOGD("\t\tExtension Header = BNEP_EXTENSION_CONTROL");
            ALOGD("\t\tFurthur Extension Present = TRUE");
            bnep_data[8] = 0x07;
            ALOGD("\t\tExtension Length = 0x07");
            bnep_data[9] = 0x03;
            ALOGD("\t\tExtension Control Type = BNEP_FILTER_NET_TYPE_SET_MSG");
            p = &bnep_data[10];
            UINT16_TO_BE_STREAM (p, 0x0004);
            sprintf((char *)&bnep_data[12], "%x%x%x%x%x%x", 03, 00, 00, 20, 00, 00);
            sprintf((char *)&bnep_data[18], "%x%x%x%x%x%x", 03, 00, 00, 20, 00, 00);
            bnep_data[19] = 0x00;
            ALOGD("\tExtension 1");
            ALOGD("\t\tExtension Header = BNEP_EXTENSION_CONTROL");
            ALOGD("\t\tFurthur Extension Present = FALSE");
            bnep_data[20] = 0x0F;
            ALOGD("\t\tExtension Length = 0x0F");
            bnep_data[21] = 0x05;
            ALOGD("\t\tExtension Control Type = BNEP_FILTER_MULTI_ADDR_SET_MSG");
            p = &bnep_data[22];
            UINT16_TO_BE_STREAM (p, 0x000C);
            sprintf((char *)&bnep_data[24], "%x%x%x%x%x%x", 03, 00, 00, 20, 00, 00);
            sprintf((char *)&bnep_data[30], "%x%x%x%x%x%x", 03, 00, 00, 20, 00, 00);

            bnep_data_size = 0x0021;
        break;

        default:
        break;
    }

    ALOGD("}");
    BNEP_Write(p_handle, dest_address, bnep_data, bnep_data_size, 0x0800, source_address, extn);
}

/***********************************************************************************************************************/
static const bnep_verifier_interface_t bnep_verifier_interface = {
    sizeof(bnep_verifier_interface_t),
    BNEPV_init,
    BNEPV_set_remote_bd_addr,
    BNEPV_select_test_case,
    BNEPV_get_cmd,
    BNEPV_connect,
    BNEPV_send_control_msg,
    BNEPV_disconnect,
};

const bnep_verifier_interface_t *btif_get_bnep_verifier_interface(void)
{
    ALOGI("%s", __FUNCTION__);
    return &bnep_verifier_interface;
}
