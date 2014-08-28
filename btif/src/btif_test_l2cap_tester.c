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
 *  Filename:      btif_test_l2cap_tester.c
 *
 *  Description:   Bluetooth Test implementation for Testing Lower Protocols.
 *
 *****************************************************************************/
#include <stdio.h>
#include <hardware/bluetooth.h>
#include <fcntl.h>
#include "bta_api.h"
#include "bd.h"
#include "gki.h"
#define LOG_TAG     "btif-test"

#include "btif_test.h"
#include "btif_common.h"
#include "l2c_api.h"

/************************************************************************************
 **  Constants & Macros
 ************************************************************************************/
#define BT_PSM_L2CAP_TEST   BT_PSM_SDP

static void L2CAP_Test_ConnectInd_cb(BD_ADDR bd_addr, UINT16 lcid, UINT16 psm, UINT8 id);
static void L2CAP_Test_ConnectCnf_cb(UINT16 lcid, UINT16 err);
static void L2CAP_Test_ConnectPnd_cb(UINT16 lcid);
static void L2CAP_Test_ConfigInd_cb(UINT16 lcid, tL2CAP_CFG_INFO *p_cfg);
static void L2CAP_Test_ConfigCnf_cb(UINT16 lcid, tL2CAP_CFG_INFO *p_cfg);
static void L2CAP_Test_DisconnectInd_cb(UINT16 lcid, BOOLEAN is_clear);
static void L2CAP_Test_DisconnectCnf_cb(UINT16 lcid, UINT16 result);
static void L2CAP_Test_QoSViolationInd_cb(BD_ADDR bd_addr);
static void L2CAP_Test_BufDataInd_cb(UINT16 lcid, BT_HDR *p_buf);
static void L2CAP_Test_CongestionStatusInd_cb(UINT16 lcid, BOOLEAN is_congested);
static void L2CAP_Test_TxComplete_cb(UINT16 lcid, UINT16 sdu_count);

#define L2CAP_MODE_BASIC    0x00
#define L2CAP_MODE_ERTM     0x01
#define L2CAP_MODE_STM      0x02

typedef struct {
    UINT8 mode;
    UINT16 cid;
    UINT8 send_config;
    tL2CAP_CFG_INFO cfg;
    tL2CAP_ERTM_INFO ertm_info;
} tL2CAP_CON_STATUS;

BD_ADDR rbd_addr;
tL2CAP_CON_STATUS gL2cap_con;

tL2CAP_APPL_INFO gL2capTestApp =
{
    L2CAP_Test_ConnectInd_cb,
    L2CAP_Test_ConnectCnf_cb,
    L2CAP_Test_ConnectPnd_cb,
    L2CAP_Test_ConfigInd_cb,
    L2CAP_Test_ConfigCnf_cb,
    L2CAP_Test_DisconnectInd_cb,
    L2CAP_Test_DisconnectCnf_cb,
    L2CAP_Test_QoSViolationInd_cb,
    L2CAP_Test_BufDataInd_cb,
    L2CAP_Test_CongestionStatusInd_cb,
    L2CAP_Test_TxComplete_cb,
};

/***********************************************************************************************************************/
static void L2CAP_Test_ConnectInd_cb(BD_ADDR bd_addr, UINT16 lcid, UINT16 psm, UINT8 id)
{
    ALOGI("%s", __FUNCTION__);

    gL2cap_con.cid = lcid;

    if (gL2cap_con.mode == L2CAP_MODE_BASIC)
    {
        L2CA_ConnectRsp(bd_addr, id, lcid, L2CAP_CONN_OK, L2CAP_CONN_OK);

        if (gL2cap_con.send_config)
            L2CA_ConfigReq(lcid, &gL2cap_con.cfg);
    }
    else if (gL2cap_con.mode == L2CAP_MODE_ERTM)
    {
        L2CA_ErtmConnectRsp(bd_addr, id, lcid, L2CAP_CONN_OK, L2CAP_CONN_OK, &gL2cap_con.ertm_info);

        if (gL2cap_con.send_config)
            L2CA_ConfigReq(lcid, &gL2cap_con.cfg);
    }
    else if (gL2cap_con.mode == L2CAP_MODE_STM)
    {
        L2CA_ErtmConnectRsp(bd_addr, id, lcid, L2CAP_CONN_OK, L2CAP_CONN_OK, &gL2cap_con.ertm_info);

        if (gL2cap_con.send_config)
            L2CA_ConfigReq(lcid, &gL2cap_con.cfg);
    }
}

static void L2CAP_Test_ConnectCnf_cb(UINT16 lcid, UINT16 err)
{
    ALOGI("%s", __FUNCTION__);

    gL2cap_con.cid = lcid;

    L2CA_ConfigReq(lcid, &gL2cap_con.cfg);
}

static void L2CAP_Test_ConnectPnd_cb(UINT16 lcid)
{
    ALOGI("%s", __FUNCTION__);
}

static void L2CAP_Test_ConfigInd_cb(UINT16 lcid, tL2CAP_CFG_INFO *p_cfg)
{
    ALOGI("%s", __FUNCTION__);

    if (p_cfg->mtu_present == TRUE)
    {
        ALOGI("MTU Size: %d", p_cfg->mtu);
    }
    if (p_cfg->fcr_present == TRUE)
    {
        ALOGI("FCR mode: %d", p_cfg->fcr.mode);
        ALOGI("FCR tx_win_sz: %d", p_cfg->fcr.tx_win_sz);
        ALOGI("FCR max_transmit: %d", p_cfg->fcr.max_transmit);
        ALOGI("FCR rtrans_tout: %d", p_cfg->fcr.rtrans_tout);
        ALOGI("FCR mon_tout: %d", p_cfg->fcr.mon_tout);
        ALOGI("FCR mps: %d", p_cfg->fcr.mps);
    }

    p_cfg->result = L2CAP_CFG_OK;

    if (gL2cap_con.mode == L2CAP_MODE_BASIC)
    {
        if (p_cfg->fcr_present)
        {
            if (p_cfg->fcr.mode != L2CAP_FCR_BASIC_MODE)
                p_cfg->result = L2CAP_CFG_UNACCEPTABLE_PARAMS;
        }
    }

    if (gL2cap_con.mode == L2CAP_MODE_STM)
    {
        if (p_cfg->fcr_present)
        {
            if (p_cfg->fcr.mode == L2CAP_FCR_BASIC_MODE)
            {
                p_cfg->fcr.tx_win_sz = 0x08;
                p_cfg->fcr.max_transmit = 0x03;
                p_cfg->fcr.rtrans_tout = 0x07D0;
                p_cfg->fcr.mon_tout = 0x2EE0;
                p_cfg->fcr.mps = 144;
            }
        }
    }

    if (gL2cap_con.mode == L2CAP_MODE_ERTM)
    {
        p_cfg->fcs_present = TRUE;
        p_cfg->fcs = TRUE;
    }

    L2CA_ConfigRsp(lcid, p_cfg);
}

static void L2CAP_Test_ConfigCnf_cb(UINT16 lcid, tL2CAP_CFG_INFO *p_cfg)
{
    ALOGI("%s", __FUNCTION__);

    if (p_cfg->result == L2CAP_CFG_UNACCEPTABLE_PARAMS)
    {
        if (p_cfg->fcr_present)
        {
            p_cfg->fcr_present = TRUE;
            p_cfg->fcr.mode = L2CAP_FCR_ERTM_MODE;

            //Taken from PTS PIXIT Settings
            p_cfg->fcr.tx_win_sz = 0x10;
            p_cfg->fcr.max_transmit = 0x05;
            p_cfg->fcr.rtrans_tout = 0x07D0;
            p_cfg->fcr.mon_tout = 0x2EE0;
            p_cfg->fcr.mps = 144;
        }

        L2CA_ConfigReq(lcid, p_cfg);
    }
}

static void L2CAP_Test_DisconnectInd_cb(UINT16 lcid, BOOLEAN is_clear)
{
    ALOGI("%s", __FUNCTION__);

    if (is_clear)
    {
        L2CA_DisconnectRsp(gL2cap_con.cid);
        gL2cap_con.cid = 0;

        return;
    }
}

static void L2CAP_Test_DisconnectCnf_cb(UINT16 lcid, UINT16 result)
{
    ALOGI("%s", __FUNCTION__);
    gL2cap_con.cid = 0;
}

static void L2CAP_Test_QoSViolationInd_cb(BD_ADDR bd_addr)
{
    ALOGI("%s", __FUNCTION__);
}

static void L2CAP_Test_BufDataInd_cb(UINT16 lcid, BT_HDR *p_buf)
{
    ALOGI("%s", __FUNCTION__);
    GKI_freebuf(p_buf);
}

static void L2CAP_Test_CongestionStatusInd_cb(UINT16 lcid, BOOLEAN is_congested)
{
    ALOGI("%s", __FUNCTION__);
}

static void L2CAP_Test_TxComplete_cb(UINT16 lcid, UINT16 sdu_count)
{
    ALOGI("%s", __FUNCTION__);
}

/***********************************************************************************************************************/
static UINT16 L2CAPTest_init(void)
{
    ALOGI("%s", __FUNCTION__);

    return L2CA_Register(BT_PSM_L2CAP_TEST, &gL2capTestApp);
}

static void L2CAPTest_set_default_parameters(void)
{
    ALOGI("%s", __FUNCTION__);

    memset(&gL2cap_con, 0, sizeof(tL2CAP_CON_STATUS));

    gL2cap_con.mode = L2CAP_MODE_ERTM;
    gL2cap_con.send_config = 1;

    gL2cap_con.ertm_info.preferred_mode = L2CAP_FCR_ERTM_MODE;
    gL2cap_con.ertm_info.allowed_modes = L2CAP_FCR_CHAN_OPT_ERTM;
    gL2cap_con.ertm_info.user_rx_pool_id = HCI_ACL_POOL_ID;
    gL2cap_con.ertm_info.user_tx_pool_id = HCI_ACL_POOL_ID;
    gL2cap_con.ertm_info.fcr_rx_pool_id = HCI_ACL_POOL_ID;
    gL2cap_con.ertm_info.fcr_tx_pool_id = HCI_ACL_POOL_ID;

    gL2cap_con.cfg.mtu_present = TRUE;
    gL2cap_con.cfg.mtu = SDP_MTU_SIZE;

    gL2cap_con.cfg.flush_to_present = TRUE;
    gL2cap_con.cfg.flush_to = SDP_FLUSH_TO;

    gL2cap_con.cfg.fcs_present = TRUE;
    gL2cap_con.cfg.fcs = TRUE;

    gL2cap_con.cfg.fcr_present = TRUE;
    gL2cap_con.cfg.fcr.mode = L2CAP_FCR_ERTM_MODE;

    gL2cap_con.cfg.fcr.tx_win_sz = 0x08;
    gL2cap_con.cfg.fcr.max_transmit = 0x03;
    gL2cap_con.cfg.fcr.rtrans_tout = 0x07D0;
    gL2cap_con.cfg.fcr.mon_tout = 0x2EE0;
    gL2cap_con.cfg.fcr.mps = 144;
}

static void L2CAPTest_set_parameters(UINT8 cmd, void *p_data)
{
    ALOGI("%s", __FUNCTION__);

    UINT8 *p;
    p = (UINT8 *) p_data;

    switch (cmd)
    {
    case L2CAP_PARAMETER_CLEAR:
        memset(&gL2cap_con, 0, sizeof(tL2CAP_CON_STATUS));
        break;

    case L2CAP_PARAMETER_MODE:
        gL2cap_con.mode = *p;
        break;

    case L2CAP_PARAMETER_SEND_CONFIG:
        gL2cap_con.send_config = *p;
        break;

    case L2CAP_PARAMETER_SET_ERTM:
        if (gL2cap_con.mode == 1)
        {
            gL2cap_con.ertm_info.preferred_mode = L2CAP_FCR_ERTM_MODE;
            gL2cap_con.ertm_info.allowed_modes = L2CAP_FCR_CHAN_OPT_ERTM;
        }
        else
        {
            gL2cap_con.ertm_info.preferred_mode = L2CAP_FCR_STREAM_MODE;
            gL2cap_con.ertm_info.allowed_modes = L2CAP_FCR_CHAN_OPT_STREAM;
        }

        gL2cap_con.ertm_info.user_rx_pool_id = HCI_ACL_POOL_ID;
        gL2cap_con.ertm_info.user_tx_pool_id = HCI_ACL_POOL_ID;
        gL2cap_con.ertm_info.fcr_rx_pool_id = HCI_ACL_POOL_ID;
        gL2cap_con.ertm_info.fcr_tx_pool_id = HCI_ACL_POOL_ID;
        break;

    case L2CAP_PARAMETER_SET_MTU:
        if (*p)
        {
            gL2cap_con.cfg.mtu_present = TRUE;
            gL2cap_con.cfg.mtu = SDP_MTU_SIZE;
        }
        else
        {
            gL2cap_con.cfg.mtu_present = FALSE;
        }
        break;

    case L2CAP_PARAMETER_SET_FLUSH_TO:
        if (*p)
        {
            gL2cap_con.cfg.flush_to_present = TRUE;
            gL2cap_con.cfg.flush_to = SDP_FLUSH_TO;
        }
        else
        {
            gL2cap_con.cfg.flush_to_present = FALSE;
        }
        break;

    case L2CAP_PARAMETER_SET_FCS:
        if (*p == 1)
        {
            gL2cap_con.cfg.fcs_present = TRUE;
            gL2cap_con.cfg.fcs = TRUE;
        }
        else if (*p == 2)
        {
            gL2cap_con.cfg.fcs_present = TRUE;
            gL2cap_con.cfg.fcs = FALSE;
        }
        else
        {
            gL2cap_con.cfg.fcs_present = FALSE;
            gL2cap_con.cfg.fcs = FALSE;
        }
        break;

    case L2CAP_PARAMETER_SET_FCR:
        if (*p)
        {
            gL2cap_con.cfg.fcr_present = TRUE;

            if (gL2cap_con.mode == 1)
                gL2cap_con.cfg.fcr.mode = L2CAP_FCR_ERTM_MODE;
            else if (gL2cap_con.mode == 2)
                gL2cap_con.cfg.fcr.mode = L2CAP_FCR_STREAM_MODE;
            else
                gL2cap_con.cfg.fcr.mode = L2CAP_FCR_BASIC_MODE;

            gL2cap_con.cfg.fcr.tx_win_sz = 0x08;
            gL2cap_con.cfg.fcr.max_transmit = 0x03;
            gL2cap_con.cfg.fcr.rtrans_tout = 0x07D0;
            gL2cap_con.cfg.fcr.mon_tout = 0x2EE0;
            gL2cap_con.cfg.fcr.mps = 144;
        }
        else
        {
            gL2cap_con.cfg.fcr_present = FALSE;
        }
        break;

    default:
        break;
    }
}

static void L2CAPTest_set_remote_bd_addr(BD_ADDR* p_bd_addr)
{
    ALOGI("%s", __FUNCTION__);
    memcpy(&rbd_addr, p_bd_addr, sizeof(BD_ADDR));
}

static void L2CAPTest_connect(void)
{
    ALOGI("%s", __FUNCTION__);

    if (gL2cap_con.mode == L2CAP_MODE_BASIC)
    {
        L2CA_ConnectReq(BT_PSM_L2CAP_TEST, rbd_addr);
    }
    else
    {
        L2CA_ErtmConnectReq(BT_PSM_L2CAP_TEST, rbd_addr, &gL2cap_con.ertm_info);
    }
}

static void L2CAPTest_disconnect(void)
{
    ALOGI("%s", __FUNCTION__);
    L2CA_DisconnectReq(gL2cap_con.cid);
}

static void L2CAPTest_senddata(UINT16 byte)
{
    BT_HDR *p_buf;
    UINT8 *p_data;
    int i = 0;

    ALOGI("%s", __FUNCTION__);

    if (gL2cap_con.cid == 0)
    {
        ALOGE("%s, cid: %d", __FUNCTION__, gL2cap_con.cid);
        return;
    }

    if ((p_buf = (BT_HDR *) GKI_getpoolbuf(SDP_POOL_ID)) == NULL)
        return;

    p_buf->offset = L2CAP_MIN_OFFSET;
    p_data = (UINT8 *) (p_buf + 1) + L2CAP_MIN_OFFSET;
    //Running for lopping to add dummy data.
    for (i = 0; i < byte; i++)
        UINT8_TO_BE_STREAM(p_data, 0x10);

    p_buf->len = byte;
    L2CA_DataWrite(gL2cap_con.cid, p_buf);
    return;
}

static void L2CAPTest_ping(UINT8 which)
{
    if (which == 1)
        L2CA_Ping(rbd_addr, NULL);
    else if (which == 2)
        L2CA_SendTestSFrame(gL2cap_con.cid, L2CAP_FCR_SUP_RNR, 0);
    else if (which == 3)
        L2CA_SendTestSFrame(gL2cap_con.cid, L2CAP_FCR_SUP_RR, 0);
}

static void L2CAPTest_cleanup(void)
{
    ALOGI("%s", __FUNCTION__);

    L2CA_Deregister (BT_PSM_L2CAP_TEST);
    memset(&gL2cap_con, 0, sizeof(tL2CAP_CON_STATUS));
}

static const l2cap_test_interface_t l2cap_test_interface = {
    sizeof(l2cap_test_interface_t),
    L2CAPTest_init,
    L2CAPTest_set_default_parameters,
    L2CAPTest_set_parameters,
    L2CAPTest_set_remote_bd_addr,
    L2CAPTest_connect,
    L2CAPTest_disconnect,
    L2CAPTest_senddata,
    L2CAPTest_ping,
    L2CAPTest_cleanup,
};

const l2cap_test_interface_t *btif_get_l2cap_test_interface(void)
{
    ALOGI("%s", __FUNCTION__);
    return &l2cap_test_interface;
}
