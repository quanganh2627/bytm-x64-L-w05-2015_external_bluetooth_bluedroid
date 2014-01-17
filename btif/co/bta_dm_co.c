/******************************************************************************
 *
 *  Copyright (C) 2009-2012 Broadcom Corporation
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
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <pthread.h>
#include <time.h>

#include "bta_api.h"
#include "bta_sys.h"
#include "bta_dm_co.h"
#include "bta_dm_ci.h"
#if (BTM_OOB_INCLUDED == TRUE)
#include "btif_dm.h"
#endif
#if (defined BLE_INCLUDED && BLE_INCLUDED == TRUE)
#include "bte_appl.h"

#ifndef BLUEDROID_RTK
tBTE_APPL_CFG bte_appl_cfg = { 0x5, 0x4, 0x7, 0x7, 0x10 };
#else
tBTE_APPL_CFG bte_appl_cfg = { 0x5, 0x4, 0x0, 0x1, 0x10 };
#endif

#endif
#define MAX_TX_BUFFER_SIZE 481
#define MAX_RX_BUFFER_SIZE 1921
#define SCO_PACKET_SIZE 48
#define SCO_POOL_SIZE 500
#define SCO_PACKET_PER_TIMEOUT 10
#define MAX_GET_POOL_BUF_RETRY 20
#define LOCK(m)  pthread_mutex_lock(&m)
#define UNLOCK(m) pthread_mutex_unlock(&m)
static UINT8 tx_data_buffer[MAX_TX_BUFFER_SIZE];
static UINT8 rx_data_buffer[MAX_RX_BUFFER_SIZE];
static UINT16 tx_read_pointer = 0;
static UINT16 tx_write_pointer = 0;
static UINT16 rx_read_pointer = 0;
static UINT16 rx_write_pointer = 0;
static pthread_mutex_t tx_sco_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t rx_sco_lock = PTHREAD_MUTEX_INITIALIZER;
static tBTM_SCO_CFG cur_cfg;


/*******************************************************************************
**
** Function         BTA_dm_hsp_flush_tx_data_buf
**
** Description      This function flush the HSP Tx data buffer.
**
**
** Returns          Void.
**
*******************************************************************************/
void BTA_dm_hsp_flush_tx_data_buf()
{
    tx_read_pointer = 0;
    tx_write_pointer = 0;
    return;
}

/*******************************************************************************
**
** Function         BTA_dm_hsp_flush_rx_data_buf
**
** Description      This function flush the HSP Rx data buffer.
**
**
** Returns          Void.
**
*******************************************************************************/
void BTA_dm_hsp_flush_rx_data_buf()
{
    rx_read_pointer = 0;
    rx_write_pointer = 0;
    return;
}

/*******************************************************************************
**
** Function         BTA_dm_hsp_get_tx_data_buf_size
**
** Description      This function check the available free buffer size
**                  of the HSP Tx buffer.
**
**
** Returns          Available free buffer size.
**
*******************************************************************************/
int BTA_dm_hsp_get_tx_data_buf_size()
{
    int freebuf = 0;
    if((freebuf = tx_read_pointer - tx_write_pointer) <= 0)
        freebuf += MAX_TX_BUFFER_SIZE;
    return (freebuf);
}

/*******************************************************************************
**
** Function         BTA_dm_hsp_write_tx_data_buf
**
** Description      This function writes the data coming from AF to
**                  internal HSP Tx buffer for HSP outstream.
**
**
** Returns          Void.
**
*******************************************************************************/
void BTA_dm_hsp_write_tx_data_buf(void *p_buf, UINT16 length)
{
    UINT16 i;
    UINT8 *p=(UINT8*)p_buf;

    if (p_buf == NULL)
    {
        BTIF_TRACE_ERROR1("Invalid argument : NULL buffer in %s", __func__);
        return;
    }

    LOCK(tx_sco_lock);

    for (i = 0; i < length; i++)
    {
        /*check for buffer overflow*/
        if ((tx_write_pointer == (tx_read_pointer-1)) || (tx_write_pointer == (tx_read_pointer + MAX_TX_BUFFER_SIZE - 1)))
        {
            tx_read_pointer++;
            if (tx_read_pointer >= MAX_TX_BUFFER_SIZE)
            {
                tx_read_pointer = 0;
            }
        }
        tx_data_buffer[tx_write_pointer++] = p[i];
        if (tx_write_pointer >= MAX_TX_BUFFER_SIZE)
        {
            tx_write_pointer = 0;
        }

    }

    UNLOCK(tx_sco_lock);
    return;
}

/*******************************************************************************
**
** Function         BTA_dm_hsp_read_tx_data_buf
**
** Description      This function reads the data from internal HSP Tx
**                  buffer.
**
**
** Returns          Length of the read bytes.
**
*******************************************************************************/
UINT16 bta_dm_hsp_read_tx_data_buf(void *p_buf, UINT16 length)
{
    UINT16 i;
    UINT8 *p = (UINT8*)p_buf;

    if(p_buf == NULL)
    {
        BTIF_TRACE_ERROR1("Invalid argument : NULL buffer in %s", __func__);
        return 0;
    }

    LOCK(tx_sco_lock);

    for (i = 0; i < length; i++)
    {
        /*check for empty buffer*/
        if (tx_read_pointer == tx_write_pointer)
        {
            length = i;
            break;
        }

        p[i] = tx_data_buffer[tx_read_pointer++];
        if (tx_read_pointer >= MAX_TX_BUFFER_SIZE)
        {
            tx_read_pointer = 0;
        }

    }

    UNLOCK(tx_sco_lock);


    return length;
}

/*******************************************************************************
**
** Function         BTA_dm_hsp_write_rx_data_buf
**
** Description      This function writes the data coming from lower to
**                  internal HSP Rx buffer for HSP instream.
**
**
** Returns          Void.
**
*******************************************************************************/
void bta_dm_hsp_write_rx_data_buf(void *p_buf, UINT16 length)
{
    UINT16 i;
    UINT8 *p = (UINT8*)p_buf;

    if (p_buf == NULL)
    {
        BTIF_TRACE_ERROR1("Invalid argument : NULL buffer in %s", __func__);
        return;
    }

    LOCK(rx_sco_lock);

    for (i = 0; i < length; i++)
    {
        /*check for buffer overflow*/
        if ((rx_write_pointer == (rx_read_pointer-1)) || (rx_write_pointer == (rx_read_pointer + MAX_RX_BUFFER_SIZE - 1)))
        {
            rx_read_pointer++;
            if (rx_read_pointer >= MAX_RX_BUFFER_SIZE)
            {
                rx_read_pointer = 0;
            }
        }
        rx_data_buffer[rx_write_pointer++] = p[i];
        if(rx_write_pointer >= MAX_RX_BUFFER_SIZE)
        {
            rx_write_pointer = 0;
        }

    }

    UNLOCK(rx_sco_lock);
}

/*******************************************************************************
**
** Function         BTA_dm_hsp_read_rx_data_buf
**
** Description      This function reads the data from internal HSP Rx
**                  buffer and give it to upper layer for HSP instream.
**
**
** Returns          Length of the read bytes.
**
*******************************************************************************/
UINT16 BTA_dm_hsp_read_rx_data_buf(void *p_buf, UINT16 length)
{
    UINT16 i;
    UINT8 *p = (UINT8*)p_buf;

    if (p_buf == NULL)
    {
        BTIF_TRACE_ERROR1("Invalid argument : NULL buffer in %s", __func__);
        return 0;
    }

    LOCK(rx_sco_lock);

    for (i = 0; i < length; i++)
    {
        /*check for empty buffer*/
        if (rx_read_pointer == rx_write_pointer)
        {
            length = i;
            break;
        }

        p[i] = rx_data_buffer[rx_read_pointer++];
        if (rx_read_pointer >= MAX_RX_BUFFER_SIZE)
        {
            rx_read_pointer = 0;
        }
    }

    UNLOCK(rx_sco_lock);

    return length;
}

/*******************************************************************************
**
** Function         bta_dm_co_get_compress_memory
**
** Description      This callout function is executed by DM to get memory for compression

** Parameters       id  -  BTA SYS ID
**                  memory_p - memory return by callout
**                  memory_size - memory size
**
** Returns          TRUE for success, FALSE for fail.
**
*******************************************************************************/
BOOLEAN bta_dm_co_get_compress_memory(tBTA_SYS_ID id, UINT8 **memory_p, UINT32 *memory_size)
{
    return TRUE;
}

/*******************************************************************************
**
** Function         bta_dm_co_io_req
**
** Description      This callout function is executed by DM to get IO capabilities
**                  of the local device for the Simple Pairing process
**
** Parameters       bd_addr  - The peer device
**                  *p_io_cap - The local Input/Output capabilities
**                  *p_oob_data - TRUE, if OOB data is available for the peer device.
**                  *p_auth_req - TRUE, if MITM protection is required.
**
** Returns          void.
**
*******************************************************************************/
void bta_dm_co_io_req(BD_ADDR bd_addr, tBTA_IO_CAP *p_io_cap, tBTA_OOB_DATA *p_oob_data,
                      tBTA_AUTH_REQ *p_auth_req, BOOLEAN is_orig)
{
#if (BTM_OOB_INCLUDED == TRUE)
    btif_dm_set_oob_for_io_req(p_oob_data);
#endif
    BTIF_TRACE_DEBUG1("bta_dm_co_io_req *p_oob_data = %d", *p_oob_data);
    BTIF_TRACE_DEBUG1("bta_dm_co_io_req *p_io_cap = %d", *p_io_cap);
    BTIF_TRACE_DEBUG1("bta_dm_co_io_req *p_auth_req = %d", *p_auth_req);
    BTIF_TRACE_DEBUG1("bta_dm_co_io_req is_orig = %d", is_orig);
}

/*******************************************************************************
**
** Function         bta_dm_co_io_rsp
**
** Description      This callout function is executed by DM to report IO capabilities
**                  of the peer device for the Simple Pairing process
**
** Parameters       bd_addr  - The peer device
**                  io_cap - The remote Input/Output capabilities
**                  oob_data - TRUE, if OOB data is available for the peer device.
**                  auth_req - TRUE, if MITM protection is required.
**
** Returns          void.
**
*******************************************************************************/
void bta_dm_co_io_rsp(BD_ADDR bd_addr, tBTA_IO_CAP io_cap,
                      tBTA_OOB_DATA oob_data, tBTA_AUTH_REQ auth_req)
{
}

/*******************************************************************************
**
** Function         bta_dm_co_lk_upgrade
**
** Description      This callout function is executed by DM to check if the
**                  platform wants allow link key upgrade
**
** Parameters       bd_addr  - The peer device
**                  *p_upgrade - TRUE, if link key upgrade is desired.
**
** Returns          void.
**
*******************************************************************************/
void  bta_dm_co_lk_upgrade(BD_ADDR bd_addr, BOOLEAN *p_upgrade )
{
}

#if (BTM_OOB_INCLUDED == TRUE)
/*******************************************************************************
**
** Function         bta_dm_co_loc_oob
**
** Description      This callout function is executed by DM to report the OOB
**                  data of the local device for the Simple Pairing process
**
** Parameters       valid - TRUE, if the local OOB data is retrieved from LM
**                  c     - Simple Pairing Hash C
**                  r     - Simple Pairing Randomnizer R
**
** Returns          void.
**
*******************************************************************************/
void bta_dm_co_loc_oob(BOOLEAN valid, BT_OCTET16 c, BT_OCTET16 r)
{
    BTIF_TRACE_DEBUG1("bta_dm_co_loc_oob, valid = %d", valid);
#ifdef BTIF_DM_OOB_TEST
    btif_dm_proc_loc_oob(valid, c, r);
#endif
}

/*******************************************************************************
**
** Function         bta_dm_co_rmt_oob
**
** Description      This callout function is executed by DM to request the OOB
**                  data for the remote device for the Simple Pairing process
**                  Need to call bta_dm_ci_rmt_oob() in response
**
** Parameters       bd_addr  - The peer device
**
** Returns          void.
**
*******************************************************************************/
void bta_dm_co_rmt_oob(BD_ADDR bd_addr)
{
    BT_OCTET16 p_c;
    BT_OCTET16 p_r;
    BOOLEAN result = FALSE;

#ifdef BTIF_DM_OOB_TEST
    result = btif_dm_proc_rmt_oob(bd_addr, p_c, p_r);
#endif

    BTIF_TRACE_DEBUG1("bta_dm_co_rmt_oob: result=%d",result);
    bta_dm_ci_rmt_oob(result, bd_addr, p_c, p_r);
}

#endif /* BTM_OOB_INCLUDED */


// REMOVE FOR BLUEDROID ?

#if (BTM_SCO_HCI_INCLUDED == TRUE ) && (BTM_SCO_INCLUDED == TRUE)

/*******************************************************************************
**
** Function         btui_sco_codec_callback
**
** Description      Callback for btui codec.
**
**
** Returns          void
**
*******************************************************************************/
static void btui_sco_codec_callback(UINT16 event, UINT16 sco_handle)
{
    bta_dm_sco_ci_data_ready(event, sco_handle);
}

/*******************************************************************************
**
** Function         btui_sco_register
**
** Description      Sco register function which initializes the callbacks.
**
**
** Returns          void
**
*******************************************************************************/
static void btui_sco_register(tBTM_SCO_CFG *cfg)
{
    cur_cfg.event = cfg->event;
    cur_cfg.sco_handle = cfg->sco_handle;
    cur_cfg.pkt_size = cfg->pkt_size;
    cur_cfg.p_cback = cfg->p_cback;
    cur_cfg.sco_pool_id = cfg->sco_pool_id;
}
/*******************************************************************************
**
** Function         bta_dm_sco_co_init
**
** Description      This function can be used by the phone to initialize audio
**                  codec or for other initialization purposes before SCO connection
**                  is opened.
**
**
** Returns          tBTA_DM_SCO_ROUTE_TYPE: SCO routing configuration type.
**
*******************************************************************************/
tBTA_DM_SCO_ROUTE_TYPE bta_dm_sco_co_init(UINT32 rx_bw, UINT32 tx_bw,
                                          tBTA_CODEC_INFO * p_codec_type, UINT8 app_id)
{
    tBTM_SCO_ROUTE_TYPE route = BTA_DM_SCO_ROUTE_PCM;
    return route;
}



/*******************************************************************************
**
** Function         bta_dm_sco_co_open
**
** Description      This function is executed when a SCO connection is open.
**
**
** Returns          void
**
*******************************************************************************/
void bta_dm_sco_co_open(UINT16 handle, UINT8 pkt_size, UINT16 event)
{
    BTIF_TRACE_DEBUG1("%s", __func__);
    UINT16 sco_buffer_size = (UINT16) (sizeof(BT_HDR)+HCI_SCO_PREAMBLE_SIZE+SCO_PACKET_SIZE);
    UINT8 sco_buffer_pool_id = GKI_create_pool(sco_buffer_size, SCO_POOL_SIZE, GKI_RESTRICTED_POOL, NULL);
    if (sco_buffer_pool_id == GKI_INVALID_POOL)
    {
        BTIF_TRACE_DEBUG0("Failed to create a new buffer");
    }
    tBTM_SCO_CFG cfg;
    cfg.sco_pool_id = sco_buffer_pool_id;
    cfg.pkt_size = pkt_size;
    cfg.event = event;
    cfg.sco_handle = handle;
    cfg.p_cback = btui_sco_codec_callback;
    btui_sco_register(&cfg);
}

/*******************************************************************************
**
** Function         bta_dm_sco_co_close
**
** Description      This function is called when a SCO connection is closed
**
**
** Returns          void
**
*******************************************************************************/
void bta_dm_sco_co_close(void)
{
    BTIF_TRACE_DEBUG1("%s", __func__);
    GKI_delete_pool(cur_cfg.sco_pool_id);
    cur_cfg.sco_pool_id = GKI_INVALID_POOL;

}

/*******************************************************************************
**
** Function         bta_dm_sco_co_in_data
**
** Description      This function is called to send incoming SCO data to application.
**
** Returns          void
**
*******************************************************************************/
void bta_dm_sco_co_in_data(BT_HDR  *p_buf,tBTM_SCO_DATA_FLAG status)
{
    uint8_t *p_data;
    int length;
    int i;
    BTIF_TRACE_DEBUG1("%s", __func__);
    if (p_buf != NULL)
    {
        p_data = (uint8_t*)p_buf+sizeof(BT_HDR)+HCI_SCO_PREAMBLE_SIZE;
        bta_dm_hsp_write_rx_data_buf(p_data, SCO_PACKET_SIZE);
        GKI_freebuf(p_buf);
    }
    else
        BTIF_TRACE_ERROR1("Invalid argument : NULL buffer in %s", __func__);
}

void btui_sco_codec_readbuf(BT_HDR **p_buf)
{
    static int count = 0;
    BTIF_TRACE_DEBUG1("%s", __func__);
    int r, xx;
    UINT8 *p_data_buf = NULL;
    UINT8 buffer[SCO_PACKET_SIZE];
    int retry_count = 0;
    int i = 0;
    *p_buf = NULL;
    if (count < SCO_PACKET_PER_TIMEOUT)
    {
        if(cur_cfg.sco_pool_id == GKI_INVALID_POOL)
        {
            for (xx = count; xx < SCO_PACKET_PER_TIMEOUT; xx++)
                bta_dm_hsp_read_tx_data_buf(buffer, SCO_PACKET_SIZE);
            count = 0;
            return;
        }
        else
        {
            while (retry_count < MAX_GET_POOL_BUF_RETRY)
            {
                *p_buf = (BT_HDR *) GKI_getpoolbuf(cur_cfg.sco_pool_id);
                if(*p_buf == NULL)
                {
                    BTIF_TRACE_DEBUG0("GKI failed to allocate");
                    BTIF_TRACE_DEBUG1("count = %d", count);
                    retry_count++;
                }
                else
                {
                    break;
                }
            }
            if (*p_buf == NULL)
            {
                BTIF_TRACE_ERROR1("Fail to allocate the buffer pull in %s", __func__);
                for (xx = count; xx < SCO_PACKET_PER_TIMEOUT; xx++)
                    bta_dm_hsp_read_tx_data_buf(buffer, SCO_PACKET_SIZE);
                count = 0;
                return;
            }
            else
            {
                p_data_buf = (UINT8*)*p_buf + (sizeof(BT_HDR)+HCI_SCO_PREAMBLE_SIZE);
                if ((r = bta_dm_hsp_read_tx_data_buf(p_data_buf, SCO_PACKET_SIZE)) > 0)
                {
                    if (r < SCO_PACKET_SIZE)
                    {
                        p_data_buf+=r;
                        memset(p_data_buf, 0, (SCO_PACKET_SIZE - r));
                    }
                    count++;
                }
                else
                {
                    BTIF_TRACE_DEBUG0("No Data in the buffer. Drift compensation");
                    memset(p_data_buf, 0, SCO_PACKET_SIZE);
                    count++;
                }
                (*p_buf)->len = SCO_PACKET_SIZE;
                (*p_buf)->offset = HCI_SCO_PREAMBLE_SIZE;
                (*p_buf)->layer_specific = 0;
            }
        }
    }
    else
    {
        count = 0;
    }
    return;
}

/*******************************************************************************
**
** Function         bta_dm_sco_co_out_data
**
** Description      This function is called to send SCO data over HCI.
**
** Returns          void
**
*******************************************************************************/
void bta_dm_sco_co_out_data(BT_HDR  **p_buf)
{
    btui_sco_codec_readbuf(p_buf);
}

#endif /* #if (BTM_SCO_HCI_INCLUDED == TRUE ) && (BTM_SCO_INCLUDED == TRUE)*/


#if (defined BLE_INCLUDED && BLE_INCLUDED == TRUE)
/*******************************************************************************
**
** Function         bta_dm_co_le_io_key_req
**
** Description      This callout function is executed by DM to get BLE key information
**                  before SMP pairing gets going.
**
** Parameters       bd_addr  - The peer device
**                  *p_max_key_size - max key size local device supported.
**                  *p_init_key - initiator keys.
**                  *p_resp_key - responder keys.
**
** Returns          void.
**
*******************************************************************************/
void bta_dm_co_le_io_key_req(BD_ADDR bd_addr, UINT8 *p_max_key_size,
                             tBTA_LE_KEY_TYPE *p_init_key,
                             tBTA_LE_KEY_TYPE  *p_resp_key )
{
    BTIF_TRACE_ERROR0("##################################");
    BTIF_TRACE_ERROR0("bta_dm_co_le_io_key_req: only setting max size to 16");
    BTIF_TRACE_ERROR0("##################################");
    *p_max_key_size = 16;
    *p_init_key = *p_resp_key =
                  (BTA_LE_KEY_PENC|BTA_LE_KEY_PID|BTA_LE_KEY_PCSRK|BTA_LE_KEY_LENC|BTA_LE_KEY_LID|BTA_LE_KEY_LCSRK);
}


/*******************************************************************************
**
** Function         bta_dm_co_ble_local_key_reload
**
** Description      This callout function is to load the local BLE keys if available
**                  on the device.
**
** Parameters       none
**
** Returns          void.
**
*******************************************************************************/
void bta_dm_co_ble_load_local_keys(tBTA_DM_BLE_LOCAL_KEY_MASK *p_key_mask, BT_OCTET16 er,
                                   tBTA_BLE_LOCAL_ID_KEYS *p_id_keys)
{
    BTIF_TRACE_DEBUG0("##################################");
    BTIF_TRACE_DEBUG0("bta_dm_co_ble_load_local_keys:  Load local keys if any are persisted");
    BTIF_TRACE_DEBUG0("##################################");
    btif_dm_get_ble_local_keys( p_key_mask, er, p_id_keys);
}

/*******************************************************************************
**
** Function         bta_dm_co_ble_io_req
**
** Description      This callout function is executed by DM to get BLE IO capabilities
**                  before SMP pairing gets going.
**
** Parameters       bd_addr  - The peer device
**                  *p_io_cap - The local Input/Output capabilities
**                  *p_oob_data - TRUE, if OOB data is available for the peer device.
**                  *p_auth_req -  Auth request setting (Bonding and MITM required or not)
**                  *p_max_key_size - max key size local device supported.
**                  *p_init_key - initiator keys.
**                  *p_resp_key - responder keys.
**
** Returns          void.
**
*******************************************************************************/
void bta_dm_co_ble_io_req(BD_ADDR bd_addr,  tBTA_IO_CAP *p_io_cap,
                          tBTA_OOB_DATA *p_oob_data,
                          tBTA_LE_AUTH_REQ *p_auth_req,
                          UINT8 *p_max_key_size,
                          tBTA_LE_KEY_TYPE *p_init_key,
                          tBTA_LE_KEY_TYPE  *p_resp_key )
{
    /* if OOB is not supported, this call-out function does not need to do anything
     * otherwise, look for the OOB data associated with the address and set *p_oob_data accordingly
     * If the answer can not be obtained right away,
     * set *p_oob_data to BTA_OOB_UNKNOWN and call bta_dm_ci_io_req() when the answer is available */

    *p_oob_data = FALSE;

    /* *p_auth_req by default is FALSE for devices with NoInputNoOutput; TRUE for other devices. */

    if (bte_appl_cfg.ble_auth_req)
        *p_auth_req = bte_appl_cfg.ble_auth_req | (bte_appl_cfg.ble_auth_req & 0x04) | ((*p_auth_req) & 0x04);

    if (bte_appl_cfg.ble_io_cap <=4)
        *p_io_cap = bte_appl_cfg.ble_io_cap;

    if (bte_appl_cfg.ble_init_key<=7)
        *p_init_key = bte_appl_cfg.ble_init_key;

    if (bte_appl_cfg.ble_resp_key<=7)
        *p_resp_key = bte_appl_cfg.ble_resp_key;

    if (bte_appl_cfg.ble_max_key_size > 7 && bte_appl_cfg.ble_max_key_size <= 16)
        *p_max_key_size = bte_appl_cfg.ble_max_key_size;
}


#endif

