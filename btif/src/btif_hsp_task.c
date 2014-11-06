/******************************************************************************
 *
 *  Copyright (C) 2009-2012 Broadcom Corporation
 *  Copyright (C) 2013 Intel Corporation
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

/******************************************************************************
 **
 **  Name:          btif_hsp_task.c
 **
 **  Description:   This is the multimedia module for the BTIF system.  It
 **                 contains task implementations HS and HF profiles
 **                 voice processing
 **
 ******************************************************************************/

#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/time.h>

#include "bt_target.h"
#include "gki.h"
#include "bta_api.h"
#include "btu.h"
#include "bta_sys.h"
#include "bta_sys_int.h"

#include "bta_av_api.h"

#include "a2d_api.h"
#include "a2d_sbc.h"
#include "a2d_int.h"
#include "bta_av_sbc.h"
#include "bta_av_ci.h"
#include "l2c_api.h"
#include "bta_ag_api.h"

#include "btif_av_co.h"
#include "btif_media.h"

#define LOG_TAG "BTIF-HSP"

#include <hardware/bluetooth.h>
#include "audio_hsp_hw.h"
#include "btif_av.h"
#include "btif_sm.h"
#include "btif_util.h"
#include "btif_hf.h"
#include "bt_utils.h"

/*****************************************************************************
 **  Constants
 *****************************************************************************/
#define HSP_TX_START_TIMER 0
#define HSP_RX_START_TIMER 1
#define HSP_TX_STOP_TIMER  2
#define HSP_RX_STOP_TIMER  3

/* BTIF hsp task gki event definition */
#define BTIF_HSP_TASK_CMD TASK_MBOX_0_EVT_MASK
#define BTIF_HSP_TASK_DATA TASK_MBOX_1_EVT_MASK

#define BTIF_HSP_TASK_KILL EVENT_MASK(GKI_SHUTDOWN_EVT)

#define BTIF_HSP_OUT_TASK_TIMER_ID TIMER_0
#define BTIF_HSP_OUT_TASK_TIMER TIMER_0_EVT_MASK
#define BTIF_HSP_IN_TASK_TIMER_ID TIMER_1
#define BTIF_HSP_IN_TASK_TIMER TIMER_1_EVT_MASK

#define BTIF_HSP_TASK_CMD_MBOX        TASK_MBOX_0     /* ctrl mailbox  */
#define BTIF_HSP_TASK_DATA_MBOX       TASK_MBOX_1     /* data mailbox  */

enum {
    HSP_TASK_STATE_OFF = 0,
    HSP_TASK_STATE_ON = 1,
    HSP_TASK_STATE_SHUTTING_DOWN = 2
};

/* Macro to multiply the hsp task tick */
#ifndef BTIF_HSP_NUM_TICK
#define BTIF_HSP_NUM_TICK      1
#endif

/* Hsp task tick in milliseconds */
#define BTIF_HSP_OUT_TIME_TICK                     (30 * BTIF_HSP_NUM_TICK)
#define BTIF_HSP_IN_TIME_TICK                      (120 * BTIF_HSP_NUM_TICK)

#ifndef HSP_TASK_STACK_SIZE
#define HSP_TASK_STACK_SIZE       0x2000         /* In bytes */
#endif

#define HSP_TASK_TASK_STR        ((INT8 *) "HSP")
static UINT32 HSP_TASK_stack[(HSP_TASK_STACK_SIZE + 3) / 4];

#define VOICE_MAX_TX_DATA_BTYES 480
#define VOICE_MAX_RX_DATA_BTYES 1920

#ifdef BTIF_MEDIA_VERBOSE_ENABLED
#define VERBOSE(fmt, ...) \
      LogMsg( TRACE_CTRL_GENERAL | TRACE_LAYER_NONE | TRACE_ORG_APPL | \
              TRACE_TYPE_ERROR, fmt, ## __VA_ARGS__)
#else
#define VERBOSE(fmt, ...)
#endif

/*****************************************************************************
 **  Data types
 *****************************************************************************/

typedef struct
{
    BOOLEAN is_tx_started;
    BOOLEAN is_rx_started;
    UINT8 hsp_out_cmd_pending; /* we can have max one command pending */
    UINT8 hsp_in_cmd_pending; /* we can have max one command pending */
} tbtif_hsp_cb;

/*****************************************************************************
 **  Local data
 *****************************************************************************/

static tbtif_hsp_cb btif_hsp_cb;
static int hsp_task_running = HSP_TASK_STATE_OFF;


/*****************************************************************************
 **  Local functions
 *****************************************************************************/

static void btif_hsp_data_out_cb(tUIPC_CH_ID ch_id, tUIPC_EVENT event);
static void btif_hsp_data_in_cb(tUIPC_CH_ID ch_id, tUIPC_EVENT event);
static void btif_hsp_ctrl_out_cb(tUIPC_CH_ID ch_id, tUIPC_EVENT event);
static void btif_hsp_ctrl_in_cb(tUIPC_CH_ID ch_id, tUIPC_EVENT event);
static void btif_hsp_task_out_handle_timer(void);
static void btif_hsp_task_in_handle_timer(void);
static void btif_hsp_task(void *p);
static void btif_hsp_task_handle_cmd(BT_HDR *p_msg);
static void start_tx_timer();
static void start_rx_timer();
static void stop_tx_timer();
static void stop_rx_timer();
static BOOLEAN send_timer_event(UINT16 event);

/*****************************************************************************
 **  Externs
 *****************************************************************************/
extern BOOLEAN is_audio_connected();

/*****************************************************************************
 **  Misc helper functions
 *****************************************************************************/

const char* dump_hsp_event(UINT16 event)
{
    switch(event)
    {
        CASE_RETURN_STR(HSP_TX_START_TIMER)
        CASE_RETURN_STR(HSP_RX_START_TIMER)
        default:
            return "UNKNOWN HSP EVENT";
    }
}

static const char* dump_hsp_ctrl_event(UINT8 event)
{
    switch(event)
    {
        CASE_RETURN_STR(HSP_CTRL_CMD_NONE)
        CASE_RETURN_STR(HSP_CTRL_CMD_CHECK_READY)
        CASE_RETURN_STR(HSP_CTRL_CMD_START)
        CASE_RETURN_STR(HSP_CTRL_CMD_STOP)
        CASE_RETURN_STR(HSP_CTRL_CMD_SUSPEND)
        default:
            return "UNKNOWN MSG ID";
    }
}

static void hsp_out_cmd_acknowledge(UINT8 status)
{
    UINT8 ack = status;

    APPL_TRACE_EVENT("## hsp out ack : %s, status %d ##", dump_hsp_ctrl_event(btif_hsp_cb.hsp_out_cmd_pending), status);

    /* sanity check */
    if (btif_hsp_cb.hsp_out_cmd_pending == HSP_CTRL_CMD_NONE)
    {
        APPL_TRACE_ERROR("warning : no command pending, ignore ack");
        return;
    }

/* clear pending */
    btif_hsp_cb.hsp_out_cmd_pending = HSP_CTRL_CMD_NONE;

    /* acknowledge start request */
    UIPC_Send(UIPC_CH_ID_VOICE_OUT_CTRL, 0, &ack, 1);
}

static void hsp_in_cmd_acknowledge(UINT8 status)
{
    UINT8 ack = status;

    APPL_TRACE_EVENT("## hsp in ack : %s, status %d ##", dump_hsp_ctrl_event(btif_hsp_cb.hsp_in_cmd_pending), status);

    /* sanity check */
    if (btif_hsp_cb.hsp_in_cmd_pending == HSP_CTRL_CMD_NONE)
    {
        APPL_TRACE_ERROR("warning : no command pending, ignore ack");
        return;
    }

    /* clear pending */
    btif_hsp_cb.hsp_in_cmd_pending = HSP_CTRL_CMD_NONE;

    /* acknowledge start request */
    UIPC_Send(UIPC_CH_ID_VOICE_IN_CTRL, 0, &ack, 1);
}

static void btif_recv_data_out_data(void)
{
    if (BTA_dm_hsp_get_tx_data_buf_size() >= VOICE_MAX_TX_DATA_BTYES)
    {
        UINT8 read_buffer[VOICE_MAX_RX_DATA_BTYES];
        UINT16 n;

        n = UIPC_Read(UIPC_CH_ID_VOICE_OUT_DATA, NULL, read_buffer,VOICE_MAX_TX_DATA_BTYES );

        if (n == 0)
        {
            APPL_TRACE_ERROR("Read to fail the data from HSP OUT DATA CH");
            APPL_TRACE_EVENT("DATA CH DETACHED");
            UIPC_Close(UIPC_CH_ID_VOICE_OUT_DATA);
            return;
        }

        APPL_TRACE_DEBUG("%s : Writing to buffer %d bytes",__func__,n);
        BTA_dm_hsp_write_tx_data_buf(read_buffer,n);
    }
    return;
}

static void btif_recv_data_in_data(void)
{
    UINT8 cmd = 0;
    UINT32 n;

    n = UIPC_Read(UIPC_CH_ID_VOICE_IN_DATA, NULL, &cmd, 1);
    //do nothing with the read data since this funciton should not get called.
}

static void btif_recv_ctrl_out_data(void)
{
    UINT8 cmd = 0;
    UINT32 n;

    n = UIPC_Read(UIPC_CH_ID_VOICE_OUT_CTRL, NULL, &cmd, 1);

    /* detach on ctrl channel means audioflinger process was terminated */
    if (n == 0)
    {
        APPL_TRACE_ERROR("Read to fail the data from HSP OUT CTRL CH");
        APPL_TRACE_EVENT("CTRL OUT CH DETACHED");
        UIPC_Close(UIPC_CH_ID_VOICE_OUT_CTRL);
        return;
    }

    APPL_TRACE_DEBUG("hsp-ctrl-out-cmd : %s", dump_hsp_ctrl_event(cmd));

    btif_hsp_cb.hsp_out_cmd_pending = cmd;

    switch(cmd)
    {
        case HSP_CTRL_CMD_CHECK_READY:

            if (hsp_task_running == HSP_TASK_STATE_SHUTTING_DOWN)
            {
                hsp_out_cmd_acknowledge(HSP_CTRL_ACK_FAILURE);
                return;
            }

            if (is_audio_connected())
            {
                hsp_out_cmd_acknowledge(HSP_CTRL_ACK_SUCCESS);
            }
            else
            {
                hsp_out_cmd_acknowledge(HSP_CTRL_ACK_FAILURE);
            }
            break;

        case HSP_CTRL_CMD_START:
                /* setup hsp data channel listener */
            if(!UIPC_Open(UIPC_CH_ID_VOICE_OUT_DATA, btif_hsp_data_out_cb))
            {
                APPL_TRACE_ERROR("Unable to open HSP Voice out data channel");
                hsp_out_cmd_acknowledge(HSP_CTRL_ACK_FAILURE);
            }
            else
            {
                if(btif_hsp_cb.is_tx_started != TRUE)
                {
                    btif_hsp_cb.is_tx_started = TRUE;
                                       if(!send_timer_event(HSP_TX_START_TIMER))
                    {
                        APPL_TRACE_ERROR("Error in sending the start tx timer event");
                        hsp_out_cmd_acknowledge(HSP_CTRL_ACK_FAILURE);
                        break;
                    }
                }
                hsp_out_cmd_acknowledge(HSP_CTRL_ACK_SUCCESS);
            }
            break;

        case HSP_CTRL_CMD_STOP:
        case HSP_CTRL_CMD_SUSPEND:
            if(btif_hsp_cb.is_tx_started == TRUE)
            {
                               if(!send_timer_event(HSP_TX_STOP_TIMER))
                               {
                                       APPL_TRACE_ERROR("Error in sending the stop tx timer event");
                                       hsp_out_cmd_acknowledge(HSP_CTRL_ACK_FAILURE);
                                       break;
                               }
                               btif_hsp_cb.is_tx_started = FALSE;
                               BTA_dm_hsp_flush_tx_data_buf();
            }
            UIPC_Close(UIPC_CH_ID_VOICE_OUT_DATA);
            hsp_out_cmd_acknowledge(HSP_CTRL_ACK_SUCCESS);
            break;

        default:
            APPL_TRACE_ERROR("UNSUPPORTED CMD (%d)", cmd);
            hsp_out_cmd_acknowledge(HSP_CTRL_ACK_FAILURE);
            break;
    }
    APPL_TRACE_DEBUG("hsp-ctrl-out-cmd : %s DONE", dump_hsp_ctrl_event(cmd));
}

static void btif_recv_ctrl_in_data(void)
{
    UINT8 cmd = 0;
    UINT32 n;

    n = UIPC_Read(UIPC_CH_ID_VOICE_IN_CTRL, NULL, &cmd, 1);

    /* detach on ctrl channel means audioflinger process was terminated */
    if (n == 0)
    {
        APPL_TRACE_EVENT("CTRL IN CH DETACHED");
        UIPC_Close(UIPC_CH_ID_VOICE_IN_CTRL);
        return;
    }

    APPL_TRACE_DEBUG("hsp-ctrl-in-cmd : %s", dump_hsp_ctrl_event(cmd));

    btif_hsp_cb.hsp_in_cmd_pending = cmd;

    switch(cmd)
    {
        case HSP_CTRL_CMD_CHECK_READY:

            if (hsp_task_running == HSP_TASK_STATE_SHUTTING_DOWN)
            {
                hsp_in_cmd_acknowledge(HSP_CTRL_ACK_FAILURE);
                return;
            }

            if (is_audio_connected())
            {
                hsp_in_cmd_acknowledge(HSP_CTRL_ACK_SUCCESS);
            }
            else
            {
                hsp_in_cmd_acknowledge(HSP_CTRL_ACK_FAILURE);
            }
            break;

        case HSP_CTRL_CMD_START:
                /* setup hsp data channel listener */
            if(!UIPC_Open(UIPC_CH_ID_VOICE_IN_DATA, btif_hsp_data_in_cb))
            {
                APPL_TRACE_ERROR("Unable to open HSP Voice in data channel");
                hsp_in_cmd_acknowledge(HSP_CTRL_ACK_FAILURE);
            }
            else
            {
                if(btif_hsp_cb.is_rx_started != TRUE)
                {
                    btif_hsp_cb.is_rx_started = TRUE;
                                       if(!send_timer_event(HSP_RX_START_TIMER))
                    {
                        APPL_TRACE_ERROR("Error in sending the start rx timer event");
                        hsp_in_cmd_acknowledge(HSP_CTRL_ACK_FAILURE);
                        break;
                    }
                }
                hsp_in_cmd_acknowledge(HSP_CTRL_ACK_SUCCESS);
            }
            break;
        case HSP_CTRL_CMD_STOP:
        case HSP_CTRL_CMD_SUSPEND:
            if(btif_hsp_cb.is_rx_started == TRUE)
            {
                               if(!send_timer_event(HSP_RX_STOP_TIMER))
                               {
                                       APPL_TRACE_ERROR("Error in sending the stop rx timer event");
                                       hsp_in_cmd_acknowledge(HSP_CTRL_ACK_FAILURE);
                                       break;
                               }
                               btif_hsp_cb.is_rx_started = FALSE;
                               BTA_dm_hsp_flush_rx_data_buf();
            }
            UIPC_Close(UIPC_CH_ID_VOICE_IN_DATA);
            hsp_in_cmd_acknowledge(HSP_CTRL_ACK_SUCCESS);
            break;

        default:
            APPL_TRACE_ERROR("UNSUPPORTED CMD (%d)", cmd);
            hsp_in_cmd_acknowledge(HSP_CTRL_ACK_FAILURE);
            break;
    }
    APPL_TRACE_DEBUG("hsp-ctrl-in-cmd : %s DONE", dump_hsp_ctrl_event(cmd));
}

static void btif_hsp_ctrl_out_cb(tUIPC_CH_ID ch_id, tUIPC_EVENT event)
{
    APPL_TRACE_DEBUG("HSP-CTRL-OUT-CHANNEL EVENT %s", dump_uipc_event(event));

    switch(event)
    {
        case UIPC_OPEN_EVT:
            break;

        case UIPC_CLOSE_EVT:
            /* restart ctrl server unless we are shutting down */
            if (hsp_task_running == HSP_TASK_STATE_ON)
                if(!UIPC_Open(UIPC_CH_ID_VOICE_OUT_CTRL , btif_hsp_ctrl_out_cb))
                    APPL_TRACE_ERROR("Unable to open HSP Voice out ctrl channel");
            break;

        case UIPC_RX_DATA_READY_EVT:
            btif_recv_ctrl_out_data();
            break;

        default :
            APPL_TRACE_ERROR("### HSP-CTRL-OUT-CHANNEL EVENT %d NOT HANDLED ###", event);
            break;
    }
}

static void btif_hsp_ctrl_in_cb(tUIPC_CH_ID ch_id, tUIPC_EVENT event)
{
    APPL_TRACE_DEBUG("HSP-CTRL-IN-CHANNEL EVENT %s", dump_uipc_event(event));

    switch(event)
    {
        case UIPC_OPEN_EVT:
            break;

        case UIPC_CLOSE_EVT:
            /* restart ctrl server unless we are shutting down */
            if (hsp_task_running == HSP_TASK_STATE_ON)
                if(!UIPC_Open(UIPC_CH_ID_VOICE_IN_CTRL , btif_hsp_ctrl_in_cb))
                    APPL_TRACE_ERROR("Unable to open HSP Voice in ctrl channel");
            break;

        case UIPC_RX_DATA_READY_EVT:
            btif_recv_ctrl_in_data();
            break;

        default :
            APPL_TRACE_ERROR("### HSP-CTRL-IN-CHANNEL EVENT %d NOT HANDLED ###", event);
            break;
    }
}

static void btif_hsp_data_out_cb(tUIPC_CH_ID ch_id, tUIPC_EVENT event)
{
    //APPL_TRACE_DEBUG1("BTIF HSP OUT EVENT %s", dump_uipc_event(event));

    switch(event)
    {
        case UIPC_OPEN_EVT:
            break;

        case UIPC_CLOSE_EVT:
            break;

        case UIPC_RX_DATA_READY_EVT:
            btif_recv_data_out_data();
            break;

        default :
            APPL_TRACE_ERROR("### HSP-DATA EVENT %d NOT HANDLED ###", event);
            break;
    }
}

static void btif_hsp_data_in_cb(tUIPC_CH_ID ch_id, tUIPC_EVENT event)
{
    APPL_TRACE_DEBUG("BTIF HSP IN EVENT %s", dump_uipc_event(event));

    switch(event)
    {
        case UIPC_OPEN_EVT:
            break;

        case UIPC_CLOSE_EVT:
            break;

        case UIPC_RX_DATA_READY_EVT:
            btif_recv_data_in_data();
            break;

        default :
            APPL_TRACE_ERROR("### HSP-DATA EVENT %d NOT HANDLED ###", event);
            break;
    }
}

/*****************************************************************************
**
** Function        btif_start_hsp_task
**
** Description
**
** Returns
**
*******************************************************************************/
UINT8 btif_start_hsp_task(void)
{
    UINT8 retval;
    APPL_TRACE_DEBUG("%s",__func__);

    if (hsp_task_running != HSP_TASK_STATE_OFF)
    {
        APPL_TRACE_ERROR("warning : hsp task already running");
        return GKI_FAILURE;
    }

    APPL_TRACE_EVENT("## START HSP TASK ##");

    /* start hsp task */
    retval = GKI_create_task((TASKPTR)btif_hsp_task, HSP_TASK,
                HSP_TASK_TASK_STR,
                (UINT16 *) ((UINT8 *)HSP_TASK_stack + HSP_TASK_STACK_SIZE),
                sizeof(HSP_TASK_stack));

    if (retval != GKI_SUCCESS)
        return retval;

    /* wait for task to come up to sure we are able to send messages to it */
    while (hsp_task_running == HSP_TASK_STATE_OFF)
        usleep(10);

    APPL_TRACE_EVENT("## HSP TASK STARTED ##");

    return retval;
}

/*****************************************************************************
**
** Function        btif_stop_hsp_task
**
** Description
**
** Returns
**
*******************************************************************************/
void btif_stop_hsp_task(void)
{
    APPL_TRACE_EVENT("## STOP HSP TASK ##");
    GKI_destroy_task(HSP_TASK);
}

/*******************************************************************************
 **
 ** Function         btif_hsp_task_init
 **
 ** Description
 **
 ** Returns          void
 **
 *******************************************************************************/
void btif_hsp_task_init(void)
{
    memset(&(btif_hsp_cb), 0, sizeof(btif_hsp_cb));

    UIPC_Init(NULL);

#if (BTM_SCO_HCI_INCLUDED == TRUE)
    if(!UIPC_Open(UIPC_CH_ID_VOICE_OUT_CTRL , btif_hsp_ctrl_out_cb))
        APPL_TRACE_ERROR("Unable to open HSP Voice out ctrl channel");
    if(!UIPC_Open(UIPC_CH_ID_VOICE_IN_CTRL , btif_hsp_ctrl_in_cb))
        APPL_TRACE_ERROR("Unable to open HSP Voice in ctrl channel");
#endif
}

/*******************************************************************************
 **
 ** Function         btif_hsp_task
 **
 ** Description
 **
 ** Returns          void
 **
 *******************************************************************************/
void btif_hsp_task(void *p)
{
    UINT16 event;
    BT_HDR *p_msg;

    VERBOSE("================ HSP TASK STARTING ================");

    btif_hsp_task_init();

    hsp_task_running = HSP_TASK_STATE_ON;

    while (1)
    {
        /* wait for all events */
        event = GKI_wait(0xffff, 0);

        VERBOSE("================= HSP TASK EVENT %d ===============", event);

        if (event & BTIF_HSP_TASK_CMD)
        {
            /* Process all messages in the queue */
            while ((p_msg = (BT_HDR *) GKI_read_mbox(BTIF_HSP_TASK_CMD_MBOX)) != NULL)
            {
                btif_hsp_task_handle_cmd(p_msg);

            }
        }

        if (event & BTIF_HSP_OUT_TASK_TIMER)
        {
            /* advance audio timer expiration */
            btif_hsp_task_out_handle_timer();
        }
        
         if (event & BTIF_HSP_IN_TASK_TIMER)
        {
            /* advance audio timer expiration */
            btif_hsp_task_in_handle_timer();
        }

        VERBOSE("=============== HSP TASK EVENT %d DONE ============", event);

        /* When we get this event we exit the task  - should only happen on GKI_shutdown  */
        if (event & BTIF_HSP_TASK_KILL)
        {
            /* make sure no channels are restarted while shutting down */
            hsp_task_running = HSP_TASK_STATE_SHUTTING_DOWN;

            /* this calls blocks until uipc is fully closed */
            UIPC_Close(UIPC_CH_ID_VOICE_ALL);
            break;
        }
    }

    /* Clear hsp task flag */
    hsp_task_running = HSP_TASK_STATE_OFF;

    APPL_TRACE_DEBUG("HSP TASK EXITING");

    return;
}


/*******************************************************************************
 **
 ** Function         btif_hsp_task_handle_cmd
 **
 ** Description
 **
 ** Returns          void
 **
 *******************************************************************************/
static void btif_hsp_task_handle_cmd(BT_HDR *p_msg)
{
    VERBOSE("btif_hsp_task_handle_cmd : %d %s", p_msg->event, dump_hsp_event(p_msg->event));

    switch (p_msg->event)
    {
    case HSP_TX_START_TIMER:
        start_tx_timer();
        break;
    case HSP_RX_START_TIMER:
        start_rx_timer();
        break;
       case HSP_TX_STOP_TIMER:
               stop_tx_timer();
               break;
       case HSP_RX_STOP_TIMER:
               stop_rx_timer();
               break;
    default:
        APPL_TRACE_ERROR("ERROR in btif_hsp_task_handle_cmd unknown event %d", p_msg->event);
    }
    GKI_freebuf(p_msg);
    VERBOSE("btif_hsp_task_handle_cmd : %s DONE", dump_hsp_event(p_msg->event));
}

/*******************************************************************************
 **
 ** Function         btif_hsp_task_out_handle_timer
 **
 ** Description
 **
 ** Returns          void
 **
 *******************************************************************************/
static void btif_hsp_task_out_handle_timer(void)
{
    APPL_TRACE_DEBUG("Timer timed out : Sending sco data trigger");
    int i;
    for (i = 0; i < btif_max_hf_clients; i++)
    {
        BTA_AgSendScoData(btif_hf_cb[i].handle);
    }
}

static void btif_hsp_task_in_handle_timer(void)
{
    UINT8 buffer[VOICE_MAX_RX_DATA_BTYES];
    UINT16 length_read = 0;

    APPL_TRACE_DEBUG("Timer timed out : Sending sco data audio flinger");

    if((length_read = BTA_dm_hsp_read_rx_data_buf(buffer,VOICE_MAX_RX_DATA_BTYES))>0)
    {
        UIPC_Send(UIPC_CH_ID_VOICE_IN_DATA, 0, buffer, length_read);
    }
    else
        APPL_TRACE_WARNING("Error in reading the data from HSP Rx buffer");
}

static void start_tx_timer()
{
    APPL_TRACE_EVENT("starting tx timer %d ticks (%d)", GKI_MS_TO_TICKS(BTIF_HSP_OUT_TIME_TICK), TICKS_PER_SEC);
    GKI_start_timer(BTIF_HSP_OUT_TASK_TIMER_ID, GKI_MS_TO_TICKS(BTIF_HSP_OUT_TIME_TICK), TRUE);
}

static void start_rx_timer()
{
    APPL_TRACE_EVENT("starting rx timer %d ticks (%d)", GKI_MS_TO_TICKS(BTIF_HSP_IN_TIME_TICK), TICKS_PER_SEC);
    GKI_start_timer(BTIF_HSP_IN_TASK_TIMER_ID, GKI_MS_TO_TICKS(BTIF_HSP_IN_TIME_TICK), TRUE);
}

static void stop_tx_timer()
{
       APPL_TRACE_EVENT("stopping hsp tx timer");
       GKI_stop_timer(BTIF_HSP_OUT_TASK_TIMER_ID);
}

static void stop_rx_timer()
{
       APPL_TRACE_EVENT("stopping hsp rx timer");
       GKI_stop_timer(BTIF_HSP_IN_TASK_TIMER_ID);
}

static BOOLEAN send_timer_event(UINT16 event)
{
    BT_HDR *p_buf;
    if (NULL == (p_buf = GKI_getbuf(sizeof(BT_HDR))))
    {
        APPL_TRACE_EVENT("GKI failed");
        return FALSE;
    }

    p_buf->event = event;

    GKI_send_msg(HSP_TASK, BTIF_HSP_TASK_CMD_MBOX, p_buf);
    return TRUE;
}
