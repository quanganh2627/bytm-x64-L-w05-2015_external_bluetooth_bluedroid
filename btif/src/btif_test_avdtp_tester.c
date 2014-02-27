/******************************************************************************
 *  Copyright (C) 2012-2013 Intel Mobile Communications GmbH
 *  Copyright (C) 2000-2012 Broadcom Corporation
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
 *  Filename:      btif_test_avdtp_tester.c
 *
 *  Description:   Bluedroid AV implementation
 *
 *****************************************************************************/

#include <hardware/bluetooth.h>
#include "hardware/bt_av.h"

#define LOG_TAG "BTIF_AV"

#include "btif_av.h"
#include "btif_util.h"
#include "btif_profile_queue.h"
#include "bta_api.h"
#include "btif_media.h"
#include "bta_av_api.h"
#include "gki.h"
#include "bd.h"
#include "btu.h"

#include "avdt_api.h"
#include "a2d_sbc.h"
#include "l2cdefs.h"
#include "avdt_defs.h"

#include "btif_test.h"

#define STACK_QUALIFICATION

/*****************************************************************************
**  Constants & Macros
******************************************************************************/
#define BTIF_AV_SERVICE_NAME "Advanced Audio"

#define BTIF_TIMEOUT_AV_OPEN_ON_RC_SECS  2


#define AV_MAX_A2DP_MTU     1008
#define AV_RET_TOUT     4
#define AV_SIG_TOUT     4
#define AV_IDLE_TOUT    10
#define AV_SEC_NONE 0
#define AV_SEC_IN_AUTHENTICATE 0x0002
#define AV_SEC_OUT_AUTHENTICATE 0x0010
#define AV_MEDIA_PKT 500
#define AV_NUM_SEPS 32
#define AV_MAX_SEIDS 3

typedef enum {
    BTIF_AV_STATE_IDLE = 0x0,
    BTIF_AV_STATE_OPENING,
    BTIF_AV_STATE_OPENED,
    BTIF_AV_STATE_STARTED,
    BTIF_AV_STATE_CLOSING
} btif_av_state_t;

/* Should not need dedicated suspend state as actual actions are no
   different than open state. Suspend flags are needed however to prevent
   media task from trying to restart stream during remote suspend or while
   we are in the process of a local suspend */

#define BTIF_AV_FLAG_LOCAL_SUSPEND_PENDING 0x1
#define BTIF_AV_FLAG_REMOTE_SUSPEND        0x2

/*****************************************************************************
**  Local type definitions
******************************************************************************/

typedef struct
{
    tBTA_AV_HNDL bta_handle;
    bt_bdaddr_t peer_bda;
    btif_sm_handle_t sm_handle;
    UINT8 flags;
} btif_av_cb_t;

/*****************************************************************************
**  Static variables
******************************************************************************/
static BD_ADDR rbd_addr;

static btav_callbacks_t *bt_av_callbacks = NULL;
static btif_av_cb_t btif_av_cb;
static TIMER_LIST_ENT tle_av_open_on_rc;

static tAVDT_SEP_INFO sep_info[AV_NUM_SEPS];
static tAVDT_CFG sep_cfg;

static UINT8  dseps_count;

static tAVDT_CFG sep_peer_cfg[AV_NUM_SEPS];
static tAVDT_CFG sep_cfg_arr[AV_MAX_SEIDS];

//static UINT8 bt_av_handle = 0x40 | 1; // BTA_AV_CHNL_AUDIO = 0x40
static UINT8 bt_av_handle;
static UINT32 sdp_a2d_handle;
//BOOLEAN tester_av_reject = FALSE;
//BOOLEAN tester_av_greject = FALSE;

const tA2D_SBC_CIE av_co_sbc_caps =
{
    (A2D_SBC_IE_SAMP_FREQ_44), /* samp_freq */
    (A2D_SBC_IE_CH_MD_MONO | A2D_SBC_IE_CH_MD_STEREO | A2D_SBC_IE_CH_MD_JOINT | A2D_SBC_IE_CH_MD_DUAL), /* ch_mode */
    (A2D_SBC_IE_BLOCKS_16 | A2D_SBC_IE_BLOCKS_12 | A2D_SBC_IE_BLOCKS_8 | A2D_SBC_IE_BLOCKS_4), /* block_len */
    (A2D_SBC_IE_SUBBAND_4 | A2D_SBC_IE_SUBBAND_8), /* num_subbands */
    (A2D_SBC_IE_ALLOC_MD_L | A2D_SBC_IE_ALLOC_MD_S), /* alloc_mthd */
    A2D_SBC_IE_MAX_BITPOOL, /* max_bitpool */
    A2D_SBC_IE_MIN_BITPOOL /* min_bitpool */
};

/* Default SBC codec configuration */
const tA2D_SBC_CIE av_sbc_default_config =
{
    A2D_SBC_IE_SAMP_FREQ_44,        /* samp_freq */
    A2D_SBC_IE_CH_MD_JOINT,         /* ch_mode */
    A2D_SBC_IE_BLOCKS_16,           /* block_len */
    A2D_SBC_IE_SUBBAND_8,           /* num_subbands */
    A2D_SBC_IE_ALLOC_MD_L,          /* alloc_mthd */
    A2D_SBC_IE_MAX_BITPOOL,         /* max_bitpool */
    A2D_SBC_IE_MIN_BITPOOL          /* min_bitpool */
};

const tA2D_SBC_CIE av_sbc_reconfig =
{
    A2D_SBC_IE_SAMP_FREQ_32,        /* samp_freq */
    A2D_SBC_IE_CH_MD_MONO,          /* ch_mode */
    A2D_SBC_IE_BLOCKS_8,            /* block_len */
    A2D_SBC_IE_SUBBAND_8,           /* num_subbands */
    A2D_SBC_IE_ALLOC_MD_S,          /* alloc_mthd */
    A2D_SBC_IE_MAX_BITPOOL,         /* max_bitpool */
    A2D_SBC_IE_MIN_BITPOOL          /* min_bitpool */
};


UINT8 av_media_pkt[] =
    {0x34 ,0x5b ,0x04 ,0x7f ,0xe8 ,0x00 ,0x00 ,0x00 ,0x00 ,0x01 ,0x0b ,0x9c ,
    0xbd ,0x20 ,0x7c ,0xbc ,0xb8 ,0x65 ,0x43 ,0x00 ,0xa8 ,0x63 ,0x11 ,0x00 ,0x52 ,0xd2 ,0x5c ,
    0xbd ,0x45 ,0x60 ,0x99 ,0x5b ,0x36 ,0x41 ,0x5c ,0xab ,0x16 ,0xc5 ,0x25 ,0x4d ,0x28 ,0x81 ,
    0x2b, 0x8b, 0x81 , 0x05 , 0x2d , 0x52 , 0x69 , 0x61 , 0x24 , 0x52 , 0x8c, 0x69 , 0x5e ,
    0xb3 , 0xc2 , 0xe1 , 0xa3 , 0xa4 , 0x96 , 0xf1 , 0x34 , 0x34 , 0x65 , 0x0c , 0x72 , 0x4b ,
    0x82 , 0xf1 , 0xaf , 0xcc , 0x86 , 0xf1 , 0x66 , 0xbc , 0x82 , 0x4d , 0x5a , 0x2a , 0x87 ,
    0x55 , 0x5d , 0xd4 , 0x74 , 0x69 , 0x68 , 0xd4 , 0x9c , 0xbd , 0x20 , 0x69 , 0xfc , 0xc9 ,
    0x66 , 0x43 , 0x00 , 0xa8 , 0x53 , 0x22 , 0x00 , 0x67 , 0xcc , 0x75 , 0x72 , 0x83 , 0x32 ,
    0x73 , 0x95 , 0x8a , 0xb2 , 0x6d , 0x65 , 0x8c , 0xb9 , 0x8a , 0xd0 , 0xae , 0xc2 , 0x6f ,
    0xa1 , 0xb8 , 0xc2 , 0x52 , 0x9d , 0xa1 , 0x32 , 0x73 };


/*************************************************************************
** Extern functions
*************************************************************************/


/*****************************************************************************
** Local helper functions
******************************************************************************/

const char *dump_av_event_name(UINT8 event)
{
   switch(event)
   {
       CASE_RETURN_STR(AVDT_DISCOVER_CFM_EVT)
       CASE_RETURN_STR(AVDT_GETCAP_CFM_EVT)
       CASE_RETURN_STR(AVDT_OPEN_CFM_EVT)
       CASE_RETURN_STR(AVDT_OPEN_IND_EVT)
       CASE_RETURN_STR(AVDT_CONFIG_IND_EVT)
       CASE_RETURN_STR(AVDT_START_CFM_EVT)
       CASE_RETURN_STR(AVDT_START_IND_EVT)
       CASE_RETURN_STR(AVDT_SUSPEND_CFM_EVT)
       CASE_RETURN_STR(AVDT_SUSPEND_IND_EVT)
       CASE_RETURN_STR(AVDT_CLOSE_CFM_EVT)
       CASE_RETURN_STR(AVDT_CLOSE_IND_EVT)
       CASE_RETURN_STR(AVDT_RECONFIG_CFM_EVT)
       CASE_RETURN_STR(AVDT_RECONFIG_IND_EVT)
       CASE_RETURN_STR(AVDT_SECURITY_CFM_EVT)
       CASE_RETURN_STR(AVDT_SECURITY_IND_EVT)
       CASE_RETURN_STR(AVDT_WRITE_CFM_EVT)
       CASE_RETURN_STR(AVDT_CONNECT_IND_EVT)
       CASE_RETURN_STR(AVDT_DISCONNECT_IND_EVT)
       CASE_RETURN_STR(AVDT_GETCFG_CFM_EVT)
       CASE_RETURN_STR(AVDT_ABORT_CFM_EVT)
       default: return "UNKNOWN EVENT";
   }
}

const char *dump_av_error_name(UINT8 error)
{
   switch(error)
   {
       case AVDT_ERR_HEADER: return "Bad packet header format";
       case AVDT_ERR_LENGTH: return "Bad packet length";
       case AVDT_ERR_SEID: return "Invalid SEID";
       case AVDT_ERR_IN_USE: return "SEP is in use";
       case AVDT_ERR_NOT_IN_USE: return "SEP is not in use";
       case AVDT_ERR_CATEGORY: return "Bad service category";
       case AVDT_ERR_PAYLOAD: return "Bad payload format";
       case AVDT_ERR_NSC: return "Requested command not supported";
       case AVDT_ERR_INVALID_CAP: return "Reconfigure attempted invalid capabilities";
       case AVDT_ERR_RECOV_TYPE: return "Requested recovery type not defined";
       case AVDT_ERR_MEDIA_TRANS: return "Media transport capability not correct";
       case AVDT_ERR_RECOV_FMT: return "Recovery service capability not correct";
       case AVDT_ERR_ROHC_FMT: return "Header compression service capability not correct";
       case AVDT_ERR_CP_FMT: return "Content protection service capability not correct";
       case AVDT_ERR_MUX_FMT: return "Multiplexing service capability not correct";
       case AVDT_ERR_UNSUP_CFG: return "Configuration not supported";
       case AVDT_ERR_BAD_STATE: return "Message cannot be processed in this state";
       case AVDT_ERR_REPORT_FMT: return "Report service capability not correct";
       case AVDT_ERR_SERVICE: return "Invalid service category";
       case AVDT_ERR_RESOURCE: return "Insufficient resources";
       case AVDT_ERR_INVALID_MCT: return "Invalid Media Codec Type";
       case AVDT_ERR_UNSUP_MCT: return "Unsupported Media Codec Type";
       case AVDT_ERR_INVALID_LEVEL: return "Invalid Level";
       case AVDT_ERR_UNSUP_LEVEL: return "Unsupported Level";
       case AVDT_ERR_INVALID_CP: return "Invalid Content Protection Type";
       case AVDT_ERR_INVALID_FORMAT: return "Invalid Content Protection format";
       case AVDT_ERR_CONNECT: return "Connection failed";
       case AVDT_ERR_TIMEOUT: return "Response timeout";
       default: return "UNKNOWN ERROR";
   }
}

char* av_get_media_type(UINT8 mt)
{
    mt = (mt & 0xF0) >> 4;

    if(mt == AVDT_MEDIA_AUDIO)
       {
        return "Audio";
       }
    else if(mt == AVDT_MEDIA_VIDEO)
       {
        return "Video";
       }
    else if(mt == AVDT_MEDIA_MULTI)
       {
        return "Multimedia";
       }
    else
       {
          return NULL;
       }
}

char* av_get_media_codec_type(UINT8 ct)
{
    if(ct == A2D_MEDIA_CT_SBC)
    {
     return "SBC";
    }
    else if(ct == A2D_MEDIA_CT_M12)
    {
        return "MPEG-1";
    }
    else if(ct == A2D_MEDIA_CT_M24)
    {
        return "MPEG-2";
    }
    else if(ct == A2D_MEDIA_CT_ATRAC)
    {
        return "ATRAC";
    }
    else
    {
       return NULL;
    }
}

void av_data_cb (UINT8 handle, BT_HDR *p_pkt, UINT32 time_stamp, UINT8 m_pt)
{
    BTIF_TRACE_EVENT1("%s", __FUNCTION__);

    GKI_freebuf(p_pkt);

    return;
}

void av_event_cb(UINT8 handle, BD_ADDR bd_addr, UINT8 event, tAVDT_CTRL *p_data)
{
    BTIF_TRACE_EVENT1("%s", __FUNCTION__);
    BTIF_TRACE_EVENT1("%s", dump_av_event_name(event));

    switch(event)
    {
        case AVDT_ABORT_CFM_EVT:
        {
        tAVDT_EVT_HDR *abort_cfm;

        abort_cfm = (tAVDT_EVT_HDR *) p_data;

        ALOGI("seid = %x, errcode = %x, error param = %x, label = %x", abort_cfm->seid ,abort_cfm->err_code, abort_cfm->err_param, abort_cfm->label );
        ALOGI("ccb_idx = %x, sig_id = %x", abort_cfm->ccb_idx, abort_cfm->sig_id);
        }
        break;

        case AVDT_GETCFG_CFM_EVT:
        {
        tAVDT_CONFIG *cfg_info;
        int i;

        cfg_info = (tAVDT_CONFIG *) p_data;

        ALOGI("Capabilities of SEP ");

        ALOGI("seid = %x, errcode = %x, error param = %x, label = %x", cfg_info->hdr.seid ,cfg_info->hdr.err_code, cfg_info->hdr.err_param, cfg_info->hdr.label );
        ALOGI("ccb_idx = %x, sig_id = %x", cfg_info->hdr.ccb_idx, cfg_info->hdr.sig_id);

        if(!cfg_info->hdr.err_code)
        {

            for(i = 0; i < AVDT_CODEC_SIZE; i++)
            {
               ALOGI("Codec info [%d] = %d", i,cfg_info->p_cfg->codec_info[i]);
            }
            ALOGI("No of codecs = %d", cfg_info->p_cfg->num_codec);
        }
        else
        {
            ALOGI("Error - %x: %s", cfg_info->hdr.err_code, dump_av_error_name(cfg_info->hdr.err_code));
        }
        }
        break;

        case AVDT_CONNECT_IND_EVT:
        break;

        case AVDT_DISCOVER_CFM_EVT:
        {
            tAVDT_DISCOVER *disc_info;
            int i;

            disc_info = (tAVDT_DISCOVER *) p_data;


            ALOGI("seid = %x, errcode = %x, error param = %x, label = %x", disc_info->hdr.seid ,disc_info->hdr.err_code, disc_info->hdr.err_param, disc_info->hdr.label );
            ALOGI("ccb_idx = %x, sig_id = %x", disc_info->hdr.ccb_idx, disc_info->hdr.sig_id);

            ALOGI("Discovered SEPs");

            if(!disc_info->hdr.err_code)
            {
                dseps_count = disc_info->num_seps;

                for(i = 0; i < dseps_count; i++)
                {
                    sep_info[i].seid = disc_info->p_sep_info->seid;
                    sep_info[i].in_use = disc_info->p_sep_info->in_use;
                    sep_info[i].media_type = disc_info->p_sep_info->media_type;
                    sep_info[i].tsep = disc_info->p_sep_info->tsep;

                    ALOGD("SEID: %d", sep_info[i].seid);

                    if(sep_info[i].in_use)
                        ALOGD("InUse: Yes");
                    else
                        ALOGD("InUse: No");

                    ALOGD("media_type: %s", av_get_media_type(sep_info[i].media_type));

                    if(sep_info[i].tsep)
                        ALOGD("tsep: SNK");
                    else
                        ALOGD("tsep: SRC");

                    }
            }
            else
            {
                ALOGI("Error - %x: %s", disc_info->hdr.err_code, dump_av_error_name(disc_info->hdr.err_code));
            }
        }
        break;

        case AVDT_GETCAP_CFM_EVT:
        {
        tAVDT_CONFIG *cfg_info;
        int i;

        cfg_info = (tAVDT_CONFIG *) p_data;

        if(!cfg_info->hdr.err_code)
        {

        ALOGD(" Length Of Service Capability (LOSC): %d", cfg_info->p_cfg->codec_info[0]);
        ALOGD(" Media Type: %s", av_get_media_type(cfg_info->p_cfg->codec_info[1]));
        ALOGD(" Media Codec Type: %s", av_get_media_codec_type(cfg_info->p_cfg->codec_info[2]));
        ALOGD(" Codec Info Element: ");

        ALOGD(" Sampling Frequency supported: ");
        if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_SAMP_FREQ_16)
            ALOGD(" 16  kHz");
        if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_SAMP_FREQ_32)
            ALOGD(" 32  kHz");
        if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_SAMP_FREQ_44)
            ALOGD(" 44  kHz");
        if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_SAMP_FREQ_48)
            ALOGD(" 48  kHz");

        ALOGD(" Channel Mode supported: ");
        if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_CH_MD_MONO)
            ALOGD(" Mono");
        if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_CH_MD_DUAL)
            ALOGD(" Dual");
        if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_CH_MD_STEREO)
            ALOGD(" Stereo");
        if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_CH_MD_JOINT)
            ALOGD(" joint Stereo");

        ALOGD(" Block Length supported: ");
        if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_BLOCKS_4)
            ALOGD(" 4");
        if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_BLOCKS_8)
            ALOGD(" 8");
        if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_BLOCKS_12)
            ALOGD(" 12");
        if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_BLOCKS_16)
            ALOGD(" 16");

        ALOGD(" Subbands supported: ");
        if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_SUBBAND_4)
            ALOGD(" 8");
        if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_SUBBAND_8)
            ALOGD(" 4");

        ALOGD(" Allocation Method Supported");
        if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_ALLOC_MD_S)
            ALOGD(" SNR");
        if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_ALLOC_MD_L)
            ALOGD(" Loudness");

        ALOGD(" Minimum bit pool: %d", cfg_info->p_cfg->codec_info[5]);
        ALOGD(" Maximum bit pool: %d", cfg_info->p_cfg->codec_info[6]);

        ALOGD("}");
        }
        else
        {
            ALOGI("Error - %x: %s", cfg_info->hdr.err_code, dump_av_error_name(cfg_info->hdr.err_code));
        }
        /*
        for(i = 0; i < AVDT_CODEC_SIZE; i++)
        {
           ALOGI("Codec info [%d] = %d", i,sep_peer_cfg.codec_info[i]);
        }
        ALOGI("No of codecs = %d", sep_peer_cfg.num_codec);*/
        }
        break;

        case AVDT_CONFIG_IND_EVT:
        {
        tAVDT_CONFIG *cfg_ind;
        int i;

        cfg_ind = (tAVDT_CONFIG *) p_data;
        ALOGI("seid = %x, errcode = %x, error param = %x, label = %x", cfg_ind->hdr.seid ,cfg_ind->hdr.err_code, cfg_ind->hdr.err_param, cfg_ind->hdr.label );
        ALOGI("ccb_idx = %x, sig_id = %x", cfg_ind->hdr.ccb_idx, cfg_ind->hdr.sig_id);

/*        if(AVDT_GetReject(bt_av_handle))
        {
            AVDT_ConfigRsp(bt_av_handle, cfg_ind->hdr.label , AVDT_ERR_INVALID_MCT, 0);
            break;;
        }
*/
        if(!cfg_ind->hdr.err_code)
        {
            for(i = 0; i < AVDT_CODEC_SIZE; i++)
            {
               ALOGI("Codec info [%d] = %d", i,cfg_ind->p_cfg->codec_info[i]);
            }
            ALOGI("No of codecs = %d", cfg_ind->p_cfg->num_codec);
        }
        else
        {
            ALOGI("Error - %x: %s", cfg_ind->hdr.err_code, dump_av_error_name(cfg_ind->hdr.err_code));
        }

        AVDT_ConfigRsp(bt_av_handle, cfg_ind->hdr.label , 0, 0);
        }
        break;

        case AVDT_OPEN_CFM_EVT:
        {
        tAVDT_OPEN *open_ind;

        open_ind = (tAVDT_OPEN *) p_data;

        ALOGI("seid = %x, errcode = %x, error param = %x, label = %x", open_ind->hdr.seid ,open_ind->hdr.err_code, open_ind->hdr.err_param, open_ind->hdr.label );
        ALOGI("ccb_idx = %x, sig_id = %x", open_ind->hdr.ccb_idx,open_ind->hdr.sig_id);
        ALOGI("peer_mtu = %x, lcid = %x", open_ind->peer_mtu, open_ind->lcid);

        if(open_ind->hdr.err_code)
           {
            ALOGI("Error - %x: %s", open_ind->hdr.err_code, dump_av_error_name(open_ind->hdr.err_code));
           }
        }
        break;

        case AVDT_START_IND_EVT:
        {
            BT_HDR      *p_buf = NULL;
            UINT8       *p, *pp;
            static UINT32 time_stamp = 0;
            UINT8 m_pt = 0x60 | A2D_MEDIA_CT_SBC;

            if ((p_buf = (BT_HDR *)GKI_getbuf((UINT16)(sizeof(BT_HDR) + AV_MEDIA_PKT + AVDT_MEDIA_OFFSET))) != NULL)
            {
                p = (UINT8 *)(p_buf + 1) + AVDT_MEDIA_OFFSET;
                memcpy(p , av_media_pkt, sizeof(av_media_pkt));
                p_buf->offset = AVDT_MEDIA_OFFSET;
                p_buf->len = (UINT16)(sizeof(BT_HDR) + AV_MEDIA_PKT + AVDT_MEDIA_OFFSET);
                p_buf->event = event;
//              p_buf->layer_specific = ;
                time_stamp++;
                AVDT_WriteReq(bt_av_handle, p_buf, time_stamp, m_pt);
            }
            else
            {
               ALOGE("GKI_getbuf failed!");
            }
        }
        break;

        case AVDT_START_CFM_EVT:
        {
        tAVDT_EVT_HDR *start_cfm;
        start_cfm = (tAVDT_EVT_HDR *) p_data;

        ALOGI("seid = %x, errcode = %x, error param = %x, label = %x", start_cfm->seid ,start_cfm->err_code, start_cfm->err_param, start_cfm->label );
        ALOGI("ccb_idx = %x, sig_id = %x", start_cfm->ccb_idx,start_cfm->sig_id);

        if(!start_cfm->err_code)
        {
            BT_HDR      *p_buf = NULL;
            UINT8       *p, *pp;
            static UINT32 time_stamp = 0;
            UINT8 m_pt = 0x60 | A2D_MEDIA_CT_SBC;

            if ((p_buf = (BT_HDR *)GKI_getbuf((UINT16)(sizeof(BT_HDR) + AV_MEDIA_PKT + AVDT_MEDIA_OFFSET))) != NULL)
            {
                p = (UINT8 *)(p_buf + 1) + AVDT_MEDIA_OFFSET;
                memcpy(p , av_media_pkt, sizeof(av_media_pkt));
                p_buf->offset = AVDT_MEDIA_OFFSET;
                p_buf->len = (UINT16)(sizeof(BT_HDR) + AV_MEDIA_PKT + AVDT_MEDIA_OFFSET);
                p_buf->event = event;
//              p_buf->layer_specific = ;
                time_stamp++;
                AVDT_WriteReq(bt_av_handle, p_buf, time_stamp, m_pt);
            }
        }
        else
        {
           ALOGI("Write failed!!!! Error - %x: %s", start_cfm->err_code, dump_av_error_name(start_cfm->err_code));
        }

        }
        break;

        case AVDT_WRITE_CFM_EVT:
        {
        tAVDT_EVT_HDR *write_cfm;

        write_cfm = (tAVDT_EVT_HDR *) p_data;
        ALOGI("seid = %x, errcode = %x, error param = %x, label = %x", write_cfm->seid ,write_cfm->err_code, write_cfm->err_param, write_cfm->label );
        ALOGI("ccb_idx = %x, sig_id = %x", write_cfm->ccb_idx,write_cfm->sig_id);

//        sleep(1);

        if(!write_cfm->err_code)
        {
            BT_HDR      *p_buf = NULL;
            UINT8       *p, *pp;
            static UINT32 time_stamp = 0;
            UINT8 m_pt = 0x60 | A2D_MEDIA_CT_SBC;

            if ((p_buf = (BT_HDR *)GKI_getbuf((UINT16)(sizeof(BT_HDR) + AV_MEDIA_PKT + AVDT_MEDIA_OFFSET))) != NULL)
            {
                p = (UINT8 *)(p_buf + 1) + AVDT_MEDIA_OFFSET;
                memcpy(p , av_media_pkt, sizeof(av_media_pkt));
                p_buf->offset = AVDT_MEDIA_OFFSET;
                p_buf->len = (UINT16)(sizeof(BT_HDR) + AV_MEDIA_PKT + AVDT_MEDIA_OFFSET);
                p_buf->event = event;
        //              p_buf->layer_specific = ;
                time_stamp++;
                AVDT_WriteReq(bt_av_handle, p_buf, time_stamp, m_pt);
            }
        }
        else
        {
            ALOGI("Write failed!!!! Error - %x: %s", write_cfm->err_code, dump_av_error_name(write_cfm->err_code));
        }
        }
        break;

        case AVDT_SUSPEND_CFM_EVT:
        {
            tAVDT_EVT_HDR *suspend_cfm;

            suspend_cfm = (tAVDT_EVT_HDR *) p_data;

            ALOGI("seid = %x, errcode = %x, error param = %x, label = %x", suspend_cfm->seid ,suspend_cfm->err_code, suspend_cfm->err_param, suspend_cfm->label );
            ALOGI("ccb_idx = %x, sig_id = %x", suspend_cfm->ccb_idx,suspend_cfm->sig_id);

            if(suspend_cfm->err_code)
            {
                ALOGI("Error - %x: %s", suspend_cfm->err_code, dump_av_error_name(suspend_cfm->err_code));
            }
        }
        break;

        case AVDT_CLOSE_CFM_EVT:
        {
            tAVDT_EVT_HDR *close_cfm;

            close_cfm = (tAVDT_EVT_HDR *) p_data;

            ALOGI("seid = %x, errcode = %x, error param = %x, label = %x", close_cfm->seid ,close_cfm->err_code, close_cfm->err_param, close_cfm->label );
            ALOGI("ccb_idx = %x, sig_id = %x", close_cfm->ccb_idx,close_cfm->sig_id);

            if(close_cfm->err_code)
            {
                ALOGI("Error - %x: %s", close_cfm->err_code, dump_av_error_name(close_cfm->err_code));
            }
        }
        break;

        case AVDT_RECONFIG_IND_EVT:
        {
            tAVDT_CONFIG *recfg_cfm;
            int i;
            tA2D_SBC_CIE recfg_cie;
            tA2D_STATUS status;

            recfg_cfm = (tAVDT_CONFIG *)p_data;

            ALOGI("seid = %x, errcode = %x, error param = %x, label = %x", recfg_cfm->hdr.seid ,recfg_cfm->hdr.err_code, recfg_cfm->hdr.err_param, recfg_cfm->hdr.label );
            ALOGI("ccb_idx = %x, sig_id = %x", recfg_cfm->hdr.ccb_idx, recfg_cfm->hdr.sig_id);

            if((status = A2D_ParsSbcInfo(&recfg_cie, &recfg_cfm->p_cfg->codec_info[0], FALSE)) == A2D_SUCCESS)
            {
                if(!recfg_cfm->hdr.err_code)
                {
                    for(i = 0; i < AVDT_CODEC_SIZE; i++)
                    {
                       ALOGI("Codec info [%d] = %d", i,recfg_cfm->p_cfg->codec_info[i]);
                    }
                    ALOGI("No of codecs = %d", recfg_cfm->p_cfg->num_codec);
                }
                else
                {
                    ALOGI("Error - %x: %s", recfg_cfm->hdr.err_code, dump_av_error_name(recfg_cfm->hdr.err_code));
                }
            }
            else
            {
                recfg_cfm->hdr.err_code = AVDT_ERR_INVALID_CAP;
            }

            AVDT_ReconfigRsp(bt_av_handle, recfg_cfm->hdr.label, recfg_cfm->hdr.err_code, 0);
        }
        break;
        case AVDT_RECONFIG_CFM_EVT:
        {
            tAVDT_CONFIG *recfg_cfm;
            int i;
            UINT8 err_code = 0;

            recfg_cfm = (tAVDT_CONFIG *)p_data;

            ALOGI("seid = %x, errcode = %x, error param = %x, label = %x", recfg_cfm->hdr.seid ,recfg_cfm->hdr.err_code, recfg_cfm->hdr.err_param, recfg_cfm->hdr.label );
            ALOGI("ccb_idx = %x, sig_id = %x", recfg_cfm->hdr.ccb_idx, recfg_cfm->hdr.sig_id);


/*               if(AVDT_GetReject(bt_av_handle))
                err_code = AVDT_ERR_INVALID_MCT;
               else
                err_code = 0;
*/

            if(!recfg_cfm->hdr.err_code)
            {
                for(i = 0; i < AVDT_CODEC_SIZE; i++)
                {
                   ALOGI("Codec info [%d] = %d", i,recfg_cfm->p_cfg->codec_info[i]);
                }
                ALOGI("No of codecs = %d", recfg_cfm->p_cfg->num_codec);
            }
            else
            {
                ALOGI("Error - %x: %s", recfg_cfm->hdr.err_code, dump_av_error_name(recfg_cfm->hdr.err_code));
            }

        }
        break;

        case AVDT_SECURITY_CFM_EVT:
        case AVDT_SECURITY_IND_EVT:
        {
           tAVDT_SECURITY *sec_cfm;
           int i;
           UINT8 err_code;

           sec_cfm = (tAVDT_SECURITY *) p_data;

           ALOGI("seid = %x, errcode = %x, error param = %x, label = %x", sec_cfm->hdr.seid ,sec_cfm->hdr.err_code, sec_cfm->hdr.err_param, sec_cfm->hdr.label );
           ALOGI("ccb_idx = %x, sig_id = %x, len = %x", sec_cfm->hdr.ccb_idx, sec_cfm->hdr.sig_id, sec_cfm->len);

           if(event == AVDT_SECURITY_IND_EVT)
           {
/*              if(AVDT_GetReject(bt_av_handle))
                err_code = AVDT_ERR_INVALID_MCT;
              else
                err_code = 0;
*/
              AVDT_SecurityRsp(bt_av_handle, sec_cfm->hdr.label, err_code, NULL, 0);
              break;;
           }

           if(!sec_cfm->hdr.err_code)
           {
               for(i = 0; i < sec_cfm->len; i++)
               {
                  ALOGI("Sec control data [%d] = %d", i, sec_cfm->p_data[i]);
               }
           }
           else
           {
               ALOGI("Error - %x: %s", sec_cfm->hdr.err_code, dump_av_error_name(sec_cfm->hdr.err_code));
           }
        }
        break;

    }

}

static void AVDTPTest_init ( void )
{
    tAVDT_REG p_reg;
    tAVDT_CS cs;
    int i;

    BTIF_TRACE_EVENT1("%s", __FUNCTION__);

    p_reg.ctrl_mtu = AV_MAX_A2DP_MTU;
    p_reg.idle_tout = AV_IDLE_TOUT;
    p_reg.ret_tout = AV_RET_TOUT;
    p_reg.sec_mask = AV_SEC_IN_AUTHENTICATE | AV_SEC_OUT_AUTHENTICATE;
    p_reg.sig_tout = AV_SIG_TOUT;

    AVDT_Register(&p_reg, av_event_cb);


    cs.cfg.psc_mask  = sep_cfg.psc_mask = AVDT_PSC_TRANS;
    cs.media_type    = AVDT_MEDIA_AUDIO;
    cs.mtu           = AV_MAX_A2DP_MTU;
    cs.flush_to      = L2CAP_DEFAULT_FLUSH_TO;
    cs.p_ctrl_cback  = av_event_cb;
    cs.cfg.num_codec = sep_cfg.num_codec= 1;
    cs.cfg.num_protect = sep_cfg.num_protect = 0;
    cs.tsep          = AVDT_TSEP_SRC;
    cs.nsc_mask      = 0;
    cs.p_data_cback  = av_data_cb;

    A2D_BldSbcInfo(AVDT_MEDIA_AUDIO, (tA2D_SBC_CIE *) &av_co_sbc_caps, &cs.cfg.codec_info[0]);
    memcpy(&sep_cfg.codec_info[0], &cs.cfg.codec_info[0], AVDT_CODEC_SIZE);

    for(i = 0; i < AVDT_CODEC_SIZE; i++)
    {
       ALOGI("Codec info [%d] = %d", i , cs.cfg.codec_info[i]);
    }

    AVDT_CreateStream(&bt_av_handle, &cs);

}

static void AVDTPTest_set_remote_addr ( BD_ADDR  *p_bd_addr )
{
    memcpy(&rbd_addr, p_bd_addr, sizeof(BD_ADDR));
}
    static void AVDTPTest_send_control_msg ( UINT8 type )
    {
       if((type >= 90) && (type < 100))
       {
         AVDT_set_reject(type - 90);
         return;
        }
       switch(type)
       {
        case 255:
        {
                BT_HDR      *p_buf = NULL;
                UINT8       *p, *pp;
                static UINT32 time_stamp = 0;
                UINT8 m_pt = 0x60 | A2D_MEDIA_CT_SBC;

                if ((p_buf = (BT_HDR *)GKI_getbuf((UINT16)(sizeof(BT_HDR) + AV_MEDIA_PKT + AVDT_MEDIA_OFFSET))) != NULL)
                {
                    p = (UINT8 *)(p_buf + 1) + AVDT_MEDIA_OFFSET;
                    memcpy(p , av_media_pkt, sizeof(av_media_pkt));
                    p_buf->offset = AVDT_MEDIA_OFFSET;
                    p_buf->len = (UINT16)(sizeof(BT_HDR) + AV_MEDIA_PKT + AVDT_MEDIA_OFFSET);
                    p_buf->event = 0;
    //              p_buf->layer_specific = ;
                    time_stamp++;
                    AVDT_WriteReq(bt_av_handle, p_buf, time_stamp, m_pt);
                }
        }
        break;

        case AVDT_SIG_DISCOVER:
        {
            AVDT_DiscoverReq(rbd_addr, sep_info, AV_NUM_SEPS, av_event_cb);
        }
        break;

        case AVDT_SIG_GETCAP:
        {
            UINT8 i;

            for ( i = 0; i < dseps_count; i++ )
            {
                if((sep_info[i].media_type == AVDT_MEDIA_AUDIO) &&
                    (sep_info[i].tsep == AVDT_TSEP_SNK)
                        && (sep_info[i].in_use == FALSE))
                {
                    AVDT_GetCapReq(rbd_addr, sep_info[i].seid, &sep_peer_cfg[i], av_event_cb);
                }
            }
        }
        break;

        case AVDT_SIG_OPEN:
        case AVDT_SIG_SETCONFIG:
        {
            int i;
            UINT8 max_bp, max_bp_peer, min_bp, min_bp_peer, max_bp_cfg, min_bp_cfg;

            A2D_BldSbcInfo(AVDT_MEDIA_AUDIO, (tA2D_SBC_CIE *) &av_sbc_default_config, &sep_cfg.codec_info[0]);

            max_bp = sep_cfg.codec_info[A2D_SBC_INFO_LEN];
            min_bp = sep_cfg.codec_info[A2D_SBC_INFO_LEN - 1];

            max_bp_peer = sep_peer_cfg[0].codec_info[A2D_SBC_INFO_LEN];
            min_bp_peer = sep_peer_cfg[0].codec_info[A2D_SBC_INFO_LEN - 1];

            if(max_bp > max_bp_peer)
            {
                max_bp_cfg = max_bp_peer;
                sep_cfg.codec_info[A2D_SBC_INFO_LEN] = max_bp_cfg;
            }

            if(min_bp < min_bp_peer)
            {
                min_bp_cfg = min_bp_peer;
                sep_cfg.codec_info[A2D_SBC_INFO_LEN - 1] = min_bp_cfg;
            }

            for(i = 0; i < AVDT_CODEC_SIZE; i++)
            {
               ALOGI("Codec info [%d] = %d", i , sep_cfg.codec_info[i]);
            }

            AVDT_OpenReq(bt_av_handle, rbd_addr, sep_info[0].seid, &sep_cfg);
        }
        break;

        case AVDT_SIG_GETCONFIG:
        {
        AVDT_GetConfigReq(bt_av_handle);
        }
        break;

        case AVDT_SIG_RECONFIG:
        {
            tAVDT_CFG recfg;
            UINT16 status;
            recfg.psc_mask = AVDT_PSC_TRANS;
            recfg.num_codec = 1;
            recfg.num_protect = 0;
            status = A2D_BldSbcInfo(AVDT_MEDIA_AUDIO, (tA2D_SBC_CIE *) &av_sbc_reconfig, &recfg.codec_info[0]);
            ALOGD("Reconfig bldsbc Status == %d", status);
            status = AVDT_ReconfigReq(bt_av_handle, &recfg);
            ALOGD("Reconfig Status == %d", status);
        }
        break;

        case AVDT_SIG_START:
        {
        AVDT_StartReq(&bt_av_handle, 1);
        }
        break;

        case AVDT_SIG_CLOSE:
        {
        AVDT_CloseReq(bt_av_handle);
        }
        break;

        case AVDT_SIG_SUSPEND:
        {
        AVDT_SuspendReq(&bt_av_handle, 1);
        }
        break;

        case AVDT_SIG_ABORT:
        {
        AVDT_AbortReq(bt_av_handle);
        }
        break;
       }
    }


static const avdtp_test_interface_t avdtp_test_interface = {
    sizeof(avdtp_test_interface_t),
    AVDTPTest_init,
    AVDTPTest_send_control_msg,
    AVDTPTest_set_remote_addr,
};

const avdtp_test_interface_t *btif_get_avdtp_test_interface(void)
{
    ALOGI("%s", __FUNCTION__);
    return &avdtp_test_interface;
}
