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
 *  Filename:      btif_test_avdtp_verifier.c
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

#include "btif_test.h"
#include "btif_test_testcase.h"

#define AV_MAX_A2DP_MTU             1008
#define AV_RET_TOUT                 4
#define AV_SIG_TOUT                 10
#define AV_IDLE_TOUT                10
#define AV_SEC_NONE                 0
#define AV_SEC_IN_AUTHENTICATE      0x0002
#define AV_SEC_OUT_AUTHENTICATE     0x0010

#define AVDTV_SIG_DISCOVER          1
#define AVDTV_SIG_GETCAP            2
#define AVDTV_SIG_SETCONFIG         3
#define AVDTV_SIG_GETCONFIG         4
#define AVDTV_SIG_RECONFIG          5
#define AVDTV_SIG_OPEN              6
#define AVDTV_SIG_START             7
#define AVDTV_SIG_CLOSE             8
#define AVDTV_SIG_SUSPEND           9
#define AVDTV_SIG_ABORT             10
#define AVDTV_SIG_INVALID_DISCOVER  11
#define AVDTV_SIG_INVALID_GETCAP    12
#define AVDTV_SIG_INVALID_GETCONFIG 14
#define AVDTV_SIG_INVALID_RECONFIG  15
#define AVDTV_SIG_INVALID_SETCONFIG 16


static UINT8 bt_av_handle;
static UINT8 send_disconnect = 0;

static BD_ADDR rbd_addr;

/* Discover */
#define AV_NUM_SEPS                 32

static tAVDT_SEP_INFO               sep_info[AV_NUM_SEPS];
static UINT8                        dseps_count;

/* Get Cap */
static tAVDT_CFG                    sep_peer_cfg[AV_NUM_SEPS];

static tAVDT_CFG                    sep_cfg;

const tA2D_SBC_CIE av_co_sbc_caps =
{
    (A2D_SBC_IE_SAMP_FREQ_44),                                                                           /* samp_freq */
    (A2D_SBC_IE_CH_MD_MONO | A2D_SBC_IE_CH_MD_STEREO | A2D_SBC_IE_CH_MD_JOINT | A2D_SBC_IE_CH_MD_DUAL),  /* ch_mode */
    (A2D_SBC_IE_BLOCKS_16 | A2D_SBC_IE_BLOCKS_12 | A2D_SBC_IE_BLOCKS_8 | A2D_SBC_IE_BLOCKS_4),          /* block_len */
    (A2D_SBC_IE_SUBBAND_4 | A2D_SBC_IE_SUBBAND_8),                                                     /* num_subbands */
    (A2D_SBC_IE_ALLOC_MD_L | A2D_SBC_IE_ALLOC_MD_S),                                                  /* alloc_mthd */
    A2D_SBC_IE_MAX_BITPOOL,                                                                          /* max_bitpool */
    A2D_SBC_IE_MIN_BITPOOL                                                                          /* min_bitpool */
};

/* Default SBC codec configuration */
const tA2D_SBC_CIE av_sbc_default_config =
{
    A2D_SBC_IE_SAMP_FREQ_44,        /* samp_freq */
    A2D_SBC_IE_CH_MD_JOINT,         /* ch_mode */
    A2D_SBC_IE_BLOCKS_16,           /* block_len */
    A2D_SBC_IE_SUBBAND_8,           /* num_subbands */
    A2D_SBC_IE_ALLOC_MD_L,          /* alloc_mthd */
    A2D_SBC_IE_MAX_BITPOOL,        /* max_bitpool */
    A2D_SBC_IE_MIN_BITPOOL         /* min_bitpool */
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


void (*pf_av_cb) ( UINT8 );
static void av_event_cb( UINT8 handle, BD_ADDR bd_addr, UINT8 event, tAVDT_CTRL *p_data );

/******************************************************************************

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
       CASE_RETURN_STR(AVDT_DISCOVER_IND_EVT)
       CASE_RETURN_STR(AVDT_GETCAP_IND_EVT)
       CASE_RETURN_STR(AVDT_GETCFG_IND_EVT)
       CASE_RETURN_STR(AVDT_ABORT_IND_EVT)
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
    static int timer = 1000;

    BTIF_TRACE_EVENT1("%s", __FUNCTION__);

    GKI_freebuf(p_pkt);
    timer --;

    ALOGD("Received Media packet with time stamp: %x", (unsigned int)time_stamp);

    if(timer == 0)
    {
       timer = 2000;
    }

    return;
}

static void av_event_cb( UINT8 handle, BD_ADDR bd_addr, UINT8 event, tAVDT_CTRL *p_data )
{
    int i;
    BTIF_TRACE_EVENT1("%s", dump_av_event_name(event));

    switch(event)
    {
        case AVDT_DISCONNECT_IND_EVT:
        {
            tAVDT_EVT_HDR *disc_ind;
            UINT8 tc_v;

            disc_ind = (tAVDT_EVT_HDR *) p_data;

            if(send_disconnect)
                send_disconnect = 0;

            ALOGD("Received Disconnect Indication");

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
        break;

        case AVDT_CONNECT_IND_EVT:
        {
           tAVDT_EVT_HDR *con_ind;

            con_ind = (tAVDT_EVT_HDR *) p_data;

            ALOGI("Received Connect Indication");

            if(!con_ind->err_code)
            {
                TC_Callback(TC_EVENT_CONN_CFM);
                ALOGI("AVDTP Connection Success");
            }
            else
            {
                TC_Callback(TC_EVENT_CONN_FAILED);
                ALOGE("AVDTP Connection Rejected");
            }
        }
        break;

        case AVDT_DISCOVER_IND_EVT:
        {
            tAVDT_DISCOVER *disc_info;
            int i;

            ALOGI("Received Discover Indication Event");
            ALOGD("{");

            disc_info = (tAVDT_DISCOVER *)p_data;

            if(TC_GetEvt() != AVDT_DISCOVER_IND_EVT)
            {
                ALOGE("Wrong AVDTP Command");
                TC_Update(TC_VERDICT_FAIL);
                break;
            }

            if(disc_info->hdr.err_code)
            {
                ALOGE("Error - %x: %s", disc_info->hdr.err_code, dump_av_error_name(disc_info->hdr.err_code));
                if(TC_GetTcNum() == 21)
                {
                    AVDT_set_reject(0);
                    TC_Update(TC_VERDICT_PASS);
                }
                else
                    TC_Update(TC_VERDICT_FAIL);
            }
            else
            {
                for(i = 0; i < disc_info->num_seps; i++)
                {
                    ALOGD("\tSEID: %d", disc_info->p_sep_info->seid);

                    if(disc_info->p_sep_info->in_use)
                        ALOGD("\t\tIn Use: Yes");
                    else
                        ALOGD("\t\tIn Use: No");

                    ALOGD("\t\tMedia Type : %s", av_get_media_type(disc_info->p_sep_info->media_type));

                    if(disc_info->p_sep_info->tsep)
                        ALOGD("\t\tSEP Type : SNK");
                    else
                        ALOGD("\t\tSEP Type : SRC");
                }

                TC_Update(TC_VERDICT_PASS);
            }
            ALOGD("}");
        }
        break;

        case AVDT_DISCOVER_CFM_EVT:
        {
            tAVDT_DISCOVER *disc_info;
            int i;

            ALOGD("Received Discover Confirmation");
            ALOGD("{");

            disc_info = (tAVDT_DISCOVER *)p_data;

            if(TC_GetEvt() != AVDT_DISCOVER_CFM_EVT)
            {
                TC_Update(TC_VERDICT_FAIL);
                ALOGE("Wrong AVDTP Command");
                break;
            }

            if(disc_info->hdr.err_code)
            {
                ALOGE("Error - %x: %s", disc_info->hdr.err_code, dump_av_error_name(disc_info->hdr.err_code));
                if(TC_GetTcNum() == 23)
                    TC_Update(TC_VERDICT_PASS);
                else
                    TC_Update(TC_VERDICT_FAIL);
            }
            else
            {
                dseps_count = disc_info->num_seps;
                for(i = 0; i < dseps_count; i++)
                {
                    sep_info[i].seid = disc_info->p_sep_info->seid;
                    sep_info[i].in_use = disc_info->p_sep_info->in_use;
                    sep_info[i].media_type = disc_info->p_sep_info->media_type;
                    sep_info[i].tsep = disc_info->p_sep_info->tsep;

                    ALOGD("\tSEID: %d", sep_info[i].seid);

                    if(sep_info[i].in_use)
                        ALOGD("\t\tIn Use: Yes");
                    else
                        ALOGD("\t\tIn Use: No");

                    ALOGD("\t\tMedia Type: %s", av_get_media_type(sep_info[i].media_type));

                    if(sep_info[i].tsep)
                        ALOGD("\t\tSEP Type: SNK");
                    else
                        ALOGD("\t\tSEP Type: SRC");
                }

                ALOGD("}");

                if(TC_GetTcNum() == 23)
                    TC_Update(TC_VERDICT_FAIL);
                else
                    TC_Update(TC_VERDICT_PASS);
            }
        }
        break;

        case AVDT_GETCAP_IND_EVT:
        case AVDT_GETCAP_CFM_EVT:
        {
            tAVDT_CONFIG *cfg_info;
            int i;

            cfg_info = (tAVDT_CONFIG *) p_data;
            if(event == AVDT_GETCAP_IND_EVT)
            {
                ALOGD("Received Get Capabilities Indication");
                if(TC_GetEvt() != AVDT_GETCAP_IND_EVT)
                {
                    TC_Update(TC_VERDICT_FAIL);
                    ALOGE("Wrong AVDTP Command");
                    break;
                }
                ALOGD("Capabilities sent:");
            }
            else
            {
                ALOGD("Received Get Capabilities Confirmation");
                if(TC_GetEvt() != AVDT_GETCAP_CFM_EVT)
                {
                    TC_Update(TC_VERDICT_FAIL);
                    ALOGE("Wrong AVDTP Command");
                    break;
                }
            }

            ALOGD("{");
            if(cfg_info->hdr.err_code)
            {
                ALOGE("Error - %x: %s", cfg_info->hdr.err_code, dump_av_error_name(cfg_info->hdr.err_code));
                if(TC_GetTcNum() == 26)
                {
                    TC_Update(TC_VERDICT_PASS);
                }
                else if(TC_GetTcNum() == 24)
                {
                    AVDT_set_reject(0);
                    TC_Update(TC_VERDICT_PASS);
                }
                else
                {
                    TC_Update(TC_VERDICT_FAIL);
                }
            }
            else
            {
                ALOGD("\tLength Of Service Capability (LOSC): %d", cfg_info->p_cfg->codec_info[0]);
                ALOGD("\tMedia Type: %s", av_get_media_type(cfg_info->p_cfg->codec_info[1]));
                ALOGD("\tMedia Codec Type: %s", av_get_media_codec_type(cfg_info->p_cfg->codec_info[2]));
                ALOGD("\tCodec Info Element: ");

                ALOGD("\t\tSampling Frequency supported");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_SAMP_FREQ_16)
                    ALOGD("\t\t\t16 kHz");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_SAMP_FREQ_32)
                    ALOGD("\t\t\t32 kHz");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_SAMP_FREQ_44)
                    ALOGD("\t\t\t44 kHz");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_SAMP_FREQ_48)
                    ALOGD("\t\t\t48 kHz");

                ALOGD("\t\tChannel Mode supported");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_CH_MD_MONO)
                    ALOGD("\t\t\tMono");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_CH_MD_DUAL)
                    ALOGD("\t\t\tDual");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_CH_MD_STEREO)
                    ALOGD("\t\t\tStereo");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_CH_MD_JOINT)
                    ALOGD("\t\t\tJoint Stereo");

                ALOGD("\t\tBlock Length supported");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_BLOCKS_4)
                    ALOGD("\t\t\t4");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_BLOCKS_8)
                    ALOGD("\t\t\t8");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_BLOCKS_12)
                    ALOGD("\t\t\t12");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_BLOCKS_16)
                    ALOGD("\t\t\t16");

                ALOGD("\t\tSubbands supported: ");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_SUBBAND_4)
                    ALOGD("\t\t\t8");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_SUBBAND_8)
                    ALOGD("\t\t\t4");

                ALOGD("\t\tAllocation Method Supported");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_ALLOC_MD_S)
                    ALOGD("\t\t\tSNR");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_ALLOC_MD_L)
                    ALOGD("\t\t\tLoudness");

                ALOGD("\tMinimum bit pool: %d", cfg_info->p_cfg->codec_info[5]);
                ALOGD("\tMaximum bit pool: %d", cfg_info->p_cfg->codec_info[6]);

                ALOGD("}");

                if(TC_GetTcNum() == 26)
                    TC_Update(TC_VERDICT_FAIL);
                else
                    TC_Update(TC_VERDICT_PASS);
            }
        }
        break;

        case AVDT_CONFIG_IND_EVT:
        {
            tAVDT_SETCONFIG *cfg_ind;
            cfg_ind = (tAVDT_SETCONFIG *) p_data;

            ALOGI("Received Config Indication");

            if(TC_GetEvt() != AVDT_CONFIG_IND_EVT)
            {
                TC_Update(TC_VERDICT_FAIL);
                ALOGE("Wrong AVDTP Command");
                break;
            }

            if( (TC_GetTcNum() == 27) && (cfg_ind->hdr.err_code == AVDT_ERR_INVALID_FORMAT))
            {
                AVDT_set_reject(0);
                ALOGI("Reject with error code 0xE1 successfully sent");
                TC_Update(TC_VERDICT_PASS);
            }
            else
            {
                TC_Update(TC_VERDICT_PASS);
                AVDT_ConfigRsp(bt_av_handle, cfg_ind->hdr.label, 0, 0);
            }
        }
        break;

        case AVDT_OPEN_IND_EVT:
        case AVDT_OPEN_CFM_EVT:
        {
            tAVDT_OPEN *open_ind;
            open_ind = (tAVDT_OPEN *) p_data;

            if(event == AVDT_OPEN_IND_EVT)
            {
                ALOGI("Received Open Indication");
                if(TC_GetEvt() != AVDT_OPEN_IND_EVT)
                {
                    TC_Update(TC_VERDICT_FAIL);
                    ALOGE("Wrong AVDTP Command");
                    break;
                }
            }
            else
            {
                ALOGI("Received Open Confirmation");
                if(TC_GetEvt() != AVDT_OPEN_CFM_EVT)
                {
                    TC_Update(TC_VERDICT_FAIL);
                    ALOGE("Wrong AVDTP Command");
                    break;
                }
            }

            if(open_ind->hdr.err_code)
            {
                ALOGE("Error - %x: %s", open_ind->hdr.err_code, dump_av_error_name(open_ind->hdr.err_code));
                if(TC_GetTcNum() == 29)
                    TC_Update(TC_VERDICT_PASS);
                else if(TC_GetTcNum() == 38)
                    TC_Update(TC_VERDICT_PASS);
                else if(TC_GetTcNum() == 36 && open_ind->hdr.err_code == AVDT_ERR_INVALID_FORMAT)
                {
                    AVDT_set_reject(0);
                    ALOGI("Reject with error code 0xE1 successfully sent");
                    TC_Update(TC_VERDICT_PASS);
                }
                else
                {
                    TC_Update(TC_VERDICT_FAIL);
                }
            }
            else
            {
                if(TC_GetTcNum() == 29)
                    TC_Update(TC_VERDICT_FAIL);
                else if(TC_GetTcNum() == 38)
                    TC_Update(TC_VERDICT_FAIL);
                else if(TC_GetTcNum()== 27)
                    TC_Update(TC_VERDICT_PASS);
                else
                    TC_Update(TC_VERDICT_PASS);
            }
        }
        break;

        case AVDT_START_IND_EVT:
        {
            tAVDT_EVT_HDR *start_ind;
            start_ind = (tAVDT_EVT_HDR *) p_data;

            ALOGI("Received Start Indication");
            if(TC_GetEvt() != AVDT_START_IND_EVT)
            {
                TC_Update(TC_VERDICT_FAIL);
                ALOGE("Wrong AVDTP Command");
                break;
            }
            if((TC_GetTcNum() == 39) && (start_ind->err_code == AVDT_ERR_INVALID_FORMAT))
            {
                AVDT_set_reject(START_REJECT);
                ALOGI("Reject with error code 0xE1 successfully sent");
                TC_Update(TC_VERDICT_PASS);
            }
            else
            {
                TC_Update(TC_VERDICT_PASS);
            }
        }
        break;

        case AVDT_START_CFM_EVT:
        {
            tAVDT_EVT_HDR *start_cfm;
            start_cfm = (tAVDT_EVT_HDR *) p_data;

            ALOGI("Received Start Confirmation");
            if(TC_GetEvt() != AVDT_START_CFM_EVT)
            {
                TC_Update(TC_VERDICT_FAIL);
                ALOGE("Wrong AVDTP Command");
                break;
            }

            if(start_cfm->err_code)
            {
                ALOGE("Error - %x: %s", start_cfm->err_code, dump_av_error_name(start_cfm->err_code));
                if(TC_GetTcNum() == 41)
                    TC_Update(TC_VERDICT_PASS);
                else
                    TC_Update(TC_VERDICT_FAIL);
            }
            else
            {
                if(TC_GetTcNum() == 41)
                    TC_Update(TC_VERDICT_FAIL);
                else
                    TC_Update(TC_VERDICT_PASS);
            }
        }
        break;

        case AVDT_GETCFG_IND_EVT:
        case AVDT_GETCFG_CFM_EVT:
        {
            tAVDT_CONFIG *cfg_info;
            cfg_info = (tAVDT_CONFIG *) p_data;

            if(event == AVDT_GETCFG_IND_EVT)
            {
                ALOGI("Received Get Configuration Indication");
                if(TC_GetEvt() != AVDT_GETCFG_IND_EVT)
                {
                    TC_Update(TC_VERDICT_FAIL);
                    ALOGE("Wrong AVDTP Command");
                    break;
                }
            }
            else
            {
                ALOGI("Received Get Configuration Confirmation");
                if(TC_GetEvt() != AVDT_GETCFG_CFM_EVT)
                {
                    TC_Update(TC_VERDICT_FAIL);
                    ALOGE("Wrong AVDTP Command");
                    break;
                }
            }

            if(cfg_info->hdr.err_code)
            {
                ALOGE("Error - %x: %s", cfg_info->hdr.err_code, dump_av_error_name(cfg_info->hdr.err_code));
                if(TC_GetTcNum() == 32)
                    TC_Update(TC_VERDICT_PASS);
                else if((TC_GetTcNum() == 31) && (cfg_info->hdr.err_code == AVDT_ERR_SEID))
                    TC_Update(TC_VERDICT_PASS);
                else if((TC_GetTcNum() == 30) && (cfg_info->hdr.err_code == AVDT_ERR_INVALID_FORMAT))
                {
                    AVDT_set_reject(0);
                    ALOGI("Reject with error code 0xE1 successfully sent");
                    TC_Update(TC_VERDICT_PASS);
                }
                else
                    TC_Update(TC_VERDICT_FAIL);
            }
            else
            {
                ALOGD("{");
                ALOGD("\tLength Of Service Capability (LOSC): %d", cfg_info->p_cfg->codec_info[0]);
                ALOGD("\tMedia Type: %s", av_get_media_type(cfg_info->p_cfg->codec_info[1]));
                ALOGD("\tMedia Codec Type: %s", av_get_media_codec_type(cfg_info->p_cfg->codec_info[2]));
                ALOGD("\tCodec Info Element: ");

                ALOGD("\t\tSampling Frequency supported: ");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_SAMP_FREQ_16)
                    ALOGD("\t\t\t16 kHz");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_SAMP_FREQ_32)
                    ALOGD("\t\t\t32 kHz");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_SAMP_FREQ_44)
                    ALOGD("\t\t\t44 kHz");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_SAMP_FREQ_48)
                    ALOGD("\t\t\t48 kHz");

                ALOGD("\t\tChannel Mode supported: ");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_CH_MD_MONO)
                    ALOGD("\t\t\tMono");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_CH_MD_DUAL)
                    ALOGD("\t\t\tDual");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_CH_MD_STEREO)
                    ALOGD("\t\t\tStereo");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_CH_MD_JOINT)
                    ALOGD("\t\t\tJoint Stereo");

                ALOGD("\t\tBlock Length supported: ");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_BLOCKS_4)
                    ALOGD("\t\t\t4");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_BLOCKS_8)
                    ALOGD("\t\t\t8");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_BLOCKS_12)
                    ALOGD("\t\t\t12");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_BLOCKS_16)
                    ALOGD("\t\t\t16");

                ALOGD("\t\tSubbands supported: ");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_SUBBAND_4)
                    ALOGD("\t\t\t8");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_SUBBAND_8)
                    ALOGD("\t\t\t4");

                ALOGD("\t\tAllocation Method Supported");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_ALLOC_MD_S)
                    ALOGD("\t\t\tSNR");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_ALLOC_MD_L)
                    ALOGD("\t\t\tLoudness");

                ALOGD("\tMinimum bit pool: %d", cfg_info->p_cfg->codec_info[5]);
                ALOGD("\tMaximum bit pool: %d", cfg_info->p_cfg->codec_info[6]);

                ALOGD("}");

                if(TC_GetTcNum() == 32)
                    TC_Update(TC_VERDICT_FAIL);
                else
                    TC_Update(TC_VERDICT_PASS);
            }
        }
        break;

        case AVDT_RECONFIG_CFM_EVT:
        {
            tAVDT_CONFIG *cfg_info;
            cfg_info = (tAVDT_CONFIG *) p_data;

            ALOGI("Received ReConfiguration Confirmation");

            if(TC_GetEvt() != AVDT_RECONFIG_CFM_EVT)
            {
                TC_Update(TC_VERDICT_FAIL);
                ALOGE("Wrong AVDTP Command");
                break;
            }

            if(cfg_info->hdr.err_code)
            {
                ALOGE("Error - %x: %s", cfg_info->hdr.err_code, dump_av_error_name(cfg_info->hdr.err_code));
                if(TC_GetTcNum() == 35)
                    TC_Update(TC_VERDICT_PASS);
                else if((TC_GetTcNum() == 34) && (cfg_info->hdr.err_code == AVDT_ERR_CATEGORY))
                {
                    AVDT_set_invalid(0);
                    TC_Update(TC_VERDICT_PASS);
                }
                else if((TC_GetTcNum() == 48) && (cfg_info->hdr.err_code == AVDT_ERR_SEID))
                {
                    TC_Update(TC_VERDICT_PASS);
                }
                else if((TC_GetTcNum() == 49) && (cfg_info->hdr.err_code == AVDT_ERR_INVALID_CAP))
                {
                    TC_Update(TC_VERDICT_PASS);
                }
                else
                    TC_Update(TC_VERDICT_FAIL);
            }
            else
            {
                if(TC_GetTcNum() == 35)
                    TC_Update(TC_VERDICT_FAIL);
                else
                    TC_Update(TC_VERDICT_PASS);
            }
        }
        break;

        case AVDT_RECONFIG_IND_EVT:
        {
            tAVDT_CONFIG *cfg_info;
            cfg_info = (tAVDT_CONFIG *) p_data;

            ALOGI("Received Reconfiguration Indication");

            if(TC_GetEvt() != AVDT_RECONFIG_IND_EVT)
            {
                TC_Update(TC_VERDICT_FAIL);
                ALOGE("Wrong AVDTP Command");
                break;
            }

            if(cfg_info->hdr.err_code)
            {
                ALOGE("Error - %x: %s", cfg_info->hdr.err_code, dump_av_error_name(cfg_info->hdr.err_code));
                if( (TC_GetTcNum() == 33 ) && (cfg_info->hdr.err_code == AVDT_ERR_INVALID_FORMAT))
                {
                    AVDT_set_reject(RECONFIG_REJECT);
                    ALOGI("Reject with error code 0xE1 successfully sent");
                    TC_Update(TC_VERDICT_PASS);
                }
                else
                    TC_Update(TC_VERDICT_FAIL);
            }
            else
            {
                ALOGD("{");
                ALOGD("\tLength Of Service Capability (LOSC): %d", cfg_info->p_cfg->codec_info[0]);
                ALOGD("\tMedia Type: %s", av_get_media_type(cfg_info->p_cfg->codec_info[1]));
                ALOGD("\tMedia Codec Type: %s", av_get_media_codec_type(cfg_info->p_cfg->codec_info[2]));
                ALOGD("\tCodec Info Element: ");

                ALOGD("\t\tSampling Frequency supported");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_SAMP_FREQ_16)
                    ALOGD("\t\t\t16 kHz");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_SAMP_FREQ_32)
                    ALOGD("\t\t\t32 kHz");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_SAMP_FREQ_44)
                    ALOGD("\t\t\t44 kHz");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_SAMP_FREQ_48)
                    ALOGD("\t\t\t48 kHz");

                ALOGD("\t\tChannel Mode supported");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_CH_MD_MONO)
                    ALOGD("\t\t\tMono");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_CH_MD_DUAL)
                    ALOGD("\t\t\tDual");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_CH_MD_STEREO)
                    ALOGD("\t\t\tStereo");
                if(cfg_info->p_cfg->codec_info[3] & A2D_SBC_IE_CH_MD_JOINT)
                    ALOGD("\t\t\tJoint Stereo");

                ALOGD("\t\tBlock Length supported");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_BLOCKS_4)
                    ALOGD(" 4");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_BLOCKS_8)
                    ALOGD(" 8");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_BLOCKS_12)
                    ALOGD(" 12");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_BLOCKS_16)
                    ALOGD(" 16");

                ALOGD("\t\tSubbands Supported");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_SUBBAND_4)
                    ALOGD("\t\t\t8");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_SUBBAND_8)
                    ALOGD("\t\t\t4");

                ALOGD("\t\tAllocation Method Supported");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_ALLOC_MD_S)
                    ALOGD("\t\t\tSNR");
                if(cfg_info->p_cfg->codec_info[4] & A2D_SBC_IE_ALLOC_MD_L)
                    ALOGD("\t\t\tLoudness");

                ALOGD("\tMinimum bit pool: %d", cfg_info->p_cfg->codec_info[5]);
                ALOGD("\tMaximum bit pool: %d", cfg_info->p_cfg->codec_info[6]);
                ALOGD("}");

                TC_Update(TC_VERDICT_PASS);
            }
        }
        break;

        case AVDT_CLOSE_IND_EVT:
        case AVDT_CLOSE_CFM_EVT:
        {
            tAVDT_EVT_HDR *close_cfm;

            close_cfm = (tAVDT_EVT_HDR *) p_data;

            if(send_disconnect)
                break;

            if(event == AVDT_CLOSE_IND_EVT)
            {
                ALOGI("Received Close Indication");
                if(TC_GetEvt() != AVDT_CLOSE_IND_EVT)
                {
                    TC_Update(TC_VERDICT_FAIL);
                    ALOGE("Wrong AVDTP Command");
                    break;
                }
            }
            else
            {
                ALOGI("Received Close Confirmation");
                if(TC_GetEvt() != AVDT_CLOSE_CFM_EVT)
                {
                    TC_Update(TC_VERDICT_FAIL);
                    ALOGE("Wrong AVDTP Command");
                    break;
                }
            }

            if(close_cfm->err_code)
            {
                ALOGE("Error - %x: %s", close_cfm->err_code, dump_av_error_name(close_cfm->err_code));
                if(TC_GetTcNum() == 44)
                    TC_Update(TC_VERDICT_PASS);
                else if(TC_GetTcNum() == 42)
                {
                    AVDT_set_reject(CLOSE_REJECT);
                    ALOGI("Reject with error code 0xE1 successfully sent");
                    TC_Update(TC_VERDICT_PASS);
                }
                else
                    TC_Update(TC_VERDICT_FAIL);
            }
            else
            {
                if(TC_GetTcNum() == 44)
                    TC_Update(TC_VERDICT_FAIL);
                else
                    TC_Update(TC_VERDICT_PASS);
            }
        }
        break;

        case AVDT_SUSPEND_IND_EVT:
        case AVDT_SUSPEND_CFM_EVT:
        {
            tAVDT_EVT_HDR *suspend_cfm;

            suspend_cfm = (tAVDT_EVT_HDR *) p_data;

            if(event == AVDT_SUSPEND_IND_EVT)
            {
                ALOGI("Received Suspend Indication");
                if(TC_GetEvt() != AVDT_SUSPEND_IND_EVT)
                {
                    TC_Update(TC_VERDICT_FAIL);
                    ALOGE("Wrong AVDTP Command");
                    break;
                }
            }
            else
            {
                ALOGI("Received Suspend Confirmation");
                if(TC_GetEvt() != AVDT_SUSPEND_CFM_EVT)
                {
                    TC_Update(TC_VERDICT_FAIL);
                    ALOGE("Wrong AVDTP Command");
                    break;
                }
            }

            if(event != AVDT_SUSPEND_IND_EVT)
            {
                if(suspend_cfm->err_code)
                {
                    ALOGE("Error - %x: %s", suspend_cfm->err_code, dump_av_error_name(suspend_cfm->err_code));
                    if(TC_GetTcNum() == 47)
                        TC_Update(TC_VERDICT_PASS);
                    else if(TC_GetTcNum() == 45)
                    {
                        AVDT_set_reject(SUSPEND_REJECT);
                        ALOGI("Reject with error code 0xE1 successfully sent");
                        TC_Update(TC_VERDICT_PASS);
                    }
                    else
                        TC_Update(TC_VERDICT_FAIL);
                }
            }
            else
            {
                if(TC_GetTcNum() == 47)
                    TC_Update(TC_VERDICT_FAIL);
                else
                    TC_Update(TC_VERDICT_PASS);
            }
        }
        break;

        case AVDT_ABORT_IND_EVT:
        case AVDT_ABORT_CFM_EVT:
        {
            tAVDT_EVT_HDR *abort_cfm;

            abort_cfm = (tAVDT_EVT_HDR *) p_data;

            if(event == AVDT_ABORT_IND_EVT)
            {
                ALOGD("Received Abort Indication");
                if(TC_GetEvt() != AVDT_ABORT_IND_EVT)
                {
                    TC_Update(TC_VERDICT_FAIL);
                    ALOGE("Wrong AVDTP Command");
                    break;
                }
            }
            else
            {
                ALOGI("Received Abort Confirmation");
                if(TC_GetEvt() != AVDT_ABORT_CFM_EVT)
                {
                    TC_Update(TC_VERDICT_FAIL);
                    ALOGE("Wrong AVDTP Command");
                    break;
                }
            }

            if(abort_cfm->err_code)
            {
                ALOGE("Error - %x: %s", abort_cfm->err_code, dump_av_error_name(abort_cfm->err_code));
                TC_Update(TC_VERDICT_FAIL);
            }
            else
            {
                TC_Update(TC_VERDICT_PASS);
            }
        }
        break;

        default:
        break;
    }
}
/******************************************************************************

******************************************************************************/

static UINT8 AVDTV_get_cmd ( void )
{
    return TC_GetCmd();
}


static void AVDTV_init ( void *p )
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

    TC_Init(p);

    cs.cfg.psc_mask  = sep_cfg.psc_mask = AVDT_PSC_TRANS;
    cs.media_type    = AVDT_MEDIA_AUDIO;
    cs.mtu           = AV_MAX_A2DP_MTU;
    cs.flush_to      = L2CAP_DEFAULT_FLUSH_TO;
    cs.p_ctrl_cback  = av_event_cb;
    cs.cfg.num_codec = sep_cfg.num_codec= 1;
    cs.cfg.num_protect = sep_cfg.num_protect = 0;
    cs.tsep          = AVDT_TSEP_SNK;
    cs.nsc_mask      = 0;
    cs.p_data_cback  = av_data_cb;

    A2D_BldSbcInfo(AVDT_MEDIA_AUDIO, (tA2D_SBC_CIE *) &av_co_sbc_caps, &cs.cfg.codec_info[0]);
    memcpy(&sep_cfg.codec_info[0], &cs.cfg.codec_info[0], AVDT_CODEC_SIZE);

/*  for(i = 0; i < AVDT_CODEC_SIZE; i++)
    {
       ALOGI("Codec info [%d] = %d", i , cs.cfg.codec_info[i]);
    }
 */
    AVDT_CreateStream(&bt_av_handle, &cs);
}

static void AVDTV_set_invalid_mode( int val )
{
    AVDT_set_invalid(val);
}

static void AVDTV_set_remote_addr ( BD_ADDR  *p_bd_addr )
{
    memcpy(&rbd_addr, p_bd_addr, sizeof(BD_ADDR));
}

static void AVDTV_select_test_case ( UINT8 tc, UINT8 *p_str )
{
    // ALOGI("%s : Test Case = %d", __FUNCTION__, tc);

    ALOGI("================================================================");
    ALOGI("============ Executing : %s =================", (char *)p_str);

    TC_Select(tc);

    switch(tc)
    {
        case 1: //TP/SIG/SMG/BV-05-C
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_DISCOVER_IND_EVT);
            ALOGI("Verify the reception of a valid stream discover indication");
        break;

        case 2: //TP/SIG/SMG/BV-06-C
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            ALOGI("Verify the reception of a valid stream discover response");
        break;

        case 3://TP/SIG/SMG/BV-07-C
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_DISCOVER_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_GETCAP_IND_EVT);
            ALOGI("Verify the reception of a get capabilities indication");
        break;

        case 4://TP/SIG/SMG/BV-08-C
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCAP, AVDT_GETCAP_CFM_EVT);
            ALOGI("Verify the reception of a valid get capabilities response");
        break;

        case 5://TP/SIG/SMG/BV-09-C
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_DISCOVER_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_GETCAP_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_CONFIG_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_OPEN_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_CLOSE_IND_EVT);
            ALOGI("Verify the reception of a valid get capabilities indication");
        break;

        case 6://TP/SIG/SMG/BV-10-C
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCAP, AVDT_GETCAP_CFM_EVT);
            TC_Register(AVDTV_SIG_SETCONFIG, AVDT_OPEN_CFM_EVT);
            ALOGI("Verify the reception of a valid set configuration response");
        break;

        case 7://TP/SIG/SMG/BV-11-C
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_DISCOVER_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_GETCAP_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_CONFIG_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_OPEN_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_GETCFG_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_CLOSE_IND_EVT);
            ALOGI("Verify the reception of a valid get configuration indication");
        break;

        case 8://TP/SIG/SMG/BV-12-C
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCAP, AVDT_GETCAP_CFM_EVT);
            TC_Register(AVDTV_SIG_SETCONFIG, AVDT_OPEN_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCONFIG, AVDT_GETCFG_CFM_EVT);
            ALOGI("Verify the reception of a valid get configuration response");
        break;

        case 9://TP/SIG/SMG/BV-13-C
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_DISCOVER_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_GETCAP_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_CONFIG_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_OPEN_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_START_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_SUSPEND_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_RECONFIG_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_CLOSE_IND_EVT);
            ALOGI("Verify the reception of a valid reconfiguration indication");
        break;

        case 10://TP/SIG/SMG/BV-14-C
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCAP, AVDT_GETCAP_CFM_EVT);
            TC_Register(AVDTV_SIG_OPEN, AVDT_OPEN_CFM_EVT);
            TC_Register(AVDTV_SIG_START, AVDT_START_CFM_EVT);
            TC_Register(AVDTV_SIG_SUSPEND, AVDT_SUSPEND_CFM_EVT);
            TC_Register(AVDTV_SIG_RECONFIG, AVDT_RECONFIG_CFM_EVT);
            ALOGI("Verify the reception of a valid reconfiguration response");
        break;

        case 11://TP/SIG/SMG/BV-15-C
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_DISCOVER_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_GETCAP_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_CONFIG_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_OPEN_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_CLOSE_IND_EVT);
            ALOGI("Verify the reception of a valid open indication");
        break;

        case 12://TP/SIG/SMG/BV-16-C
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCAP, AVDT_GETCAP_CFM_EVT);
            TC_Register(AVDTV_SIG_OPEN, AVDT_OPEN_CFM_EVT);
            ALOGI("Verify the reception of a valid open response");
        break;

        case 13://TP/SIG/SMG/BV-17-C
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_DISCOVER_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_GETCAP_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_CONFIG_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_OPEN_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_START_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_CLOSE_IND_EVT);
            ALOGI("Verify the reception of a valid start indication");
        break;

        case 14://TP/SIG/SMG/BV-18-C
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCAP, AVDT_GETCAP_CFM_EVT);
            TC_Register(AVDTV_SIG_OPEN, AVDT_OPEN_CFM_EVT);
            TC_Register(AVDTV_SIG_START, AVDT_START_CFM_EVT);
            ALOGI("Verify the reception of a valid start response");
        break;

        case 15://TP/SIG/SMG/BV-19-C
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_DISCOVER_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_GETCAP_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_CONFIG_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_OPEN_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_START_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_CLOSE_IND_EVT);
            ALOGI("Verify the reception of a valid close indication");
        break;

        case 16://TP/SIG/SMG/BV-20-C
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCAP, AVDT_GETCAP_CFM_EVT);
            TC_Register(AVDTV_SIG_OPEN, AVDT_OPEN_CFM_EVT);
            TC_Register(AVDTV_SIG_CLOSE, AVDT_CLOSE_CFM_EVT);
            ALOGI("Verify the reception of a valid close response");
        break;

        case 17://TP/SIG/SMG/BV-21-C
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_DISCOVER_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_GETCAP_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_CONFIG_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_OPEN_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_START_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_SUSPEND_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_CLOSE_IND_EVT);   // to avoid wrong command being printed when disconnect is sent from verifier
            ALOGI("Verify the reception of a valid suspend indication");
        break;

        case 18://TP/SIG/SMG/BV-22-C
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCAP, AVDT_GETCAP_CFM_EVT);
            TC_Register(AVDTV_SIG_OPEN, AVDT_OPEN_CFM_EVT);
            TC_Register(AVDTV_SIG_START, AVDT_START_CFM_EVT);
            TC_Register(AVDTV_SIG_SUSPEND, AVDT_SUSPEND_CFM_EVT);
            ALOGI("Verify the reception of a valid suspend response");
        break;

        case 19://TP/SIG/SMG/BV-23-C
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_DISCOVER_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_GETCAP_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_CONFIG_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_OPEN_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_START_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_ABORT_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_CLOSE_IND_EVT);   // to avoid wrong command being printed when disconnect is sent from verifier
            ALOGI("Verify the reception of a valid abort indication");
        break;

        case 20://TP/SIG/SMG/BV-24-C
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCAP, AVDT_GETCAP_CFM_EVT);
            TC_Register(AVDTV_SIG_OPEN, AVDT_OPEN_CFM_EVT);
            TC_Register(AVDTV_SIG_ABORT, AVDT_ABORT_CFM_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_CLOSE_CFM_EVT);
            ALOGI("Verify the reception of a valid abort response");
        break;

        case 21://TP/SIG/SMG/BI-01-C
            AVDT_set_reject(DISC_REJECT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_DISCOVER_IND_EVT);
        break;

        case 22://TP/SIG/SMG/BI-02-C
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
        break;

        case 23: //TP/SIG/SMG/BI-03-C
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
        break;

        case 24://TP/SIG/SMG/BI-04-C
            AVDT_set_reject(GETCAP_REJECT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_DISCOVER_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_GETCAP_IND_EVT);
        break;

        case 25://TP/SIG/SMG/BI-05-C
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_INVALID_GETCAP, AVDT_GETCAP_CFM_EVT);
        break;

        case 26: //TP/SIG/SMG/BI-06-C
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCAP, AVDT_GETCAP_CFM_EVT);
        break;

        case 27: //TP/SIG/SMG/BI-07-C
            AVDT_set_reject(SETCONFIG_REJECT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_DISCOVER_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_GETCAP_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_OPEN_IND_EVT);
        break;

        case 28: //TP/SIG/SMG/BI-08-C
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCAP, AVDT_GETCAP_CFM_EVT);
            TC_Register(AVDTV_SIG_SETCONFIG, AVDT_OPEN_CFM_EVT);
            TC_Register(AVDTV_SIG_SETCONFIG, AVDT_OPEN_CFM_EVT);
        break;

        case 29: //TP/SIG/SMG/BI-09-C
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCAP, AVDT_GETCAP_CFM_EVT);
            TC_Register(AVDTV_SIG_SETCONFIG, AVDT_OPEN_CFM_EVT);
        break;

        case 30: //TP/SIG/SMG/BI-10-C
            AVDT_set_reject(GETCONFIG_REJECT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_DISCOVER_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_GETCAP_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_OPEN_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_GETCFG_IND_EVT);
        break;

        case 31: //TP/SIG/SMG/BI-11-C
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCAP, AVDT_GETCAP_CFM_EVT);
            TC_Register(AVDTV_SIG_SETCONFIG, AVDT_OPEN_CFM_EVT);
            TC_Register(AVDTV_SIG_INVALID_GETCONFIG, AVDT_GETCFG_CFM_EVT);
            TC_Register(AVDTV_SIG_CLOSE, AVDT_CLOSE_CFM_EVT);
        break;

        case 32: //TP/SIG/SMG/BI-12-C
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCAP, AVDT_GETCAP_CFM_EVT);
            TC_Register(AVDTV_SIG_SETCONFIG, AVDT_OPEN_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCONFIG, AVDT_GETCFG_CFM_EVT);
            TC_Register(AVDTV_SIG_CLOSE, AVDT_CLOSE_CFM_EVT);
        break;

        case 33:
            AVDT_set_reject(RECONFIG_REJECT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_DISCOVER_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_GETCAP_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_OPEN_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_START_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_RECONFIG_IND_EVT);
        break;

        case 34: //TP/SIG/SMG/BI-14-C case 1 - invalid service catergory
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCAP, AVDT_GETCAP_CFM_EVT);
            TC_Register(AVDTV_SIG_SETCONFIG, AVDT_OPEN_CFM_EVT);
            TC_Register(AVDTV_SIG_START, AVDT_START_CFM_EVT);
            TC_Register(AVDTV_SIG_SUSPEND, AVDT_SUSPEND_CFM_EVT);
            TC_Register(AVDTV_SIG_INVALID_RECONFIG, AVDT_RECONFIG_CFM_EVT);
            TC_Register(AVDTV_SIG_CLOSE, AVDT_CLOSE_CFM_EVT);
        break;

        case 48: //TP/SIG/SMG/BI-14-C case 2 - invalid SEID
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCAP, AVDT_GETCAP_CFM_EVT);
            TC_Register(AVDTV_SIG_SETCONFIG, AVDT_OPEN_CFM_EVT);
            TC_Register(AVDTV_SIG_START, AVDT_START_CFM_EVT);
            TC_Register(AVDTV_SIG_SUSPEND, AVDT_SUSPEND_CFM_EVT);
            TC_Register(AVDTV_SIG_INVALID_RECONFIG, AVDT_RECONFIG_CFM_EVT);
            TC_Register(AVDTV_SIG_CLOSE, AVDT_CLOSE_CFM_EVT);
        break;

        case 49: //TP/SIG/SMG/BI-14-C case 3 - invalid capabilities
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCAP, AVDT_GETCAP_CFM_EVT);
            TC_Register(AVDTV_SIG_SETCONFIG, AVDT_OPEN_CFM_EVT);
            TC_Register(AVDTV_SIG_START, AVDT_START_CFM_EVT);
            TC_Register(AVDTV_SIG_SUSPEND, AVDT_SUSPEND_CFM_EVT);
            TC_Register(AVDTV_SIG_INVALID_RECONFIG, AVDT_RECONFIG_CFM_EVT);
            TC_Register(AVDTV_SIG_CLOSE, AVDT_CLOSE_CFM_EVT);
        break;

        case 35: //TP/SIG/SMG/BI-15-C - a
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCAP, AVDT_GETCAP_CFM_EVT);
            TC_Register(AVDTV_SIG_SETCONFIG, AVDT_OPEN_CFM_EVT);
            TC_Register(AVDTV_SIG_START, AVDT_START_CFM_EVT);
            TC_Register(AVDTV_SIG_SUSPEND, AVDT_SUSPEND_CFM_EVT);
            TC_Register(AVDTV_SIG_RECONFIG, AVDT_RECONFIG_CFM_EVT);
            TC_Register(AVDTV_SIG_CLOSE, AVDT_CLOSE_CFM_EVT);
        break;


        case 36: //TP/SIG/SMG/BI-16-C
            AVDT_set_reject(OPEN_REJECT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_DISCOVER_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_GETCAP_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_OPEN_IND_EVT);
        break;


        case 38: //TP/SIG/SMG/BI-18-C
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCAP, AVDT_GETCAP_CFM_EVT);
            TC_Register(AVDTV_SIG_OPEN, AVDT_OPEN_CFM_EVT);
        break;

        case 39: //TP/SIG/SMG/BI-19-C
            AVDT_set_reject(START_REJECT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_DISCOVER_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_GETCAP_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_OPEN_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_START_IND_EVT);
        break;

        case 41: //TP/SIG/SMG/BI-21-C
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCAP, AVDT_GETCAP_CFM_EVT);
            TC_Register(AVDTV_SIG_SETCONFIG, AVDT_OPEN_CFM_EVT);
            TC_Register(AVDTV_SIG_START, AVDT_START_CFM_EVT);
            TC_Register(AVDTV_SIG_CLOSE, AVDT_CLOSE_CFM_EVT);
        break;

        case 42://TP/SIG/SMG/BI-22-C
            AVDT_set_reject(CLOSE_REJECT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_DISCOVER_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_GETCAP_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_OPEN_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_START_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_CLOSE_IND_EVT);
        break;

        case 44: //TP/SIG/SMG/BI-24-C
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCAP, AVDT_GETCAP_CFM_EVT);
            TC_Register(AVDTV_SIG_SETCONFIG, AVDT_OPEN_CFM_EVT);
            TC_Register(AVDTV_SIG_START, AVDT_START_CFM_EVT);
            TC_Register(AVDTV_SIG_CLOSE, AVDT_CLOSE_CFM_EVT);
        break;

        case 45://TP/SIG/SMG/BI-25-C
            AVDT_set_reject(SUSPEND_REJECT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_DISCOVER_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_GETCAP_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_OPEN_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_START_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_SUSPEND_IND_EVT);
            TC_Register(TC_CMD_EXEC_WAIT, AVDT_CLOSE_IND_EVT);
        break;


        case 47: //TP/SIG/SMG/BI-27-C
            TC_Register(AVDTV_SIG_DISCOVER, AVDT_DISCOVER_CFM_EVT);
            TC_Register(AVDTV_SIG_GETCAP, AVDT_GETCAP_CFM_EVT);
            TC_Register(AVDTV_SIG_SETCONFIG, AVDT_OPEN_CFM_EVT);
            TC_Register(AVDTV_SIG_START, AVDT_START_CFM_EVT);
            TC_Register(AVDTV_SIG_SUSPEND, AVDT_SUSPEND_CFM_EVT);
            TC_Register(AVDTV_SIG_CLOSE, AVDT_CLOSE_CFM_EVT);
        break;
    }

    ALOGI("================================================================");
    ALOGI("Initialised Test Case");
    ALOGI("Verifier will initiate an AVDTP Connection to Tester");
}


static void AVDTV_connect ( void )
{
    AVDT_ConnectReq ( rbd_addr, AV_SEC_NONE, av_event_cb );
}

static void AVDTV_disconnect ( void )
{
    send_disconnect = 1;
    AVDT_DisconnectReq ( rbd_addr, av_event_cb );
}

static void AVDTV_send_control_msg ( UINT8 which )
{
    switch(which)
    {
        case AVDTV_SIG_INVALID_GETCAP:
        {
            if(TC_GetTcNum() == 25)
            {
                AVDT_GetCapReq(rbd_addr, 0, &sep_peer_cfg[0], av_event_cb);
            }
        }
        break;

        case AVDTV_SIG_DISCOVER:
        {
            AVDT_DiscoverReq(rbd_addr, sep_info, AV_NUM_SEPS, av_event_cb);
        }
        break;

        case AVDTV_SIG_GETCAP:
        {
            UINT8 i;

            for ( i = 0; i < dseps_count; i++ )
            {
                if((sep_info[i].media_type == AVDT_MEDIA_AUDIO) &&
                    (sep_info[i].tsep == AVDT_TSEP_SRC) &&
                    (sep_info[i].in_use == FALSE))
                {
                    AVDT_GetCapReq(rbd_addr, sep_info[i].seid, &sep_peer_cfg[i], av_event_cb);
                }
            }
        }
        break;

        case AVDTV_SIG_OPEN:
        case AVDTV_SIG_SETCONFIG:
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

            AVDT_OpenReq(bt_av_handle, rbd_addr, sep_info[0].seid, &sep_cfg);
        }
        break;

        case AVDTV_SIG_GETCONFIG:
        {
            AVDT_GetConfigReq(bt_av_handle);
        }
        break;

        case AVDTV_SIG_INVALID_GETCONFIG:
        {
            AVDT_config_scb(bt_av_handle, 1, 0);
            AVDT_GetConfigReq(bt_av_handle);
            AVDT_config_scb(bt_av_handle, 0, 0);
        }
        break;

        case AVDTV_SIG_INVALID_RECONFIG:
        {
            tAVDT_CFG recfg;

            recfg.psc_mask = AVDT_PSC_TRANS;
            recfg.num_codec = 1;
            recfg.num_protect = 0;

            A2D_BldSbcInfo(AVDT_MEDIA_AUDIO, (tA2D_SBC_CIE *) &av_sbc_reconfig, &recfg.codec_info[0]);
            if(TC_GetTcNum() == 34)
            {
                AVDT_set_invalid(RECONFIG_INVALID);
                AVDT_ReconfigReq(bt_av_handle, &recfg);
            }
            else if(TC_GetTcNum() == 48)
            {
                AVDT_config_scb(bt_av_handle, 1, 0);
                AVDT_ReconfigReq(bt_av_handle, &recfg);
                AVDT_config_scb(bt_av_handle, 0, 0);
            }
            else if(TC_GetTcNum() == 49)
            {
/*              memset(&recfg.codec_info[0], 0xFF, AVDT_CODEC_SIZE);
                recfg.codec_info[0] = A2D_SBC_INFO_LEN;
                recfg.codec_info[1] = media_type;
                recfg.codec_info[2] = A2D_MEDIA_CT_SBC;
*/
                recfg.codec_info[3] = 0;

                AVDT_ReconfigReq(bt_av_handle, &recfg);
            }
        }
        break;

        case AVDTV_SIG_RECONFIG:
        {
            tAVDT_CFG recfg;

            recfg.psc_mask = AVDT_PSC_TRANS;
            recfg.num_codec = 1;
            recfg.num_protect = 0;

            A2D_BldSbcInfo(AVDT_MEDIA_AUDIO, (tA2D_SBC_CIE *) &av_sbc_reconfig, &recfg.codec_info[0]);

            AVDT_ReconfigReq(bt_av_handle, &recfg);
        }
        break;

        case AVDTV_SIG_START:
        {
            AVDT_StartReq(&bt_av_handle, 1);
        }
        break;

        case AVDTV_SIG_CLOSE:
        {
            AVDT_CloseReq(bt_av_handle);
        }
        break;

        case AVDTV_SIG_SUSPEND:
        {
            AVDT_SuspendReq(&bt_av_handle, 1);
        }
        break;

        case AVDTV_SIG_ABORT:
        {
            AVDT_AbortReq(bt_av_handle);
        }
        break;
    }
}

static const avdtp_verifier_interface_t avdtp_verifier_interface = {
    sizeof(avdtp_verifier_interface_t),
    AVDTV_init,
    AVDTV_set_remote_addr,
    AVDTV_set_invalid_mode,
    AVDTV_select_test_case,
    AVDTV_get_cmd,
    AVDTV_connect,
    AVDTV_send_control_msg,
    AVDTV_disconnect,
};

const avdtp_verifier_interface_t *btif_get_avdtp_verifier_interface(void)
{
    ALOGI("%s", __FUNCTION__);
    return &avdtp_verifier_interface;
}
