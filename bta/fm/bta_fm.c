/******************************************************************************
 *  Copyright (C) 2012-2013 Intel Mobile Communications GmbH
 *
 *  This software is licensed under the terms of the GNU General Public
 *  License version 2, as published by the Free Software Foundation, and
 *  may be copied, distributed, and modified under those terms.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 ***************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>

#include "bt_target.h"
#include "gki.h"
#include "hcidefs.h"
#include "hcimsgs.h"
#include "hcidefs.h"
#include "btu.h"
#include "bd.h"
#include "bta_sys.h"
#include "bta_api.h"
#include "bta_dm_int.h"
#include "bta_sys_int.h"
#include "btm_api.h"
#include "btm_int.h"
#include "bt_types.h"

#include <stddef.h>
#include <string.h>
#include <utils/Log.h>
#include "bta_fm.h"
#include <iui_fm.h>
#include <packer_unpacker.h>

#ifdef BT_FM_MITIGATION

extern void bta_dm_btfm_set_afh_channels(UINT8 ch_mask[]);

static  IuiFmMitigationStatus    bt_iui_fm_mitigation_cb(const IuiFmMacroId macro_id, const IuiFmMitigation *mitigation, const IuiFmMitigationSequence sequence);

/*Structure that has member to receive value from FM*/
typedef struct BtFmMitigation{
    IuiFmMacroId MacroId;
    UINT32 Seq;
    IuiFmMitigation  * FmMit;
}   BtFmMitigation;


/*******************************************************************************
**              GLOBAL VARIABLES
********************************************************************************/

UINT8 ch_mask[12] = {0};

/*******************************************************************************
**             STATIC VARIABLES
********************************************************************************/

static BtFmMitigation btfmmitigation;

static IuiFmBtChannelMask *btfm_mask;

static IuiFmFreqNotification FmNotification_on;
static IuiFmFreqNotification * const notification_on=&FmNotification_on;
static IuiFmBtInfo *binfo_on=NULL;

static IuiFmFreqNotification FmNotification_off;
static IuiFmFreqNotification * const notification_off=&FmNotification_off;
static IuiFmBtInfo *binfo_off=NULL;

/********************************************************************************************************
**             FUNCTIONS
**
**********************************************************************************************************/


/*********************************************************************************************************
**
** Function    bta_fm_init
**
** Description    register bluetooth with FM, This method is get called when Bluetooth core is enabled
**	and it call to IuiFmNotifyFrequency to notify FM with Bluetooth status turn ON and	subsquently call
**  to IuiFmRegisterMitigationCallback to register metigation callback.
**
** Returns    void
**
**************************************************************************************************************/

void  bta_fm_init()
{
    APPL_TRACE_DEBUG1("%s : ", __FUNCTION__);
    if(binfo_on==NULL)
    {    binfo_on = (IuiFmBtInfo *) malloc(sizeof(IuiFmBtInfo));
        if(!binfo_on)
        {
            APPL_TRACE_ERROR0("binfo_on is NULL: ");
            return;
        }
    }
    binfo_on->bt_state=IUI_FM_BT_STATE_ON;
    FmNotification_on.info.bt_info = binfo_on;
    FmNotification_on.type=IUI_FM_FREQ_NOTIFICATION_TYPE_BT;
    UTA_REMOTE_CALL(IuiFmNotifyFrequency)(IUI_FM_MACRO_ID_BT,  notification_on );
    UTA_REMOTE_CALL(IuiFmRegisterMitigationCallback)( IUI_FM_MACRO_ID_BT, bt_iui_fm_mitigation_cb );
    free(binfo_on);
    binfo_on=NULL;
}

/****************************************************************************************************************
**
** Function    bta_fm_deinit
**
** Description    unregister bluetooth from FM. This method is get called when Bluetooth core is disabling
** and it call to IuiFmNotifyFrequency to notify FM with Bluetooth status turn OFF and subsquently call to
** IuiFmRegisterMitigationCallback to de-register metigation callback.To de-register metigation callback,
** we pass NULL.
**
** Returns    void
**
******************************************************************************************************************/

void bta_fm_deinit()
{
    APPL_TRACE_DEBUG1("%s : ", __FUNCTION__);
    if(binfo_off==NULL)
    {
    binfo_off = (IuiFmBtInfo *) malloc(sizeof(IuiFmBtInfo));
        if(!binfo_off)
        {
            APPL_TRACE_ERROR0("binfo_off is NULL: ");
            return;
        }
    }
    binfo_off->bt_state=IUI_FM_BT_STATE_OFF;
    FmNotification_off.info.bt_info = binfo_off;
    FmNotification_off.type=IUI_FM_FREQ_NOTIFICATION_TYPE_BT;
    UTA_REMOTE_CALL(IuiFmNotifyFrequency)(IUI_FM_MACRO_ID_BT,  notification_off );
    UTA_REMOTE_CALL(IuiFmRegisterMitigationCallback)( IUI_FM_MACRO_ID_BT, NULL );
    free(binfo_off);
    binfo_off=NULL;
}

/*****************************************************************************************************
**
** Function    IuiFmMitigationCb
**
** Description    FM callback :  function pointer implementation to set afh channels. FM will call
** pointer of bt_iui_fm_mitigation_cb method, when FM will observe some interference in channels.
** FM will send mitigation frequency to Bluetooth to avoid the channel interference.
**
** Returns    IuiFmMitigationStatus
**
*******************************************************************************************************/

IuiFmMitigationStatus  bt_iui_fm_mitigation_cb(const IuiFmMacroId macro_id, const IuiFmMitigation *mitigation, const IuiFmMitigationSequence sequence)
{
    int i;
    btfmmitigation.MacroId = macro_id;
    btfmmitigation.Seq = sequence;
    UINT8  *p=ch_mask;
    APPL_TRACE_DEBUG1("%s : ", __FUNCTION__);
    btfmmitigation.FmMit = (IuiFmMitigation  *) malloc(sizeof(IuiFmMitigation));
    if(!btfmmitigation.FmMit)
    {
        APPL_TRACE_ERROR0("btfmmitigation.FmMit = NULL");
        return IUI_FM_MITIGATION_ERROR;
    }
    btfmmitigation.FmMit->type=mitigation->type;
    btfm_mask = (IuiFmBtChannelMask *) malloc(sizeof(UINT32)*IUI_FM_BT_CHANNEL_MASK_WORDS);
    if(!btfm_mask)
    {
        APPL_TRACE_ERROR0("btfm_mask = NULL");
        return IUI_FM_MITIGATION_ERROR;
    }
    btfmmitigation.FmMit->info.bt_ch_mask = btfm_mask;
    for(i=0;i<IUI_FM_BT_CHANNEL_MASK_WORDS;i++)
    {
        btfmmitigation.FmMit->info.bt_ch_mask->bt_ch_mask[i]=mitigation->info.bt_ch_mask->bt_ch_mask[i];
    }

    if(btfmmitigation.MacroId == IUI_FM_MACRO_ID_BT)
    {
        if(btfmmitigation.FmMit->type == IUI_FM_MITIGATION_TYPE_BT)
        {
            UINT32_TO_STREAM(p,btfmmitigation.FmMit->info.bt_ch_mask->bt_ch_mask[0]);
            UINT32_TO_STREAM(p,btfmmitigation.FmMit->info.bt_ch_mask->bt_ch_mask[1]);
            UINT32_TO_STREAM(p,btfmmitigation.FmMit->info.bt_ch_mask->bt_ch_mask[2]);
/* Respect to Bluetooth specification doc, if we send zero as channel mask, then it will disable the channel.
But FM has taken assumption in reverse way. So doing bit invert to achive the result. If FM will follow Bluetooth spec
assumption, then we will remove the bit invert step. Currently it is overhead*/
       //   for(i=0;i<12;i++)
       //   ch_mask[i]=(unsigned char)~ch_mask[i];
            bta_dm_btfm_set_afh_channels(ch_mask);
            return IUI_FM_MITIGATION_ASYNC_PENDING;
        }
        else{
            return IUI_FM_MITIGATION_ERROR_INVALID_PARAM;
        }
    }
    else{
        return IUI_FM_MITIGATION_ERROR_INVALID_PARAM;
    }
}

/******************************************************************************************************
**
** Function    bta_btfm_set_afh_channels_evt_cb
**
** Description    callback to complete event, when we get event from controller corresponding that
** event calling IuiFmMitigationComplete and notifying to FM
**
** Returns    void
**
**********************************************************************************************************/

void bta_btfm_set_afh_channels_evt_cb(UINT8 result)
{
    BOOLEAN evt = result;
    APPL_TRACE_DEBUG1("%s : ", __FUNCTION__);
    if(!evt)
    {
    // IUI_FM_MITIGATION_COMPLETE_OK success case
        UTA_REMOTE_CALL(IuiFmMitigationComplete)(IUI_FM_MACRO_ID_BT, IUI_FM_MITIGATION_COMPLETE_OK, btfmmitigation.FmMit, btfmmitigation.Seq );
    }
    free(btfmmitigation.FmMit);
    free(btfm_mask);
    btfmmitigation.FmMit=NULL;
    btfm_mask=NULL;
}

#endif