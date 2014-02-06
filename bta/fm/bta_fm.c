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

#define BTA_FM_RPC_UPPER_BITS 0x20000000
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

static bool bta_fm_registered = false;

#ifdef BDT_BTA_FM_DEBUG
IuiFmMitigation bdt_mitigation;
static int sequence;
#endif

/********************************************************************************************************
**             FUNCTIONS
**
**********************************************************************************************************/
/*********************************************************************************************************
**
** Function    bta_fm_register
**
** Description    register bluetooth with frequency manager and obtain handle
**
** Returns    void
**
**************************************************************************************************************/

void bta_fm_register()
{
    UtaUInt rpc_upper_bits = 0x0;
    UtaContextId rpc_id = 0;
    rpc_upper_bits = BTA_FM_RPC_UPPER_BITS;
    UtaUInt32 RpcAppsID = 0x0;
    APPL_TRACE_DEBUG1("%s : ", __FUNCTION__);
    if(bta_fm_registered)
    {
        APPL_TRACE_DEBUG1("%s : Already registered", __FUNCTION__);
        return;
    }
    /* creates queue and thread for listening to remote procedure calls,
    and set up the RPC interface */
    RpcAppsID = AppRPCIFHndlrInit();
    APPL_TRACE_DEBUG2("%s : RpcAppsID = %d ", __FUNCTION__,RpcAppsID);
    /* The client Id (Application Id) which is obtained from the
    above function is set placed in the LSB. Clear the remaining values
    and retain Client Id.*/
    RpcAppsID = (RpcAppsID & 0x000000FF);
    /* Shift client Id to the last but one byte, so that clients can
    append context Id relevant to their implementation to the last byte.*/
    rpc_upper_bits |= (RpcAppsID << 8);
    rpc_id = rpc_upper_bits;
    /* Set global variable in RPC for the current client. Not time dependent.*/
    RPCSetClientId(rpc_id);
    APPL_TRACE_DEBUG2("%s : rpc_id = %d ", __FUNCTION__,rpc_id);
    bta_fm_registered = true;

}
/*********************************************************************************************************
**
** Function    bta_fm_init
**
** Description    register bluetooth with FM, This method is get called when Bluetooth core is enabled
** and it call to IuiFmNotifyFrequency to notify FM with Bluetooth status turn ON and	subsquently call
** to IuiFmRegisterMitigationCallback to register metigation callback.
**
** Returns    void
**
**************************************************************************************************************/

void  bta_fm_init()
{
    APPL_TRACE_DEBUG1("%s : ", __FUNCTION__);
    bta_fm_register();
    if(binfo_on==NULL)
    {    binfo_on = (IuiFmBtInfo *) GKI_getbuf(sizeof(IuiFmBtInfo));
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
    APPL_TRACE_DEBUG1("%s : IuiFmNotifyFrequency - BT on notification ", __FUNCTION__);
    ALOGI("%s:IuiFmNotifyFrequency - BT on notification",__FUNCTION__);
    UTA_REMOTE_CALL(IuiFmRegisterMitigationCallback)( IUI_FM_MACRO_ID_BT, bt_iui_fm_mitigation_cb );
    APPL_TRACE_DEBUG1("%s : IuiFmRegisterMitigationCallback - BT mitigation cb registered ", __FUNCTION__);
    GKI_freebuf(binfo_on);
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
    binfo_off = (IuiFmBtInfo *) GKI_getbuf(sizeof(IuiFmBtInfo));
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
    APPL_TRACE_DEBUG1("%s : IuiFmNotifyFrequency - BT off notification ", __FUNCTION__);
    ALOGI("%s: BT off notification",__FUNCTION__);
    UTA_REMOTE_CALL(IuiFmRegisterMitigationCallback)( IUI_FM_MACRO_ID_BT, NULL );
    APPL_TRACE_DEBUG1("%s : IuiFmRegisterMitigationCallback - unregister ", __FUNCTION__);
    GKI_freebuf(binfo_off);
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
    int i,j;
    btfmmitigation.MacroId = macro_id;
    btfmmitigation.Seq = sequence;
    UINT8  *p=ch_mask;
    UINT8  Chmask_count=0;
    APPL_TRACE_DEBUG1("%s : ", __FUNCTION__);
    ALOGI("%s : ++++ ",__FUNCTION__);
    APPL_TRACE_DEBUG2("%s : macro_id = %d",__FUNCTION__,macro_id);
    APPL_TRACE_DEBUG2("%s : mitigation->type = %d",__FUNCTION__,mitigation->type);
    if((btfmmitigation.MacroId == IUI_FM_MACRO_ID_BT) && (mitigation->type == IUI_FM_MITIGATION_TYPE_BT))
    {
        btfmmitigation.FmMit = (IuiFmMitigation  *) GKI_getbuf(sizeof(IuiFmMitigation));
        if(!btfmmitigation.FmMit)
        {
            APPL_TRACE_ERROR0("btfmmitigation.FmMit = NULL");
            return IUI_FM_MITIGATION_ERROR;
        }
        btfmmitigation.FmMit->type=mitigation->type;
        btfm_mask = (IuiFmBtChannelMask *) GKI_getbuf(sizeof(UINT32)*IUI_FM_BT_CHANNEL_MASK_WORDS);
        if(!btfm_mask)
        {
            APPL_TRACE_ERROR0("btfm_mask = NULL");
            GKI_freebuf(btfmmitigation.FmMit);
            btfmmitigation.FmMit=NULL;
            return IUI_FM_MITIGATION_ERROR;
        }
        btfmmitigation.FmMit->info.bt_ch_mask = btfm_mask;
        APPL_TRACE_DEBUG1("mitigation->info.bt_ch_mask->bt_ch_mask[0] = %0x",mitigation->info.bt_ch_mask->bt_ch_mask[0]);
        APPL_TRACE_DEBUG1("mitigation->info.bt_ch_mask->bt_ch_mask[1] = %0x",mitigation->info.bt_ch_mask->bt_ch_mask[1]);
        APPL_TRACE_DEBUG1("mitigation->info.bt_ch_mask->bt_ch_mask[2] = %0x",mitigation->info.bt_ch_mask->bt_ch_mask[2]);
        for(i=0;i<IUI_FM_BT_CHANNEL_MASK_WORDS;i++)
        {
            btfmmitigation.FmMit->info.bt_ch_mask->bt_ch_mask[i]=mitigation->info.bt_ch_mask->bt_ch_mask[i];
        }

        UINT32_TO_STREAM(p,btfmmitigation.FmMit->info.bt_ch_mask->bt_ch_mask[0]);
        UINT32_TO_STREAM(p,btfmmitigation.FmMit->info.bt_ch_mask->bt_ch_mask[1]);
        UINT32_TO_STREAM(p,btfmmitigation.FmMit->info.bt_ch_mask->bt_ch_mask[2]);
        /* Respect to Bluetooth specification doc, if we send zero as channel mask, then it will disable the channel.
        But FM has taken assumption in reverse way. So doing bit invert to achieve the result */
        APPL_TRACE_ERROR1(" %s : btfmmitigation.FmMit->type == IUI_FM_MITIGATION_TYPE_BT",__FUNCTION__);
        for(i=0;i<12;i++)
        {
            ch_mask[i]=(unsigned char)~ch_mask[i];
            APPL_TRACE_DEBUG1("Mitigation channels requested = %0x",ch_mask[i]);
            /* check for the Channel mask if it is valid.
               AFH channel mask is valid only if minimum of 20 BT channels
               should be enabled. If it is less than 20 channels, it is invalid
               channel mask. the same can be be intimated to FM with return code */
            if( Chmask_count < 20)
            {
                for(j = 0; j<8; j++)
                {
                    if((ch_mask[i] >> j)&(0x01))
                        Chmask_count++;
                }
            }
        }
        if(Chmask_count < 20)
        {
            ALOGI("%s : Invalid AFH channel mask for mitigation",__FUNCTION__);
            return IUI_FM_MITIGATION_COMPLETE_NOT_ACCEPTABLE;
        }
        else
        {
            bta_dm_btfm_set_afh_channels(ch_mask);
            ALOGI("%s : --- IUI_FM_MITIGATION_ASYNC_PENDING",__FUNCTION__);
            return IUI_FM_MITIGATION_ASYNC_PENDING;
        }
    }
    else
    {
        APPL_TRACE_ERROR1(" %s : --- IUI_FM_MITIGATION_ERROR_INVALID_PARAM",__FUNCTION__);
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
    ALOGI("%s : ++++ ",__FUNCTION__);
    if(!evt)
    {
#ifdef BDT_BTA_FM_DEBUG
        btif_inform_fm_mitigation_status(IUI_FM_MITIGATION_COMPLETE_OK,sequence);
#else
    // IUI_FM_MITIGATION_COMPLETE_OK success case
        UTA_REMOTE_CALL(IuiFmMitigationComplete)(IUI_FM_MACRO_ID_BT, IUI_FM_MITIGATION_COMPLETE_OK,
                        btfmmitigation.FmMit, btfmmitigation.Seq );
#endif
        ALOGI("%s : IUI_FM_MITIGATION_COMPLETE_OK ",__FUNCTION__);
    }
    if(btfmmitigation.FmMit)
        GKI_freebuf(btfmmitigation.FmMit);
    if(btfm_mask)
        GKI_freebuf(btfm_mask);
    btfmmitigation.FmMit=NULL;
    btfm_mask=NULL;
#ifdef BDT_BTA_FM_DEBUG
    if(bdt_mitigation.info.bt_ch_mask)
    GKI_freebuf(bdt_mitigation.info.bt_ch_mask);
    bdt_mitigation.info.bt_ch_mask = NULL;
#endif
}

#ifdef BDT_BTA_FM_DEBUG
int bta_btfm_mitigation_req(void *ch_mask)
{
    APPL_TRACE_DEBUG1("%s : ", __FUNCTION__);
    int i;
    uint8_t *p = NULL;
    IuiFmMitigationStatus test_mitigation_status;
    bdt_mitigation.type = IUI_FM_MITIGATION_TYPE_BT;
    bdt_mitigation.info.bt_ch_mask = (IuiFmMitigation  *)GKI_getbuf(sizeof(IuiFmBtChannelMask));
    if(!bdt_mitigation.info.bt_ch_mask)return 1;
    for (i=0; i<12;i++)
    APPL_TRACE_DEBUG3("%s : byte stream [%d] = %0x",__FUNCTION__,i,(unsigned char)(*((uint8_t *)ch_mask+i)));
    memcpy(&bdt_mitigation.info.bt_ch_mask->bt_ch_mask[0],ch_mask,3*sizeof(uint32_t));
    p = (uint8_t *)bdt_mitigation.info.bt_ch_mask->bt_ch_mask;
    for (i=0; i<12;i++)
     APPL_TRACE_DEBUG3("%s : bdt_mitigation.info.bt_ch_mask->bt_ch_mask[%d] = %02x", __FUNCTION__,i,*(p+i));
    test_mitigation_status = bt_iui_fm_mitigation_cb(IUI_FM_MACRO_ID_BT,&bdt_mitigation,sequence++);
    if (test_mitigation_status !=IUI_FM_MITIGATION_COMPLETE_OK)
        btif_inform_fm_mitigation_status(test_mitigation_status,sequence);
    return test_mitigation_status;
}
#endif

#endif
