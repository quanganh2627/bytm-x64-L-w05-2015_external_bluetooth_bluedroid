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

#ifndef BTA_FM_H
#define BTA_FM_H

/*FM Interface code is under flag BT_FM_MITIGATION. Using this flag we can enable or disable the FM Interface code.*/
/*
******* Currently, disable this macro, because RPC APIs are not working, they wait for modem response.******
#define BT_FM_MITIGATION
*/

/*************************************************************************************************************
**
** Function    bta_fm_init
**
** Description    register bluetooth with FM, This method is get called when Bluetooth core is enabled
** and it call to IuiFmNotifyFrequency to notify FM with Bluetooth status turn ON and subsquently call to
** IuiFmRegisterMitigationCallback to register metigation callback.
**
** Returns    void
**
****************************************************************************************************************/
void bta_fm_init(void);
/***************************************************************************************************************
**
** Function    bta_fm_deinit
**
** Description    unregister bluetooth from FM. This method is get called when Bluetooth core is disabling
** and it call to IuiFmNotifyFrequency to notify FM with Bluetooth status turn OFF and subsquently call to
** IuiFmRegisterMitigationCallback to de-register metigation callback. To de-register metigation callback,
** we pass NULL.
**
** Returns    void
**
***********************************************************************************************************/
void bta_fm_deinit(void);
/******************************************************************************************************
**
** Function    bta_btfm_set_afh_channels_evt_cb
**
** Description    callback to complete event, when we get event from controller corresponding that
** event calling IuiFmMitigationComplete and notifying to FM
**
** Returns    void
**
*******************************************************************************************************/
void bta_btfm_set_afh_channels_evt_cb(UINT8);
#endif /* BTA_FM_H  */