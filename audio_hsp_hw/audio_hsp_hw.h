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

/*****************************************************************************
 *
 *  Filename:      audio_hsp_hw.h  (derived from audio_a2dp_hw.h)
 *
 *  Description:
 *
 *****************************************************************************/

#ifndef AUDIO_HSP_HW_H
#define AUDIO_HSP_HW_H

#include <system/audio.h>

/*****************************************************************************
**  Constants & Macros
******************************************************************************/
//TODO: discuss if we need another ctrl/data socket pair for input
#define HSP_AUDIO_HARDWARE_INTERFACE "audio.hsp"
#define HSP_OUT_CTRL_PATH "/data/misc/bluedroid/.hsp_out_ctrl"
#define HSP_OUT_DATA_PATH "/data/misc/bluedroid/.hsp_out_data"
#define HSP_IN_CTRL_PATH "/data/misc/bluedroid/.hsp_in_ctrl"
#define HSP_IN_DATA_PATH "/data/misc/bluedroid/.hsp_in_data"

#define AUDIO_STREAM_DEFAULT_RATE          44100
#define AUDIO_STREAM_DEFAULT_FORMAT        AUDIO_FORMAT_PCM_16_BIT
#define HSP_SOCKET_BUFFER_SZ      (40*512)  /* IN and OUT may have different settings in the future. */
#define AUDIO_SKT_DISCONNECTED             (-1)

/* hard coded sample rate supported in BT stack before we have a negotiation mechanism. */
#define BT_STREAM_IN_RATE 8000
#define BT_STREAM_OUT_RATE 8000

typedef enum {
    HSP_CTRL_CMD_NONE,
    HSP_CTRL_CMD_CHECK_READY,
    HSP_CTRL_CMD_START,
    HSP_CTRL_CMD_STOP,
    HSP_CTRL_CMD_SUSPEND
} tHSP_CTRL_CMD;

typedef enum {
    HSP_CTRL_ACK_SUCCESS,
    HSP_CTRL_ACK_FAILURE
} tHSP_CTRL_ACK;


/*****************************************************************************
**  Type definitions for callback functions
******************************************************************************/

/*****************************************************************************
**  Type definitions and return values
******************************************************************************/

/*****************************************************************************
**  Extern variables and functions
******************************************************************************/

/*****************************************************************************
**  Functions
******************************************************************************/


/*****************************************************************************
**
** Function
**
** Description
**
** Returns
**
******************************************************************************/

#endif /* HSP_AUDIO_HW_H */
