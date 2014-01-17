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

/*******************************************************************************
 *
 *  Filename:      btif_hf.h
 *
 *  Description:   This is the Handsfree Profile for the BTIF system.
 *
 *******************************************************************************/

#ifndef BTIF_HF_H
#define BTIF_HF_H

/* BTIF-HF control block to map bdaddr to BTA handle */
/* This structure contents was originally defined in bluedroid code, which is taken here */
typedef struct _btif_hf_cb
{
    UINT16                  handle;
    bt_bdaddr_t             connected_bda;
    bthf_connection_state_t state;
    bthf_vr_state_t         vr_state;
    tBTA_AG_PEER_FEAT       peer_feat;
    int                     num_active;
    int                     num_held;
    struct timespec         call_end_timestamp;
    bthf_call_state_t       call_setup_state;
} btif_hf_cb_t;

btif_hf_cb_t btif_hf_cb;

#endif
