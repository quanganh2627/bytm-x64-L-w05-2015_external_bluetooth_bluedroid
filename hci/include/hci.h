/*****************************************************************************
 * Copyright (C) 2012-2013 Intel Mobile Communications GmbH
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
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

/******************************************************************************
 *
 *  Filename:      hci.h
 *
 *  Description:   Contains definitions used for HCI transport controls
 *
 ******************************************************************************/

#ifndef HCI_H
#define HCI_H

/******************************************************************************
**  Constants & Macros
******************************************************************************/

/******************************************************************************
**  Type definitions
******************************************************************************/

/** Prototypes for HCI Service interface functions **/

/* Initialize transport's control block */
typedef void (*tHCI_INIT)(void);

/* Do transport's control block clean-up */
typedef void (*tHCI_CLEANUP)(void);

/* Send HCI command/data to the transport */
typedef void (*tHCI_SEND)(HC_BT_HDR *p_msg);

/* Handler for HCI upstream path */
typedef uint16_t (*tHCI_RCV)(void);

/* Callback function for the returned event of internally issued command */
typedef void (*tINT_CMD_CBACK)(void *p_mem);

/* Handler for sending HCI command from the local module */
typedef uint8_t (*tHCI_SEND_INT)(uint16_t opcode, uint8_t compl_evt_code, \
                                  HC_BT_HDR *p_buf, \
                                  tINT_CMD_CBACK p_cback);

/* Handler for getting acl data length */
typedef void (*tHCI_ACL_DATA_LEN_HDLR)(void);
typedef void (*tSCO_TRIGGER)(int state, uint16_t sco_handle);

/******************************************************************************
**  Extern variables and functions
******************************************************************************/

typedef struct {
    tHCI_INIT init;
    tHCI_CLEANUP cleanup;
    tHCI_SEND send;
    tHCI_SEND_INT send_int_cmd;
    tHCI_ACL_DATA_LEN_HDLR get_acl_max_len;
#ifdef HCI_USE_MCT
    tHCI_RCV evt_rcv;
    tHCI_RCV acl_rcv;
#else
    tHCI_RCV rcv;
    tSCO_TRIGGER sco_trigger;

#endif
} tHCI_IF;

/******************************************************************************
**  Functions
******************************************************************************/


#endif /* HCI_H */

