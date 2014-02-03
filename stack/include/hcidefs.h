/******************************************************************************
 *
 *  Copyright (C) 1999-2012 Broadcom Corporation
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

#ifndef HCIDEFS_H
#define HCIDEFS_H

#define HCI_PROTO_VERSION     0x01      /* Version for BT spec 1.1          */
#define HCI_PROTO_VERSION_1_2 0x02      /* Version for BT spec 1.2          */
#define HCI_PROTO_VERSION_2_0 0x03      /* Version for BT spec 2.0          */
#define HCI_PROTO_VERSION_2_1 0x04      /* Version for BT spec 2.1 [Lisbon] */
#define HCI_PROTO_VERSION_3_0 0x05      /* Version for BT spec 3.0          */
#define HCI_PROTO_REVISION    0x000C    /* Current implementation version   */
/*
**  Definitions for HCI groups
*/
#define HCI_GRP_LINK_CONTROL_CMDS       (0x01 << 10)            /* 0x0400 */
#define HCI_GRP_LINK_POLICY_CMDS        (0x02 << 10)            /* 0x0800 */
#define HCI_GRP_HOST_CONT_BASEBAND_CMDS (0x03 << 10)            /* 0x0C00 */
#define HCI_GRP_INFORMATIONAL_PARAMS    (0x04 << 10)            /* 0x1000 */
#define HCI_GRP_STATUS_PARAMS           (0x05 << 10)            /* 0x1400 */
#define HCI_GRP_TESTING_CMDS            (0x06 << 10)            /* 0x1800 */

#define HCI_GRP_VENDOR_SPECIFIC         (0x3F << 10)            /* 0xFC00 */

/* Group occupies high 6 bits of the HCI command rest is opcode itself */
#define HCI_OGF(p)  (UINT8)((0xFC00 & (p)) >> 10)
#define HCI_OCF(p)  ( 0x3FF & (p))

/*
**  Defentions for Link Control Commands
*/
/* Following opcode is used only in command complete event for flow control */
#define HCI_COMMAND_NONE                0x0000

/* Commands of HCI_GRP_LINK_CONTROL_CMDS group */
#define HCI_INQUIRY                     (0x0001 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_INQUIRY_CANCEL              (0x0002 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_PERIODIC_INQUIRY_MODE       (0x0003 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_EXIT_PERIODIC_INQUIRY_MODE  (0x0004 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_CREATE_CONNECTION           (0x0005 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_DISCONNECT                  (0x0006 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_ADD_SCO_CONNECTION          (0x0007 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_CREATE_CONNECTION_CANCEL    (0x0008 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_ACCEPT_CONNECTION_REQUEST   (0x0009 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_REJECT_CONNECTION_REQUEST   (0x000A | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_LINK_KEY_REQUEST_REPLY      (0x000B | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_LINK_KEY_REQUEST_NEG_REPLY  (0x000C | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_PIN_CODE_REQUEST_REPLY      (0x000D | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_PIN_CODE_REQUEST_NEG_REPLY  (0x000E | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_CHANGE_CONN_PACKET_TYPE     (0x000F | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_AUTHENTICATION_REQUESTED    (0x0011 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_SET_CONN_ENCRYPTION         (0x0013 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_CHANGE_CONN_LINK_KEY        (0x0015 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_MASTER_LINK_KEY             (0x0017 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_RMT_NAME_REQUEST            (0x0019 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_RMT_NAME_REQUEST_CANCEL     (0x001A | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_READ_RMT_FEATURES           (0x001B | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_READ_RMT_EXT_FEATURES       (0x001C | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_READ_RMT_VERSION_INFO       (0x001D | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_READ_RMT_CLOCK_OFFSET       (0x001F | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_READ_LMP_HANDLE             (0x0020 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_SETUP_ESCO_CONNECTION       (0x0028 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_ACCEPT_ESCO_CONNECTION      (0x0029 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_REJECT_ESCO_CONNECTION      (0x002A | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_IO_CAPABILITY_RESPONSE      (0x002B | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_USER_CONF_REQUEST_REPLY     (0x002C | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_USER_CONF_VALUE_NEG_REPLY   (0x002D | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_USER_PASSKEY_REQ_REPLY      (0x002E | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_USER_PASSKEY_REQ_NEG_REPLY  (0x002F | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_REM_OOB_DATA_REQ_REPLY      (0x0030 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_REM_OOB_DATA_REQ_NEG_REPLY  (0x0033 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_IO_CAP_REQ_NEG_REPLY        (0x0034 | HCI_GRP_LINK_CONTROL_CMDS)

/* AMP HCI */
#define HCI_CREATE_PHYSICAL_LINK        (0x0035 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_ACCEPT_PHYSICAL_LINK        (0x0036 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_DISCONNECT_PHYSICAL_LINK    (0x0037 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_CREATE_LOGICAL_LINK         (0x0038 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_ACCEPT_LOGICAL_LINK         (0x0039 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_DISCONNECT_LOGICAL_LINK     (0x003A | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_LOGICAL_LINK_CANCEL         (0x003B | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_FLOW_SPEC_MODIFY            (0x003C | HCI_GRP_LINK_CONTROL_CMDS)

#define HCI_ENH_SETUP_ESCO_CONNECTION   (0x003D | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_ENH_ACCEPT_ESCO_CONNECTION  (0x003E | HCI_GRP_LINK_CONTROL_CMDS)

/* ConnectionLess Broadcast */
#define HCI_TRUNCATED_PAGE              (0x003F | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_TRUNCATED_PAGE_CANCEL       (0x0040 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_SET_CLB                     (0x0041 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_RECEIVE_CLB                 (0x0042 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_START_SYNC_TRAIN            (0x0043 | HCI_GRP_LINK_CONTROL_CMDS)
#define HCI_RECEIVE_SYNC_TRAIN          (0x0044 | HCI_GRP_LINK_CONTROL_CMDS)

#define HCI_LINK_CTRL_CMDS_FIRST        HCI_INQUIRY
#define HCI_LINK_CTRL_CMDS_LAST         HCI_RECEIVE_SYNC_TRAIN

/* Commands of HCI_GRP_LINK_POLICY_CMDS */
#define HCI_HOLD_MODE                   (0x0001 | HCI_GRP_LINK_POLICY_CMDS)
#define HCI_SNIFF_MODE                  (0x0003 | HCI_GRP_LINK_POLICY_CMDS)
#define HCI_EXIT_SNIFF_MODE             (0x0004 | HCI_GRP_LINK_POLICY_CMDS)
#define HCI_PARK_MODE                   (0x0005 | HCI_GRP_LINK_POLICY_CMDS)
#define HCI_EXIT_PARK_MODE              (0x0006 | HCI_GRP_LINK_POLICY_CMDS)
#define HCI_QOS_SETUP                   (0x0007 | HCI_GRP_LINK_POLICY_CMDS)
#define HCI_ROLE_DISCOVERY              (0x0009 | HCI_GRP_LINK_POLICY_CMDS)
#define HCI_SWITCH_ROLE                 (0x000B | HCI_GRP_LINK_POLICY_CMDS)
#define HCI_READ_POLICY_SETTINGS        (0x000C | HCI_GRP_LINK_POLICY_CMDS)
#define HCI_WRITE_POLICY_SETTINGS       (0x000D | HCI_GRP_LINK_POLICY_CMDS)
#define HCI_READ_DEF_POLICY_SETTINGS    (0x000E | HCI_GRP_LINK_POLICY_CMDS)
#define HCI_WRITE_DEF_POLICY_SETTINGS   (0x000F | HCI_GRP_LINK_POLICY_CMDS)
#define HCI_FLOW_SPECIFICATION          (0x0010 | HCI_GRP_LINK_POLICY_CMDS)
#define HCI_SNIFF_SUB_RATE              (0x0011 | HCI_GRP_LINK_POLICY_CMDS)

#define HCI_LINK_POLICY_CMDS_FIRST      HCI_HOLD_MODE
#define HCI_LINK_POLICY_CMDS_LAST       HCI_SNIFF_SUB_RATE


/* Commands of HCI_GRP_HOST_CONT_BASEBAND_CMDS */
#define HCI_SET_EVENT_MASK              (0x0001 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_RESET                       (0x0003 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_SET_EVENT_FILTER            (0x0005 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_FLUSH                       (0x0008 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_PIN_TYPE               (0x0009 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_PIN_TYPE              (0x000A | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_CREATE_NEW_UNIT_KEY         (0x000B | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_GET_MWS_TRANS_LAYER_CFG     (0x000C | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_STORED_LINK_KEY        (0x000D | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_STORED_LINK_KEY       (0x0011 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_DELETE_STORED_LINK_KEY      (0x0012 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_CHANGE_LOCAL_NAME           (0x0013 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_LOCAL_NAME             (0x0014 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_CONN_ACCEPT_TOUT       (0x0015 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_CONN_ACCEPT_TOUT      (0x0016 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_PAGE_TOUT              (0x0017 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_PAGE_TOUT             (0x0018 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_SCAN_ENABLE            (0x0019 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_SCAN_ENABLE           (0x001A | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_PAGESCAN_CFG           (0x001B | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_PAGESCAN_CFG          (0x001C | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_INQUIRYSCAN_CFG        (0x001D | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_INQUIRYSCAN_CFG       (0x001E | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_AUTHENTICATION_ENABLE  (0x001F | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_AUTHENTICATION_ENABLE (0x0020 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_ENCRYPTION_MODE        (0x0021 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_ENCRYPTION_MODE       (0x0022 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_CLASS_OF_DEVICE        (0x0023 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_CLASS_OF_DEVICE       (0x0024 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_VOICE_SETTINGS         (0x0025 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_VOICE_SETTINGS        (0x0026 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_AUTO_FLUSH_TOUT        (0x0027 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_AUTO_FLUSH_TOUT       (0x0028 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_NUM_BCAST_REXMITS      (0x0029 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_NUM_BCAST_REXMITS     (0x002A | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_HOLD_MODE_ACTIVITY     (0x002B | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_HOLD_MODE_ACTIVITY    (0x002C | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_TRANSMIT_POWER_LEVEL   (0x002D | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_SCO_FLOW_CTRL_ENABLE   (0x002E | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_SCO_FLOW_CTRL_ENABLE  (0x002F | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_SET_HC_TO_HOST_FLOW_CTRL    (0x0031 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_HOST_BUFFER_SIZE            (0x0033 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_HOST_NUM_PACKETS_DONE       (0x0035 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_LINK_SUPER_TOUT        (0x0036 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_LINK_SUPER_TOUT       (0x0037 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_NUM_SUPPORTED_IAC      (0x0038 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_CURRENT_IAC_LAP        (0x0039 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_CURRENT_IAC_LAP       (0x003A | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_PAGESCAN_PERIOD_MODE   (0x003B | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_PAGESCAN_PERIOD_MODE  (0x003C | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_PAGESCAN_MODE          (0x003D | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_PAGESCAN_MODE         (0x003E | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_SET_AFH_CHANNELS            (0x003F | HCI_GRP_HOST_CONT_BASEBAND_CMDS)

#define HCI_READ_INQSCAN_TYPE           (0x0042 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_INQSCAN_TYPE          (0x0043 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_INQUIRY_MODE           (0x0044 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_INQUIRY_MODE          (0x0045 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_PAGESCAN_TYPE          (0x0046 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_PAGESCAN_TYPE         (0x0047 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_AFH_ASSESSMENT_MODE    (0x0048 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_AFH_ASSESSMENT_MODE   (0x0049 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_EXT_INQ_RESPONSE       (0x0051 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_EXT_INQ_RESPONSE      (0x0052 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_REFRESH_ENCRYPTION_KEY      (0x0053 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_SIMPLE_PAIRING_MODE    (0x0055 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_SIMPLE_PAIRING_MODE   (0x0056 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_LOCAL_OOB_DATA         (0x0057 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_INQ_TX_POWER_LEVEL     (0x0058 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_INQ_TX_POWER_LEVEL    (0x0059 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_ERRONEOUS_DATA_RPT     (0x005A | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_ERRONEOUS_DATA_RPT    (0x005B | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_ENHANCED_FLUSH              (0x005F | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_SEND_KEYPRESS_NOTIF         (0x0060 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)


/* AMP HCI */
#define HCI_READ_LOGICAL_LINK_ACCEPT_TIMEOUT  (0x0061 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_LOGICAL_LINK_ACCEPT_TIMEOUT (0x0062 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_SET_EVENT_MASK_PAGE_2             (0x0063 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_LOCATION_DATA                (0x0064 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_LOCATION_DATA               (0x0065 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_FLOW_CONTROL_MODE            (0x0066 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_FLOW_CONTROL_MODE           (0x0067 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_BE_FLUSH_TOUT                (0x0069 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_BE_FLUSH_TOUT               (0x006A | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_SHORT_RANGE_MODE                  (0x006B | HCI_GRP_HOST_CONT_BASEBAND_CMDS) /* 802.11 only */
#define HCI_READ_LE_HOST_SUPPORTED              (0x006C | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_LE_HOST_SUPPORTED             (0x006D | HCI_GRP_HOST_CONT_BASEBAND_CMDS)


/* MWS coexistence */
#define HCI_SET_MWS_CHANNEL_PARAMETERS          (0x006E | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_SET_EXTERNAL_FRAME_CONFIGURATION    (0x006F | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_SET_MWS_SIGNALING                   (0x0070 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_SET_MWS_TRANSPORT_LAYER             (0x0071 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_SET_MWS_SCAN_FREQUENCY_TABLE        (0x0072 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_SET_MWS_PATTERN_CONFIGURATION       (0x0073 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)

/* ConnectionLess Broadcast */
#define HCI_SET_RESERVED_LT_ADDR                (0x0077 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_DELETE_RESERVED_LT_ADDR             (0x0078 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_CLB_DATA                      (0x0079 | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_WRITE_SYNC_TRAIN_PARAM              (0x007A | HCI_GRP_HOST_CONT_BASEBAND_CMDS)
#define HCI_READ_SYNC_TRAIN_PARAM               (0x007B | HCI_GRP_HOST_CONT_BASEBAND_CMDS)

#define HCI_CONT_BASEBAND_CMDS_FIRST    HCI_SET_EVENT_MASK
#define HCI_CONT_BASEBAND_CMDS_LAST     HCI_READ_SYNC_TRAIN_PARAM


/* Commands of HCI_GRP_INFORMATIONAL_PARAMS group */
#define HCI_READ_LOCAL_VERSION_INFO     (0x0001 | HCI_GRP_INFORMATIONAL_PARAMS)
#define HCI_READ_LOCAL_SUPPORTED_CMDS   (0x0002 | HCI_GRP_INFORMATIONAL_PARAMS)
#define HCI_READ_LOCAL_FEATURES         (0x0003 | HCI_GRP_INFORMATIONAL_PARAMS)
#define HCI_READ_LOCAL_EXT_FEATURES     (0x0004 | HCI_GRP_INFORMATIONAL_PARAMS)
#define HCI_READ_BUFFER_SIZE            (0x0005 | HCI_GRP_INFORMATIONAL_PARAMS)
#define HCI_READ_COUNTRY_CODE           (0x0007 | HCI_GRP_INFORMATIONAL_PARAMS)
#define HCI_READ_BD_ADDR                (0x0009 | HCI_GRP_INFORMATIONAL_PARAMS)
#define HCI_READ_DATA_BLOCK_SIZE        (0x000A | HCI_GRP_INFORMATIONAL_PARAMS)
#define HCI_READ_LOCAL_SUPPORTED_CODECS (0x000B | HCI_GRP_INFORMATIONAL_PARAMS)

#define HCI_INFORMATIONAL_CMDS_FIRST    HCI_READ_LOCAL_VERSION_INFO
#define HCI_INFORMATIONAL_CMDS_LAST     HCI_READ_LOCAL_SUPPORTED_CODECS


/* Commands of HCI_GRP_STATUS_PARAMS group */
#define HCI_READ_FAILED_CONTACT_COUNT   (0x0001 | HCI_GRP_STATUS_PARAMS)
#define HCI_RESET_FAILED_CONTACT_COUNT  (0x0002 | HCI_GRP_STATUS_PARAMS)
#define HCI_GET_LINK_QUALITY            (0x0003 | HCI_GRP_STATUS_PARAMS)
#define HCI_READ_RSSI                   (0x0005 | HCI_GRP_STATUS_PARAMS)
#define HCI_READ_AFH_CH_MAP             (0x0006 | HCI_GRP_STATUS_PARAMS)
#define HCI_READ_CLOCK                  (0x0007 | HCI_GRP_STATUS_PARAMS)
#define HCI_READ_ENCR_KEY_SIZE          (0x0008 | HCI_GRP_STATUS_PARAMS)

/* AMP HCI */
#define HCI_READ_LOCAL_AMP_INFO         (0x0009 | HCI_GRP_STATUS_PARAMS)
#define HCI_READ_LOCAL_AMP_ASSOC        (0x000A | HCI_GRP_STATUS_PARAMS)
#define HCI_WRITE_REMOTE_AMP_ASSOC      (0x000B | HCI_GRP_STATUS_PARAMS)

#define HCI_STATUS_PARAMS_CMDS_FIRST    HCI_READ_FAILED_CONTACT_COUNT
#define HCI_STATUS_PARAMS_CMDS_LAST     HCI_WRITE_REMOTE_AMP_ASSOC

/* Commands of HCI_GRP_TESTING_CMDS group */
#define HCI_READ_LOOPBACK_MODE          (0x0001 | HCI_GRP_TESTING_CMDS)
#define HCI_WRITE_LOOPBACK_MODE         (0x0002 | HCI_GRP_TESTING_CMDS)
#define HCI_ENABLE_DEV_UNDER_TEST_MODE  (0x0003 | HCI_GRP_TESTING_CMDS)
#define HCI_WRITE_SIMP_PAIR_DEBUG_MODE  (0x0004 | HCI_GRP_TESTING_CMDS)

/* AMP HCI */
#define HCI_ENABLE_AMP_RCVR_REPORTS     (0x0007 | HCI_GRP_TESTING_CMDS)
#define HCI_AMP_TEST_END                (0x0008 | HCI_GRP_TESTING_CMDS)
#define HCI_AMP_TEST                    (0x0009 | HCI_GRP_TESTING_CMDS)

#define HCI_TESTING_CMDS_FIRST          HCI_READ_LOOPBACK_MODE
#define HCI_TESTING_CMDS_LAST           HCI_AMP_TEST

#define HCI_VENDOR_CMDS_FIRST           0x0001
#define HCI_VENDOR_CMDS_LAST            0xFFFF
#define HCI_VSC_MULTI_AV_HANDLE         0x0AAA
#define HCI_VSC_BURST_MODE_HANDLE       0x0BBB

/* BLE HCI */
#define HCI_GRP_BLE_CMDS                (0x08 << 10)
/* Commands of BLE Controller setup and configuration */
#define HCI_BLE_SET_EVENT_MASK          (0x0001 | HCI_GRP_BLE_CMDS)
#define HCI_BLE_READ_BUFFER_SIZE        (0x0002 | HCI_GRP_BLE_CMDS)
#define HCI_BLE_READ_LOCAL_SPT_FEAT     (0x0003 | HCI_GRP_BLE_CMDS)
#define HCI_BLE_WRITE_LOCAL_SPT_FEAT    (0x0004 | HCI_GRP_BLE_CMDS)
#define HCI_BLE_WRITE_RANDOM_ADDR       (0x0005 | HCI_GRP_BLE_CMDS)
#define HCI_BLE_WRITE_ADV_PARAMS        (0x0006 | HCI_GRP_BLE_CMDS)
#define HCI_BLE_READ_ADV_CHNL_TX_POWER  (0x0007 | HCI_GRP_BLE_CMDS)
#define HCI_BLE_WRITE_ADV_DATA          (0x0008 | HCI_GRP_BLE_CMDS)
#define HCI_BLE_WRITE_SCAN_RSP_DATA     (0x0009 | HCI_GRP_BLE_CMDS)
#define HCI_BLE_WRITE_ADV_ENABLE        (0x000A | HCI_GRP_BLE_CMDS)
#define HCI_BLE_WRITE_SCAN_PARAMS       (0x000B | HCI_GRP_BLE_CMDS)
#define HCI_BLE_WRITE_SCAN_ENABLE       (0x000C | HCI_GRP_BLE_CMDS)
#define HCI_BLE_CREATE_LL_CONN          (0x000D | HCI_GRP_BLE_CMDS)
#define HCI_BLE_CREATE_CONN_CANCEL      (0x000E | HCI_GRP_BLE_CMDS)
#define HCI_BLE_READ_WHITE_LIST_SIZE    (0x000F | HCI_GRP_BLE_CMDS)
#define HCI_BLE_CLEAR_WHITE_LIST        (0x0010 | HCI_GRP_BLE_CMDS)
#define HCI_BLE_ADD_WHITE_LIST          (0x0011 | HCI_GRP_BLE_CMDS)
#define HCI_BLE_REMOVE_WHITE_LIST       (0x0012 | HCI_GRP_BLE_CMDS)
#define HCI_BLE_UPD_LL_CONN_PARAMS      (0x0013 | HCI_GRP_BLE_CMDS)
#define HCI_BLE_SET_HOST_CHNL_CLASS     (0x0014 | HCI_GRP_BLE_CMDS)
#define HCI_BLE_READ_CHNL_MAP           (0x0015 | HCI_GRP_BLE_CMDS)
#define HCI_BLE_READ_REMOTE_FEAT        (0x0016 | HCI_GRP_BLE_CMDS)
#define HCI_BLE_ENCRYPT                 (0x0017 | HCI_GRP_BLE_CMDS)
#define HCI_BLE_RAND                    (0x0018 | HCI_GRP_BLE_CMDS)
#define HCI_BLE_START_ENC               (0x0019 | HCI_GRP_BLE_CMDS)
#define HCI_BLE_LTK_REQ_REPLY           (0x001A | HCI_GRP_BLE_CMDS)
#define HCI_BLE_LTK_REQ_NEG_REPLY       (0x001B | HCI_GRP_BLE_CMDS)
#define HCI_BLE_READ_SUPPORTED_STATES   (0x001C | HCI_GRP_BLE_CMDS)
/* BLE TEST COMMANDS */
#define HCI_BLE_RECEIVER_TEST           (0x001D | HCI_GRP_BLE_CMDS)
#define HCI_BLE_TRANSMITTER_TEST        (0x001E | HCI_GRP_BLE_CMDS)
#define HCI_BLE_TEST_END                (0x001F | HCI_GRP_BLE_CMDS)

#define HCI_BLE_RESET                   (0x0020 | HCI_GRP_BLE_CMDS)

/* LE supported states definition */
#define HCI_LE_ADV_STATE          0x00000001
#define HCI_LE_SCAN_STATE         0x00000002
#define HCI_LE_INIT_STATE         0x00000004
#define HCI_LE_CONN_SL_STATE      0x00000008
#define HCI_LE_ADV_SCAN_STATE     0x00000010
#define HCI_LE_ADV_INIT_STATE     0x00000020
#define HCI_LE_ADV_MA_STATE       0x00000040
#define HCI_LE_ADV_SL_STATE       0x00000080
#define HCI_LE_SCAN_INIT_STATE    0x00000100
#define HCI_LE_SCAN_MA_STATE      0x00000200
#define HCI_LE_SCAN_SL_STATE      0x00000400
#define HCI_LE_INIT_MA_STATE      0x00000800

/*
**  Definitions for HCI Events
*/
#define HCI_INQUIRY_COMP_EVT                0x01
#define HCI_INQUIRY_RESULT_EVT              0x02
#define HCI_CONNECTION_COMP_EVT             0x03
#define HCI_CONNECTION_REQUEST_EVT          0x04
#define HCI_DISCONNECTION_COMP_EVT          0x05
#define HCI_AUTHENTICATION_COMP_EVT         0x06
#define HCI_RMT_NAME_REQUEST_COMP_EVT       0x07
#define HCI_ENCRYPTION_CHANGE_EVT           0x08
#define HCI_CHANGE_CONN_LINK_KEY_EVT        0x09
#define HCI_MASTER_LINK_KEY_COMP_EVT        0x0A
#define HCI_READ_RMT_FEATURES_COMP_EVT      0x0B
#define HCI_READ_RMT_VERSION_COMP_EVT       0x0C
#define HCI_QOS_SETUP_COMP_EVT              0x0D
#define HCI_COMMAND_COMPLETE_EVT            0x0E
#define HCI_COMMAND_STATUS_EVT              0x0F
#define HCI_HARDWARE_ERROR_EVT              0x10
#define HCI_FLUSH_OCCURED_EVT               0x11
#define HCI_ROLE_CHANGE_EVT                 0x12
#define HCI_NUM_COMPL_DATA_PKTS_EVT         0x13
#define HCI_MODE_CHANGE_EVT                 0x14
#define HCI_RETURN_LINK_KEYS_EVT            0x15
#define HCI_PIN_CODE_REQUEST_EVT            0x16
#define HCI_LINK_KEY_REQUEST_EVT            0x17
#define HCI_LINK_KEY_NOTIFICATION_EVT       0x18
#define HCI_LOOPBACK_COMMAND_EVT            0x19
#define HCI_DATA_BUF_OVERFLOW_EVT           0x1A
#define HCI_MAX_SLOTS_CHANGED_EVT           0x1B
#define HCI_READ_CLOCK_OFF_COMP_EVT         0x1C
#define HCI_CONN_PKT_TYPE_CHANGE_EVT        0x1D
#define HCI_QOS_VIOLATION_EVT               0x1E
#define HCI_PAGE_SCAN_MODE_CHANGE_EVT       0x1F
#define HCI_PAGE_SCAN_REP_MODE_CHNG_EVT     0x20
#define HCI_FLOW_SPECIFICATION_COMP_EVT     0x21
#define HCI_INQUIRY_RSSI_RESULT_EVT         0x22
#define HCI_READ_RMT_EXT_FEATURES_COMP_EVT  0x23
#define HCI_ESCO_CONNECTION_COMP_EVT        0x2C
#define HCI_ESCO_CONNECTION_CHANGED_EVT     0x2D
#define HCI_SNIFF_SUB_RATE_EVT              0x2E
#define HCI_EXTENDED_INQUIRY_RESULT_EVT     0x2F
#define HCI_ENCRYPTION_KEY_REFRESH_COMP_EVT 0x30
#define HCI_IO_CAPABILITY_REQUEST_EVT       0x31
#define HCI_IO_CAPABILITY_RESPONSE_EVT      0x32
#define HCI_USER_CONFIRMATION_REQUEST_EVT   0x33
#define HCI_USER_PASSKEY_REQUEST_EVT        0x34
#define HCI_REMOTE_OOB_DATA_REQUEST_EVT     0x35
#define HCI_SIMPLE_PAIRING_COMPLETE_EVT     0x36
#define HCI_LINK_SUPER_TOUT_CHANGED_EVT     0x38
#define HCI_ENHANCED_FLUSH_COMPLETE_EVT     0x39
#define HCI_USER_PASSKEY_NOTIFY_EVT         0x3B
#define HCI_KEYPRESS_NOTIFY_EVT             0x3C
#define HCI_RMT_HOST_SUP_FEAT_NOTIFY_EVT    0x3D

/*#define HCI_GENERIC_AMP_LINK_KEY_NOTIF_EVT  0x3E Removed from spec */
#define HCI_PHYSICAL_LINK_COMP_EVT          0x40
#define HCI_CHANNEL_SELECTED_EVT            0x41
#define HCI_DISC_PHYSICAL_LINK_COMP_EVT     0x42
#define HCI_PHY_LINK_LOSS_EARLY_WARNING_EVT 0x43
#define HCI_PHY_LINK_RECOVERY_EVT           0x44
#define HCI_LOGICAL_LINK_COMP_EVT           0x45
#define HCI_DISC_LOGICAL_LINK_COMP_EVT      0x46
#define HCI_FLOW_SPEC_MODIFY_COMP_EVT       0x47
#define HCI_NUM_COMPL_DATA_BLOCKS_EVT       0x48
#define HCI_SHORT_RANGE_MODE_COMPLETE_EVT   0x4C
#define HCI_AMP_STATUS_CHANGE_EVT           0x4D

/* ULP HCI Event */
#define HCI_BLE_EVENT                   0x03E
/* ULP Event sub code */
#define HCI_BLE_CONN_COMPLETE_EVT           0x01
#define HCI_BLE_ADV_PKT_RPT_EVT             0x02
#define HCI_BLE_LL_CONN_PARAM_UPD_EVT       0x03
#define HCI_BLE_READ_REMOTE_FEAT_CMPL_EVT   0x04
#define HCI_BLE_LTK_REQ_EVT                 0x05

/* ConnectionLess Broadcast events */
#define HCI_SYNC_TRAIN_COMP_EVT             0x4F
#define HCI_SYNC_TRAIN_RECEIVED_EVT         0x50
#define HCI_CLB_RX_DATA_EVT                 0x51
#define HCI_CLB_RX_TIMEOUT_EVT              0x52
#define HCI_TRUNCATED_PAGE_COMP_EVT         0x53
#define HCI_SLAVE_PAGE_RESP_TIMEOUT_EVT     0x54
#define HCI_CLB_CHANNEL_CHANGE_EVT          0x55
#define HCI_INQUIRY_RESPONSE_NOTIF          0x56

#define HCI_EVENT_RSP_FIRST                 HCI_INQUIRY_COMP_EVT
#define HCI_EVENT_RSP_LAST                  HCI_CLB_CHANNEL_CHANGE_EVT

#define HCI_VENDOR_SPECIFIC_EVT         0xFF  /* Vendor specific events */
#define HCI_NAP_TRACE_EVT               0xFF  /* was define 0xFE, 0xFD, change to 0xFF
                                                 because conflict w/ TCI_EVT and per
                                                 specification compliant */



/*
**  Defentions for HCI Error Codes that are past in the events
*/
#define HCI_SUCCESS                                     0x00
#define HCI_PENDING                                     0x00
#define HCI_ERR_ILLEGAL_COMMAND                         0x01
#define HCI_ERR_NO_CONNECTION                           0x02
#define HCI_ERR_HW_FAILURE                              0x03
#define HCI_ERR_PAGE_TIMEOUT                            0x04
#define HCI_ERR_AUTH_FAILURE                            0x05
#define HCI_ERR_KEY_MISSING                             0x06
#define HCI_ERR_MEMORY_FULL                             0x07
#define HCI_ERR_CONNECTION_TOUT                         0x08
#define HCI_ERR_MAX_NUM_OF_CONNECTIONS                  0x09
#define HCI_ERR_MAX_NUM_OF_SCOS                         0x0A
#define HCI_ERR_CONNECTION_EXISTS                       0x0B
#define HCI_ERR_COMMAND_DISALLOWED                      0x0C
#define HCI_ERR_HOST_REJECT_RESOURCES                   0x0D
#define HCI_ERR_HOST_REJECT_SECURITY                    0x0E
#define HCI_ERR_HOST_REJECT_DEVICE                      0x0F
#define HCI_ERR_HOST_TIMEOUT                            0x10
#define HCI_ERR_UNSUPPORTED_VALUE                       0x11
#define HCI_ERR_ILLEGAL_PARAMETER_FMT                   0x12
#define HCI_ERR_PEER_USER                               0x13
#define HCI_ERR_PEER_LOW_RESOURCES                      0x14
#define HCI_ERR_PEER_POWER_OFF                          0x15
#define HCI_ERR_CONN_CAUSE_LOCAL_HOST                   0x16
#define HCI_ERR_REPEATED_ATTEMPTS                       0x17
#define HCI_ERR_PAIRING_NOT_ALLOWED                     0x18
#define HCI_ERR_UNKNOWN_LMP_PDU                         0x19
#define HCI_ERR_UNSUPPORTED_REM_FEATURE                 0x1A
#define HCI_ERR_SCO_OFFSET_REJECTED                     0x1B
#define HCI_ERR_SCO_INTERVAL_REJECTED                   0x1C
#define HCI_ERR_SCO_AIR_MODE                            0x1D
#define HCI_ERR_INVALID_LMP_PARAM                       0x1E
#define HCI_ERR_UNSPECIFIED                             0x1F
#define HCI_ERR_UNSUPPORTED_LMP_FEATURE                 0x20
#define HCI_ERR_ROLE_CHANGE_NOT_ALLOWED                 0x21
#define HCI_ERR_LMP_RESPONSE_TIMEOUT                    0x22
#define HCI_ERR_LMP_ERR_TRANS_COLLISION                 0x23
#define HCI_ERR_LMP_PDU_NOT_ALLOWED                     0x24
#define HCI_ERR_ENCRY_MODE_NOT_ACCEPTABLE               0x25
#define HCI_ERR_UNIT_KEY_USED                           0x26
#define HCI_ERR_QOS_NOT_SUPPORTED                       0x27
#define HCI_ERR_INSTANT_PASSED                          0x28
#define HCI_ERR_PAIRING_WITH_UNIT_KEY_NOT_SUPPORTED     0x29
#define HCI_ERR_DIFF_TRANSACTION_COLLISION              0x2A
#define HCI_ERR_UNDEFINED_0x2B                          0x2B
#define HCI_ERR_QOS_UNACCEPTABLE_PARAM                  0x2C
#define HCI_ERR_QOS_REJECTED                            0x2D
#define HCI_ERR_CHAN_CLASSIF_NOT_SUPPORTED              0x2E
#define HCI_ERR_INSUFFCIENT_SECURITY                    0x2F
#define HCI_ERR_PARAM_OUT_OF_RANGE                      0x30
#define HCI_ERR_UNDEFINED_0x31                          0x31
#define HCI_ERR_ROLE_SWITCH_PENDING                     0x32
#define HCI_ERR_UNDEFINED_0x33                          0x33
#define HCI_ERR_RESERVED_SLOT_VIOLATION                 0x34
#define HCI_ERR_ROLE_SWITCH_FAILED                      0x35
#define HCI_ERR_INQ_RSP_DATA_TOO_LARGE                  0x36
#define HCI_ERR_SIMPLE_PAIRING_NOT_SUPPORTED            0x37
#define HCI_ERR_HOST_BUSY_PAIRING                       0x38
#define HCI_ERR_REJ_NO_SUITABLE_CHANNEL                 0x39
#define HCI_ERR_CONTROLLER_BUSY                         0x3A
#define HCI_ERR_UNACCEPT_CONN_INTERVAL                  0x3B
#define HCI_ERR_DIRECTED_ADVERTISING_TIMEOUT            0x3C
#define HCI_ERR_CONN_TOUT_DUE_TO_MIC_FAILURE            0x3D
#define HCI_ERR_CONN_FAILED_ESTABLISHMENT               0x3E
#define HCI_ERR_MAC_CONNECTION_FAILED                   0x3F

/* ConnectionLess Broadcast errors */
#define HCI_ERR_LT_ADDR_ALREADY_IN_USE                  0x40
#define HCI_ERR_LT_ADDR_NOT_ALLOCATED                   0x41
#define HCI_ERR_CLB_NOT_ENABLED                         0x42
#define HCI_ERR_CLB_DATA_TOO_BIG                        0x43

#define HCI_ERR_MAX_ERR                                 0x43

#define HCI_HINT_TO_RECREATE_AMP_PHYS_LINK              0xFF

/*
** Definitions for HCI enable event
*/
#define HCI_INQUIRY_COMPLETE_EV(p)          (*((UINT32 *)(p)) & 0x00000001)
#define HCI_INQUIRY_RESULT_EV(p)            (*((UINT32 *)(p)) & 0x00000002)
#define HCI_CONNECTION_COMPLETE_EV(p)       (*((UINT32 *)(p)) & 0x00000004)
#define HCI_CONNECTION_REQUEST_EV(p)        (*((UINT32 *)(p)) & 0x00000008)
#define HCI_DISCONNECTION_COMPLETE_EV(p)    (*((UINT32 *)(p)) & 0x00000010)
#define HCI_AUTHENTICATION_COMPLETE_EV(p)   (*((UINT32 *)(p)) & 0x00000020)
#define HCI_RMT_NAME_REQUEST_COMPL_EV(p)    (*((UINT32 *)(p)) & 0x00000040)
#define HCI_CHANGE_CONN_ENCRPT_ENABLE_EV(p) (*((UINT32 *)(p)) & 0x00000080)
#define HCI_CHANGE_CONN_LINK_KEY_EV(p)      (*((UINT32 *)(p)) & 0x00000100)
#define HCI_MASTER_LINK_KEY_COMPLETE_EV(p)  (*((UINT32 *)(p)) & 0x00000200)
#define HCI_READ_RMT_FEATURES_COMPL_EV(p)   (*((UINT32 *)(p)) & 0x00000400)
#define HCI_READ_RMT_VERSION_COMPL_EV(p)    (*((UINT32 *)(p)) & 0x00000800)
#define HCI_QOS_SETUP_COMPLETE_EV(p)        (*((UINT32 *)(p)) & 0x00001000)
#define HCI_COMMAND_COMPLETE_EV(p)          (*((UINT32 *)(p)) & 0x00002000)
#define HCI_COMMAND_STATUS_EV(p)            (*((UINT32 *)(p)) & 0x00004000)
#define HCI_HARDWARE_ERROR_EV(p)            (*((UINT32 *)(p)) & 0x00008000)
#define HCI_FLASH_OCCURED_EV(p)             (*((UINT32 *)(p)) & 0x00010000)
#define HCI_ROLE_CHANGE_EV(p)               (*((UINT32 *)(p)) & 0x00020000)
#define HCI_NUM_COMPLETED_PKTS_EV(p)        (*((UINT32 *)(p)) & 0x00040000)
#define HCI_MODE_CHANGE_EV(p)               (*((UINT32 *)(p)) & 0x00080000)
#define HCI_RETURN_LINK_KEYS_EV(p)          (*((UINT32 *)(p)) & 0x00100000)
#define HCI_PIN_CODE_REQUEST_EV(p)          (*((UINT32 *)(p)) & 0x00200000)
#define HCI_LINK_KEY_REQUEST_EV(p)          (*((UINT32 *)(p)) & 0x00400000)
#define HCI_LINK_KEY_NOTIFICATION_EV(p)     (*((UINT32 *)(p)) & 0x00800000)
#define HCI_LOOPBACK_COMMAND_EV(p)          (*((UINT32 *)(p)) & 0x01000000)
#define HCI_DATA_BUF_OVERFLOW_EV(p)         (*((UINT32 *)(p)) & 0x02000000)
#define HCI_MAX_SLOTS_CHANGE_EV(p)          (*((UINT32 *)(p)) & 0x04000000)
#define HCI_READ_CLOCK_OFFSET_COMP_EV(p)    (*((UINT32 *)(p)) & 0x08000000)
#define HCI_CONN_PKT_TYPE_CHANGED_EV(p)     (*((UINT32 *)(p)) & 0x10000000)
#define HCI_QOS_VIOLATION_EV(p)             (*((UINT32 *)(p)) & 0x20000000)
#define HCI_PAGE_SCAN_MODE_CHANGED_EV(p)    (*((UINT32 *)(p)) & 0x40000000)
#define HCI_PAGE_SCAN_REP_MODE_CHNG_EV(p)   (*((UINT32 *)(p)) & 0x80000000)

/* the default event mask for 2.1+EDR (Lisbon) does not include Lisbon events */
#define HCI_DEFAULT_EVENT_MASK_0            0xFFFFFFFF
#define HCI_DEFAULT_EVENT_MASK_1            0x00001FFF

/* the event mask for 2.0 + EDR and later (includes Lisbon events) */
#define HCI_LISBON_EVENT_MASK_0             0xFFFFFFFF
#define HCI_LISBON_EVENT_MASK_1             0x1DBFFFFF
#define HCI_LISBON_EVENT_MASK               "\x0D\xBF\xFF\xFF\xFF\xFF\xFF\xFF"
#define HCI_LISBON_EVENT_MASK_EXT           "\x1D\xBF\xFF\xFF\xFF\xFF\xFF\xFF"
#define HCI_DUMO_EVENT_MASK_EXT             "\x3D\xBF\xFF\xFF\xFF\xFF\xFF\xFF"
/*  0x00001FFF FFFFFFFF Default - no Lisbon events
    0x00000800 00000000 Synchronous Connection Complete Event
    0x00001000 00000000 Synchronous Connection Changed Event
    0x00002000 00000000 Sniff Subrate Event
    0x00004000 00000000 Extended Inquiry Result Event
    0x00008000 00000000 Encryption Key Refresh Complete Event
    0x00010000 00000000 IO Capability Request Event
    0x00020000 00000000 IO Capability Response Event
    0x00040000 00000000 User Confirmation Request Event
    0x00080000 00000000 User Passkey Request Event
    0x00100000 00000000 Remote OOB Data Request Event
    0x00200000 00000000 Simple Pairing Complete Event
    0x00400000 00000000 Generic AMP Link Key Notification Event
    0x00800000 00000000 Link Supervision Timeout Changed Event
    0x01000000 00000000 Enhanced Flush Complete Event
    0x04000000 00000000 User Passkey Notification Event
    0x08000000 00000000 Keypress Notification Event
    0x10000000 00000000 Remote Host Supported Features Notification Event
    0x20000000 00000000 LE Meta Event
 */


/* the event mask for AMP controllers */
#define HCI_AMP_EVENT_MASK_3_0               "\x00\x00\x00\x00\x00\x00\x3F\xFF"

/*  0x0000000000000000 No events specified (default)
    0x0000000000000001 Physical Link Complete Event
    0x0000000000000002 Channel Selected Event
    0x0000000000000004 Disconnection Physical Link Event
    0x0000000000000008 Physical Link Loss Early Warning Event
    0x0000000000000010 Physical Link Recovery Event
    0x0000000000000020 Logical Link Complete Event
    0x0000000000000040 Disconnection Logical Link Complete Event
    0x0000000000000080 Flow Spec Modify Complete Event
    0x0000000000000100 Number of Completed Data Blocks Event
    0x0000000000000200 AMP Start Test Event
    0x0000000000000400 AMP Test End Event
    0x0000000000000800 AMP Receiver Report Event
    0x0000000000001000 Short Range Mode Change Complete Event
    0x0000000000002000 AMP Status Change Event
*/

/* the event mask page 2 (CLB + CSA4) for BR/EDR controller */
#define HCI_PAGE_2_EVENT_MASK                  "\x00\x00\x00\x00\x00\x7F\xC0\x00"
/*  0x0000000000004000 Triggered Clock Capture Event
    0x0000000000008000 Sync Train Complete Event
    0x0000000000010000 Sync Train Received Event
    0x0000000000020000 Connectionless Broadcast Receive Event
    0x0000000000040000 Connectionless Broadcast Timeout Event
    0x0000000000080000 Truncated Page Complete Event
    0x0000000000100000 Salve Page Response Timeout Event
    0x0000000000200000 Connectionless Broadcast Channel Map Change Event
    0x0000000000400000 Inquiry Response Notification Event
*/

/*
** Definitions for packet type masks (BT1.2 and BT2.0 definitions)
*/
#define HCI_PKT_TYPES_MASK_NO_2_DH1         0x0002
#define HCI_PKT_TYPES_MASK_NO_3_DH1         0x0004
#define HCI_PKT_TYPES_MASK_DM1              0x0008
#define HCI_PKT_TYPES_MASK_DH1              0x0010
#define HCI_PKT_TYPES_MASK_HV1              0x0020
#define HCI_PKT_TYPES_MASK_HV2              0x0040
#define HCI_PKT_TYPES_MASK_HV3              0x0080
#define HCI_PKT_TYPES_MASK_NO_2_DH3         0x0100
#define HCI_PKT_TYPES_MASK_NO_3_DH3         0x0200
#define HCI_PKT_TYPES_MASK_DM3              0x0400
#define HCI_PKT_TYPES_MASK_DH3              0x0800
#define HCI_PKT_TYPES_MASK_NO_2_DH5         0x1000
#define HCI_PKT_TYPES_MASK_NO_3_DH5         0x2000
#define HCI_PKT_TYPES_MASK_DM5              0x4000
#define HCI_PKT_TYPES_MASK_DH5              0x8000

/* Packet type should be one of valid but at least one should be specified */
#define HCI_VALID_SCO_PKT_TYPE(t) (((((t) & ~(HCI_PKT_TYPES_MASK_HV1       \
                                           |  HCI_PKT_TYPES_MASK_HV2       \
                                           |  HCI_PKT_TYPES_MASK_HV3)) == 0)) \
                                    && ((t) != 0))





/* Packet type should not be invalid and at least one should be specified */
#define HCI_VALID_ACL_PKT_TYPE(t) (((((t) & ~(HCI_PKT_TYPES_MASK_DM1        \
                                           |  HCI_PKT_TYPES_MASK_DH1        \
                                           |  HCI_PKT_TYPES_MASK_DM3        \
                                           |  HCI_PKT_TYPES_MASK_DH3        \
                                           |  HCI_PKT_TYPES_MASK_DM5        \
                                           |  HCI_PKT_TYPES_MASK_DH5        \
                                           |  HCI_PKT_TYPES_MASK_NO_2_DH1   \
                                           |  HCI_PKT_TYPES_MASK_NO_3_DH1   \
                                           |  HCI_PKT_TYPES_MASK_NO_2_DH3   \
                                           |  HCI_PKT_TYPES_MASK_NO_3_DH3   \
                                           |  HCI_PKT_TYPES_MASK_NO_2_DH5   \
                                           |  HCI_PKT_TYPES_MASK_NO_3_DH5  )) == 0)) \
                                    && (((t) &  (HCI_PKT_TYPES_MASK_DM1        \
                                              |  HCI_PKT_TYPES_MASK_DH1        \
                                              |  HCI_PKT_TYPES_MASK_DM3        \
                                              |  HCI_PKT_TYPES_MASK_DH3        \
                                              |  HCI_PKT_TYPES_MASK_DM5        \
                                              |  HCI_PKT_TYPES_MASK_DH5)) != 0))

/*
** Definitions for eSCO packet type masks (BT1.2 and BT2.0 definitions)
*/
#define HCI_ESCO_PKT_TYPES_MASK_HV1         0x0001
#define HCI_ESCO_PKT_TYPES_MASK_HV2         0x0002
#define HCI_ESCO_PKT_TYPES_MASK_HV3         0x0004
#define HCI_ESCO_PKT_TYPES_MASK_EV3         0x0008
#define HCI_ESCO_PKT_TYPES_MASK_EV4         0x0010
#define HCI_ESCO_PKT_TYPES_MASK_EV5         0x0020
#define HCI_ESCO_PKT_TYPES_MASK_NO_2_EV3    0x0040
#define HCI_ESCO_PKT_TYPES_MASK_NO_3_EV3    0x0080
#define HCI_ESCO_PKT_TYPES_MASK_NO_2_EV5    0x0100
#define HCI_ESCO_PKT_TYPES_MASK_NO_3_EV5    0x0200

/* Packet type should be one of valid but at least one should be specified for 1.2 */
#define HCI_VALID_ESCO_PKT_TYPE(t) (((((t) & ~(HCI_ESCO_PKT_TYPES_MASK_EV3       \
                                           |   HCI_ESCO_PKT_TYPES_MASK_EV4       \
                                           |   HCI_ESCO_PKT_TYPES_MASK_EV5)) == 0)) \
                                    && ((t) != 0))/* Packet type should be one of valid but at least one should be specified */

#define HCI_VALID_ESCO_SCOPKT_TYPE(t) (((((t) & ~(HCI_ESCO_PKT_TYPES_MASK_HV1       \
                                           |      HCI_ESCO_PKT_TYPES_MASK_HV2       \
                                           |      HCI_ESCO_PKT_TYPES_MASK_HV3)) == 0)) \
                                    && ((t) != 0))

#define HCI_VALID_SCO_ALL_PKT_TYPE(t) (((((t) & ~(HCI_ESCO_PKT_TYPES_MASK_HV1       \
                                           |      HCI_ESCO_PKT_TYPES_MASK_HV2       \
                                           |      HCI_ESCO_PKT_TYPES_MASK_HV3       \
                                           |      HCI_ESCO_PKT_TYPES_MASK_EV3       \
                                           |      HCI_ESCO_PKT_TYPES_MASK_EV4       \
                                           |      HCI_ESCO_PKT_TYPES_MASK_EV5)) == 0)) \
                                    && ((t) != 0))

/*
** Define parameters to allow role switch during create connection
*/
#define HCI_CR_CONN_NOT_ALLOW_SWITCH    0x00
#define HCI_CR_CONN_ALLOW_SWITCH        0x01

/*
** Hold Mode command destination
*/
#define HOLD_MODE_DEST_LOCAL_DEVICE     0x00
#define HOLD_MODE_DEST_RMT_DEVICE       0x01

/*
**  Definitions for different HCI parameters
*/
#define HCI_PER_INQ_MIN_MAX_PERIOD      0x0003
#define HCI_PER_INQ_MAX_MAX_PERIOD      0xFFFF
#define HCI_PER_INQ_MIN_MIN_PERIOD      0x0002
#define HCI_PER_INQ_MAX_MIN_PERIOD      0xFFFE

#define HCI_MAX_INQUIRY_LENGTH          0x30

#define HCI_MIN_INQ_LAP                 0x9E8B00
#define HCI_MAX_INQ_LAP                 0x9E8B3F

/* HCI role defenitions */
#define HCI_ROLE_MASTER                 0x00
#define HCI_ROLE_SLAVE                  0x01
#define HCI_ROLE_UNKNOWN                0xff

/* HCI mode defenitions */
#define HCI_MODE_ACTIVE                 0x00
#define HCI_MODE_HOLD                   0x01
#define HCI_MODE_SNIFF                  0x02
#define HCI_MODE_PARK                   0x03

/* HCI Flow Control Mode defenitions */
#define HCI_PACKET_BASED_FC_MODE        0x00
#define HCI_BLOCK_BASED_FC_MODE         0x01

/* Define Packet types as requested by the Host */
#define HCI_ACL_PKT_TYPE_NONE           0x0000
#define HCI_ACL_PKT_TYPE_DM1            0x0008
#define HCI_ACL_PKT_TYPE_DH1            0x0010
#define HCI_ACL_PKT_TYPE_AUX1           0x0200
#define HCI_ACL_PKT_TYPE_DM3            0x0400
#define HCI_ACL_PKT_TYPE_DH3            0x0800
#define HCI_ACL_PKT_TYPE_DM5            0x4000
#define HCI_ACL_PKT_TYPE_DH5            0x8000

/* Define key type in the Master Link Key command */
#define HCI_USE_SEMI_PERMANENT_KEY      0x00
#define HCI_USE_TEMPORARY_KEY           0x01

/* Page scan period modes */
#define HCI_PAGE_SCAN_REP_MODE_R0       0x00
#define HCI_PAGE_SCAN_REP_MODE_R1       0x01
#define HCI_PAGE_SCAN_REP_MODE_R2       0x02

/* Define limits for page scan repetition modes */
#define HCI_PAGE_SCAN_R1_LIMIT          0x0800
#define HCI_PAGE_SCAN_R2_LIMIT          0x1000

/* Page scan period modes */
#define HCI_PAGE_SCAN_PER_MODE_P0       0x00
#define HCI_PAGE_SCAN_PER_MODE_P1       0x01
#define HCI_PAGE_SCAN_PER_MODE_P2       0x02

/* Page scan modes */
#define HCI_MANDATARY_PAGE_SCAN_MODE    0x00
#define HCI_OPTIONAL_PAGE_SCAN_MODE1    0x01
#define HCI_OPTIONAL_PAGE_SCAN_MODE2    0x02
#define HCI_OPTIONAL_PAGE_SCAN_MODE3    0x03

/* Page and inquiry scan types */
#define HCI_SCAN_TYPE_STANDARD          0x00
#define HCI_SCAN_TYPE_INTERLACED        0x01       /* 1.2 devices or later */
#define HCI_DEF_SCAN_TYPE               HCI_SCAN_TYPE_STANDARD

/* Definitions for quality of service service types */
#define HCI_SERVICE_NO_TRAFFIC          0x00
#define HCI_SERVICE_BEST_EFFORT         0x01
#define HCI_SERVICE_GUARANTEED          0x02

#define HCI_QOS_LATENCY_DO_NOT_CARE     0xFFFFFFFF
#define HCI_QOS_DELAY_DO_NOT_CARE       0xFFFFFFFF

/* Definitions for Flow Specification */
#define HCI_FLOW_SPEC_LATENCY_DO_NOT_CARE 0xFFFFFFFF

/* Definitions for AFH Channel Map */
#define HCI_AFH_CHANNEL_MAP_LEN         10

/* Definitions for Extended Inquiry Response */
#define HCI_EXT_INQ_RESPONSE_LEN        240
#define HCI_EIR_FLAGS_TYPE                   BT_EIR_FLAGS_TYPE
#define HCI_EIR_MORE_16BITS_UUID_TYPE        BT_EIR_MORE_16BITS_UUID_TYPE
#define HCI_EIR_COMPLETE_16BITS_UUID_TYPE    BT_EIR_COMPLETE_16BITS_UUID_TYPE
#define HCI_EIR_MORE_32BITS_UUID_TYPE        BT_EIR_MORE_32BITS_UUID_TYPE
#define HCI_EIR_COMPLETE_32BITS_UUID_TYPE    BT_EIR_COMPLETE_32BITS_UUID_TYPE
#define HCI_EIR_MORE_128BITS_UUID_TYPE       BT_EIR_MORE_128BITS_UUID_TYPE
#define HCI_EIR_COMPLETE_128BITS_UUID_TYPE   BT_EIR_COMPLETE_128BITS_UUID_TYPE
#define HCI_EIR_SHORTENED_LOCAL_NAME_TYPE    BT_EIR_SHORTENED_LOCAL_NAME_TYPE
#define HCI_EIR_COMPLETE_LOCAL_NAME_TYPE     BT_EIR_COMPLETE_LOCAL_NAME_TYPE
#define HCI_EIR_TX_POWER_LEVEL_TYPE          BT_EIR_TX_POWER_LEVEL_TYPE
#define HCI_EIR_MANUFACTURER_SPECIFIC_TYPE   BT_EIR_MANUFACTURER_SPECIFIC_TYPE
#define HCI_EIR_OOB_BD_ADDR_TYPE             BT_EIR_OOB_BD_ADDR_TYPE
#define HCI_EIR_OOB_COD_TYPE                 BT_EIR_OOB_COD_TYPE
#define HCI_EIR_OOB_SSP_HASH_C_TYPE          BT_EIR_OOB_SSP_HASH_C_TYPE
#define HCI_EIR_OOB_SSP_RAND_R_TYPE          BT_EIR_OOB_SSP_RAND_R_TYPE

/* Definitions for Write Simple Pairing Mode */
#define HCI_SP_MODE_UNDEFINED           0x00
#define HCI_SP_MODE_ENABLED             0x01

/* Definitions for Write Simple Pairing Debug Mode */
#define HCI_SPD_MODE_DISABLED           0x00
#define HCI_SPD_MODE_ENABLED            0x01

/* Definitions for IO Capability Response/Command */
#define HCI_IO_CAP_DISPLAY_ONLY         0x00
#define HCI_IO_CAP_DISPLAY_YESNO        0x01
#define HCI_IO_CAP_KEYBOARD_ONLY        0x02
#define HCI_IO_CAP_NO_IO                0x03

#define HCI_OOB_AUTH_DATA_NOT_PRESENT   0x00
#define HCI_OOB_REM_AUTH_DATA_PRESENT   0x01

#define HCI_MITM_PROTECT_NOT_REQUIRED  0x00
#define HCI_MITM_PROTECT_REQUIRED      0x01


/* Policy settings status */
#define HCI_DISABLE_ALL_LM_MODES        0x0000
#define HCI_ENABLE_MASTER_SLAVE_SWITCH  0x0001
#define HCI_ENABLE_HOLD_MODE            0x0002
#define HCI_ENABLE_SNIFF_MODE           0x0004
#define HCI_ENABLE_PARK_MODE            0x0008

/* By default allow switch, because host can not allow that */
/* that until he created the connection */
#define HCI_DEFAULT_POLICY_SETTINGS     HCI_DISABLE_ALL_LM_MODES

/* Filters that are sent in set filter command */
#define HCI_FILTER_TYPE_CLEAR_ALL       0x00
#define HCI_FILTER_INQUIRY_RESULT       0x01
#define HCI_FILTER_CONNECTION_SETUP     0x02

#define HCI_FILTER_COND_NEW_DEVICE      0x00
#define HCI_FILTER_COND_DEVICE_CLASS    0x01
#define HCI_FILTER_COND_BD_ADDR         0x02

#define HCI_DO_NOT_AUTO_ACCEPT_CONNECT  1
#define HCI_DO_AUTO_ACCEPT_CONNECT      2   /* role switch disabled */
#define HCI_DO_AUTO_ACCEPT_CONNECT_RS   3   /* role switch enabled (1.1 errata 1115) */

/* Auto accept flags */
#define HCI_AUTO_ACCEPT_OFF             0x00
#define HCI_AUTO_ACCEPT_ACL_CONNECTIONS 0x01
#define HCI_AUTO_ACCEPT_SCO_CONNECTIONS 0x02

/* PIN type */
#define HCI_PIN_TYPE_VARIABLE           0
#define HCI_PIN_TYPE_FIXED              1

/* Loopback Modes */
#define HCI_LOOPBACK_MODE_DISABLED      0
#define HCI_LOOPBACK_MODE_LOCAL         1
#define HCI_LOOPBACK_MODE_REMOTE        2

#define SLOTS_PER_10MS                  16      /* 0.625 ms slots in a 10 ms tick */

/* Maximum connection accept timeout in 0.625msec */
#define HCI_MAX_CONN_ACCEPT_TOUT        0xB540  /* 29 sec */
#define HCI_DEF_CONN_ACCEPT_TOUT        0x1F40  /* 5 sec */

/* Page timeout is used in LC only and LC is counting down slots not using OS */
#define HCI_DEFAULT_PAGE_TOUT           0x2000  /* 5.12 sec (in slots) */

/* Scan enable flags */
#define HCI_NO_SCAN_ENABLED             0x00
#define HCI_INQUIRY_SCAN_ENABLED        0x01
#define HCI_PAGE_SCAN_ENABLED           0x02

/* Pagescan timer definitions in 0.625 ms */
#define HCI_MIN_PAGESCAN_INTERVAL       0x12    /* 11.25 ms */
#define HCI_MAX_PAGESCAN_INTERVAL       0x1000  /* 2.56 sec */
#define HCI_DEF_PAGESCAN_INTERVAL       0x0800  /* 1.28 sec */

/* Parameter for pagescan window is passed to LC and is kept in slots */
#define HCI_MIN_PAGESCAN_WINDOW         0x11    /* 10.625 ms */
#define HCI_MAX_PAGESCAN_WINDOW         0x1000  /* 2.56  sec */
#define HCI_DEF_PAGESCAN_WINDOW         0x12    /* 11.25 ms  */

/* Inquiryscan timer definitions in 0.625 ms */
#define HCI_MIN_INQUIRYSCAN_INTERVAL    0x12    /* 11.25 ms */
#define HCI_MAX_INQUIRYSCAN_INTERVAL    0x1000  /* 2.56 sec */
#define HCI_DEF_INQUIRYSCAN_INTERVAL    0x1000  /* 2.56 sec */

/* Parameter for inquiryscan window is passed to LC and is kept in slots */
#define HCI_MIN_INQUIRYSCAN_WINDOW      0x11    /* 10.625 ms */
#define HCI_MAX_INQUIRYSCAN_WINDOW      0x1000  /* 2.56 sec */
#define HCI_DEF_INQUIRYSCAN_WINDOW      0x12    /* 11.25 ms */

/* Encryption modes */
#define HCI_ENCRYPT_MODE_DISABLED       0x00
#define HCI_ENCRYPT_MODE_POINT_TO_POINT 0x01
#define HCI_ENCRYPT_MODE_ALL            0x02

/* Voice settings */
#define HCI_INP_CODING_LINEAR           0x0000 /* 0000000000 */
#define HCI_INP_CODING_U_LAW            0x0100 /* 0100000000 */
#define HCI_INP_CODING_A_LAW            0x0200 /* 1000000000 */
#define HCI_INP_CODING_MASK             0x0300 /* 1100000000 */

#define HCI_INP_DATA_FMT_1S_COMPLEMENT  0x0000 /* 0000000000 */
#define HCI_INP_DATA_FMT_2S_COMPLEMENT  0x0040 /* 0001000000 */
#define HCI_INP_DATA_FMT_SIGN_MAGNITUDE 0x0080 /* 0010000000 */
#define HCI_INP_DATA_FMT_UNSIGNED       0x00c0 /* 0011000000 */
#define HCI_INP_DATA_FMT_MASK           0x00c0 /* 0011000000 */

#define HCI_INP_SAMPLE_SIZE_8BIT        0x0000 /* 0000000000 */
#define HCI_INP_SAMPLE_SIZE_16BIT       0x0020 /* 0000100000 */
#define HCI_INP_SAMPLE_SIZE_MASK        0x0020 /* 0000100000 */

#define HCI_INP_LINEAR_PCM_BIT_POS_MASK 0x001c /* 0000011100 */
#define HCI_INP_LINEAR_PCM_BIT_POS_OFFS 2

#define HCI_AIR_CODING_FORMAT_CVSD      0x0000 /* 0000000000 */
#define HCI_AIR_CODING_FORMAT_U_LAW     0x0001 /* 0000000001 */
#define HCI_AIR_CODING_FORMAT_A_LAW     0x0002 /* 0000000010 */
#define HCI_AIR_CODING_FORMAT_TRANSPNT  0x0003 /* 0000000011 */
#define HCI_AIR_CODING_FORMAT_MASK      0x0003 /* 0000000011 */

/* default                                        0001100000 */
#define HCI_DEFAULT_VOICE_SETTINGS    (HCI_INP_CODING_LINEAR \
                                     | HCI_INP_DATA_FMT_2S_COMPLEMENT \
                                     | HCI_INP_SAMPLE_SIZE_16BIT \
                                     | HCI_AIR_CODING_FORMAT_CVSD)

#define HCI_CVSD_SUPPORTED(x)       (((x) & HCI_AIR_CODING_FORMAT_MASK) == HCI_AIR_CODING_FORMAT_CVSD)
#define HCI_U_LAW_SUPPORTED(x)      (((x) & HCI_AIR_CODING_FORMAT_MASK) == HCI_AIR_CODING_FORMAT_U_LAW)
#define HCI_A_LAW_SUPPORTED(x)      (((x) & HCI_AIR_CODING_FORMAT_MASK) == HCI_AIR_CODING_FORMAT_A_LAW)
#define HCI_TRANSPNT_SUPPORTED(x)   (((x) & HCI_AIR_CODING_FORMAT_MASK) == HCI_AIR_CODING_FORMAT_TRANSPNT)

/* Retransmit timer definitions in 0.625 */
#define HCI_MAX_AUTO_FLUSH_TOUT         0x07FF
#define HCI_DEFAULT_AUTO_FLUSH_TOUT     0       /* No auto flush */

/* Broadcast retransmitions */
#define HCI_DEFAULT_NUM_BCAST_RETRAN    1

/* Define broadcast data types as passed in the hci data packet */
#define HCI_DATA_POINT_TO_POINT         0x00
#define HCI_DATA_ACTIVE_BCAST           0x01
#define HCI_DATA_PICONET_BCAST          0x02

/* Hold mode activity */
#define HCI_MAINTAIN_CUR_POWER_STATE    0x00
#define HCI_SUSPEND_PAGE_SCAN           0x01
#define HCI_SUSPEND_INQUIRY_SCAN        0x02
#define HCI_SUSPEND_PERIODIC_INQUIRIES  0x04

/* Default Link Supervision timeoout */
#define HCI_DEFAULT_INACT_TOUT          0x7D00  /* BR/EDR (20 seconds) */
#define HCI_DEFAULT_AMP_INACT_TOUT      0x3E80  /* AMP    (10 seconds) */

/* Read transmit power level parameter */
#define HCI_READ_CURRENT                0x00
#define HCI_READ_MAXIMUM                0x01

/* Link types for connection complete event */
#define HCI_LINK_TYPE_SCO               0x00
#define HCI_LINK_TYPE_ACL               0x01
#define HCI_LINK_TYPE_ESCO              0x02

/* Link Key Notification Event (Key Type) definitions */
#define HCI_LKEY_TYPE_COMBINATION       0x00
#define HCI_LKEY_TYPE_LOCAL_UNIT        0x01
#define HCI_LKEY_TYPE_REMOTE_UNIT       0x02
#define HCI_LKEY_TYPE_DEBUG_COMB        0x03
#define HCI_LKEY_TYPE_UNAUTH_COMB       0x04
#define HCI_LKEY_TYPE_AUTH_COMB         0x05
#define HCI_LKEY_TYPE_CHANGED_COMB      0x06

/* Internal definitions - not used over HCI */
#define HCI_LKEY_TYPE_AMP_WIFI          0x80
#define HCI_LKEY_TYPE_AMP_UWB           0x81
#define HCI_LKEY_TYPE_UNKNOWN           0xff

/* Read Local Version HCI Version return values (Command Complete Event) */
#define HCI_VERSION_1_0B                0x00
#define HCI_VERSION_1_1                 0x01

/* Define an invalid value for a handle */
#define HCI_INVALID_HANDLE              0xFFFF

/* Define max ammount of data in the HCI command */
#define HCI_COMMAND_SIZE        255

/* Define the preamble length for all HCI Commands.
** This is 2-bytes for opcode and 1 byte for length
*/
#define HCIC_PREAMBLE_SIZE      3

/* Define the preamble length for all HCI Events
** This is 1-byte for opcode and 1 byte for length
*/
#define HCIE_PREAMBLE_SIZE      2
#define HCI_SCO_PREAMBLE_SIZE   3
#define HCI_DATA_PREAMBLE_SIZE  4

/* local Bluetooth controller id for AMP HCI */
#define LOCAL_BR_EDR_CONTROLLER_ID      0

/* controller id types for AMP HCI */
#define HCI_CONTROLLER_TYPE_BR_EDR      0
#define HCI_CONTROLLER_TYPE_802_11      1
#define HCI_CONTROLLER_TYPE_ECMA        2
#define HCI_MAX_CONTROLLER_TYPES        3

/*  ConnectionLess Broadcast */
#define HCI_CLB_DISABLE                 0x00
#define HCI_CLB_ENABLE                  0x01

/* ConnectionLess Broadcast Data fragment */
#define HCI_CLB_FRAGMENT_CONT           0x00
#define HCI_CLB_FRAGMENT_START          0x01
#define HCI_CLB_FRAGMENT_END            0x02
#define HCI_CLB_FRAGMENT_SINGLE         0x03

/* AMP Controller Status codes
*/
#define HCI_AMP_CTRLR_PHYSICALLY_DOWN   0
#define HCI_AMP_CTRLR_USABLE_BY_BT      1
#define HCI_AMP_CTRLR_UNUSABLE_FOR_BT   2
#define HCI_AMP_CTRLR_LOW_CAP_FOR_BT    3
#define HCI_AMP_CTRLR_MED_CAP_FOR_BT    4
#define HCI_AMP_CTRLR_HIGH_CAP_FOR_BT   5
#define HCI_AMP_CTRLR_FULL_CAP_FOR_BT   6

#define HCI_MAX_AMP_STATUS_TYPES        7


/* Define the extended flow specification fields used by AMP */
typedef struct
{
    UINT8       id;
    UINT8       stype;
    UINT16      max_sdu_size;
    UINT32      sdu_inter_time;
    UINT32      access_latency;
    UINT32      flush_timeout;
} tHCI_EXT_FLOW_SPEC;


/* HCI message type definitions (for H4 messages) */
#define HCIT_TYPE_COMMAND   1
#define HCIT_TYPE_ACL_DATA  2
#define HCIT_TYPE_SCO_DATA  3
#define HCIT_TYPE_EVENT     4
#define HCIT_TYPE_LM_DIAG   7
#define HCIT_TYPE_NFC       16

#define HCIT_LM_DIAG_LENGTH 63

/* Parameter information for HCI_BRCM_SET_ACL_PRIORITY */
#define HCI_BRCM_ACL_PRIORITY_PARAM_SIZE    3
#define HCI_BRCM_ACL_PRIORITY_LOW           0x00
#define HCI_BRCM_ACL_PRIORITY_HIGH          0xFF
#define HCI_BRCM_SET_ACL_PRIORITY           (0x0057 | HCI_GRP_VENDOR_SPECIFIC)

/* Define values for LMP Test Control parameters
** Test Scenario, Hopping Mode, Power Control Mode
*/
#define LMP_TESTCTL_TESTSC_PAUSE        0
#define LMP_TESTCTL_TESTSC_TXTEST_0     1
#define LMP_TESTCTL_TESTSC_TXTEST_1     2
#define LMP_TESTCTL_TESTSC_TXTEST_1010  3
#define LMP_TESTCTL_TESTSC_PSRND_BITSEQ 4
#define LMP_TESTCTL_TESTSC_CLOSEDLB_ACL 5
#define LMP_TESTCTL_TESTSC_CLOSEDLB_SCO 6
#define LMP_TESTCTL_TESTSC_ACL_NOWHIT   7
#define LMP_TESTCTL_TESTSC_SCO_NOWHIT   8
#define LMP_TESTCTL_TESTSC_TXTEST_11110000  9
#define LMP_TESTCTL_TESTSC_EXITTESTMODE 255

#define LMP_TESTCTL_HOPMOD_RXTX1FREQ    0
#define LMP_TESTCTL_HOPMOD_HOP_EURUSA   1
#define LMP_TESTCTL_HOPMOD_HOP_JAPAN    2
#define LMP_TESTCTL_HOPMOD_HOP_FRANCE   3
#define LMP_TESTCTL_HOPMOD_HOP_SPAIN    4
#define LMP_TESTCTL_HOPMOD_REDUCED_HOP  5

#define LMP_TESTCTL_POWCTL_FIXEDTX_OP   0
#define LMP_TESTCTL_POWCTL_ADAPTIVE     1


/*
** Define company IDs (from Bluetooth Assigned Numbers v1.1, section 2.2)
*/
#define LMP_COMPID_ERICSSON             0
#define LMP_COMPID_NOKIA                1
#define LMP_COMPID_INTEL                2
#define LMP_COMPID_IBM                  3
#define LMP_COMPID_TOSHIBA              4
#define LMP_COMPID_3COM                 5
#define LMP_COMPID_MICROSOFT            6
#define LMP_COMPID_LUCENT               7
#define LMP_COMPID_MOTOROLA             8
#define LMP_COMPID_INFINEON             9
#define LMP_COMPID_CSR                  10
#define LMP_COMPID_SILICON_WAVE         11
#define LMP_COMPID_DIGIANSWER           12
#define LMP_COMPID_TEXAS_INSTRUMENTS    13
#define LMP_COMPID_PARTHUS              14
#define LMP_COMPID_BROADCOM             15
#define LMP_COMPID_MITEL_SEMI           16
#define LMP_COMPID_WIDCOMM              17
#define LMP_COMPID_ZEEVO                18
#define LMP_COMPID_ATMEL                19
#define LMP_COMPID_MITSUBISHI           20
#define LMP_COMPID_RTX_TELECOM          21
#define LMP_COMPID_KC_TECH              22
#define LMP_COMPID_NEWLOGIC             23
#define LMP_COMPID_TRANSILICA           24
#define LMP_COMPID_ROHDE_SCHWARZ        25
#define LMP_COMPID_TTPCOM               26
#define LMP_COMPID_SIGNIA               27
#define LMP_COMPID_CONEXANT             28
#define LMP_COMPID_QUALCOMM             29
#define LMP_COMPID_INVENTEL             30
#define LMP_COMPID_AVM                  31
#define LMP_COMPID_BANDSPEED            32
#define LMP_COMPID_MANSELLA             33
#define LMP_COMPID_NEC_CORP             34
#define LMP_COMPID_WAVEPLUS             35
#define LMP_COMPID_ALCATEL              36
#define LMP_COMPID_PHILIPS              37
#define LMP_COMPID_C_TECHNOLOGIES       38
#define LMP_COMPID_OPEN_INTERFACE       39
#define LMP_COMPID_RF_MICRO             40
#define LMP_COMPID_HITACHI              41
#define LMP_COMPID_SYMBOL_TECH          42
#define LMP_COMPID_TENOVIS              43
#define LMP_COMPID_MACRONIX             44
#define LMP_COMPID_GCT_SEMI             45
#define LMP_COMPID_NORWOOD_SYSTEMS      46
#define LMP_COMPID_MEWTEL_TECH          47
#define LMP_COMPID_STM                  48
#define LMP_COMPID_SYNOPSYS             49
#define LMP_COMPID_RED_M_LTD            50
#define LMP_COMPID_COMMIL_LTD           51
#define LMP_COMPID_CATC                 52
#define LMP_COMPID_ECLIPSE              53
#define LMP_COMPID_RENESAS_TECH         54
#define LMP_COMPID_MOBILIAN_CORP        55
#define LMP_COMPID_TERAX                56
#define LMP_COMPID_ISSC                 57
#define LMP_COMPID_MATSUSHITA           58
#define LMP_COMPID_GENNUM_CORP          59
#define LMP_COMPID_RESEARCH_IN_MOTION   60
#define LMP_COMPID_IPEXTREME            61
#define LMP_COMPID_SYSTEMS_AND_CHIPS    62
#define LMP_COMPID_BLUETOOTH_SIG        63
#define LMP_COMPID_SEIKO_EPSON_CORP     64
#define LMP_COMPID_ISS_TAIWAN           65
#define LMP_COMPID_CONWISE_TECHNOLOGIES 66
#define LMP_COMPID_PARROT_SA            67
#define LMP_COMPID_SOCKET_COMM          68
#define LMP_COMPID_ALTHEROS             69
#define LMP_COMPID_MEDIATEK             70
#define LMP_COMPID_BLUEGIGA             71
#define LMP_COMPID_MARVELL              72
#define LMP_COMPID_3DSP_CORP            73
#define LMP_COMPID_ACCEL_SEMICONDUCTOR  74
#define LMP_COMPID_CONTINENTAL_AUTO     75
#define LMP_COMPID_APPLE                76
#define LMP_COMPID_STACCATO             77
#define LMP_COMPID_AVAGO_TECHNOLOGIES   78
#define LMP_COMPID_APT_LTD              79
#define LMP_COMPID_SIRF_TECHNOLOGY      80
#define LMP_COMPID_TZERO_TECHNOLOGY     81
#define LMP_COMPID_J_AND_M_CORP         82
#define LMP_COMPID_FREE_2_MOVE          83
#define LMP_COMPID_3DIJOY_CORP          84
#define LMP_COMPID_PLANTRONICS          85
#define LMP_COMPID_SONY_ERICSSON_MOBILE 86
#define LMP_COMPID_HARMON_INTL_IND      87
#define LMP_COMPID_VIZIO                88
#define LMP_COMPID_NORDIC SEMI          89
#define LMP_COMPID_EM MICRO             90
#define LMP_COMPID_RALINK TECH          91
#define LMP_COMPID_BELKIN INC           92
#define LMP_COMPID_REALTEK SEMI         93
#define LMP_COMPID_STONESTREET ONE      94
#define LMP_COMPID_WICENTRIC            95
#define LMP_COMPID_RIVIERAWAVES         96
#define LMP_COMPID_RDA MICRO            97
#define LMP_COMPID_GIBSON GUITARS       98
#define LMP_COMPID_MICOMMAND INC        99
#define LMP_COMPID_BAND XI              100
#define LMP_COMPID_HP COMPANY           101
#define LMP_COMPID_9SOLUTIONS OY        102
#define LMP_COMPID_GN NETCOM            103
#define LMP_COMPID_GENERAL MOTORS       104
#define LMP_COMPID_AD ENGINEERING       105
#define LMP_COMPID_MINDTREE LTD         106
#define LMP_COMPID_POLAR ELECTRO        107
#define LMP_COMPID_BEAUTIFUL ENTERPRISE 108
#define LMP_COMPID_BRIARTEK             109
#define LMP_COMPID_SUMMIT DATA COMM     110
#define LMP_COMPID_SOUND ID             111
#define LMP_COMPID_MONSTER LLC          112
#define LMP_COMPID_CONNECTBLU           113

#define LMP_COMPID_SHANGHAI_SSE         114
#define LMP_COMPID_GROUP_SENSE          115
#define LMP_COMPID_ZOMM                 116
#define LMP_COMPID_SAMSUNG              117
#define LMP_COMPID_CREATIVE_TECH        118
#define LMP_COMPID_LAIRD_TECH           119
#define LMP_COMPID_NIKE                 120
#define LMP_COMPID_LESSWIRE             121
#define LMP_COMPID_MSTAR_SEMI           122
#define LMP_COMPID_HANLYNN_TECH         123
#define LMP_COMPID_AR_CAMBRIDGE         124
#define LMP_COMPID_SEERS_TECH           125
#define LMP_COMPID_SPORTS_TRACKING      126
#define LMP_COMPID_AUTONET_MOBILE       127
#define LMP_COMPID_DELORME_PUBLISH      128
#define LMP_COMPID_WUXI_VIMICRO         129
#define LMP_COMPID_SENNHEISER           130
#define LMP_COMPID_TIME_KEEPING_SYS     131
#define LMP_COMPID_LUDUS_HELSINKI       132
#define LMP_COMPID_BLUE_RADIOS          133
#define LMP_COMPID_EQUINUX              134
#define LMP_COMPID_GARMIN_INTL          135
#define LMP_COMPID_ECOTEST              136
#define LMP_COMPID_GN_RESOUND           137
#define LMP_COMPID_JAWBONE              138
#define LMP_COMPID_TOPCON_POSITIONING   139
#define LMP_COMPID_QUALCOMM_LABS        140
#define LMP_COMPID_ZSCAN_SOFTWARE       141
#define LMP_COMPID_QUINTIC              142
#define LMP_COMPID_STOLLMAN_EV          143
#define LMP_COMPID_FUNAI_ELECTRONIC     144
#define LMP_COMPID_ADV_PANMOBILE        145
#define LMP_COMPID_THINK_OPTICS         146
#define LMP_COMPID_UNIVERSAL_ELEC       147
#define LMP_COMPID_AIROHA_TECH          148
#define LMP_COMPID_MAX_ID               149 /* this is a place holder */
#define LMP_COMPID_INTERNAL             65535

#define MAX_LMP_COMPID                  (LMP_COMPID_MAX_ID)
/*
** Define the packet types in the packet header, and a couple extra
*/
#define PKT_TYPE_NULL   0x00
#define PKT_TYPE_POLL   0x01
#define PKT_TYPE_FHS    0x02
#define PKT_TYPE_DM1    0x03

#define PKT_TYPE_DH1    0x04
#define PKT_TYPE_HV1    0x05
#define PKT_TYPE_HV2    0x06
#define PKT_TYPE_HV3    0x07
#define PKT_TYPE_DV     0x08
#define PKT_TYPE_AUX1   0x09

#define PKT_TYPE_DM3    0x0a
#define PKT_TYPE_DH3    0x0b

#define PKT_TYPE_DM5    0x0e
#define PKT_TYPE_DH5    0x0f


#define PKT_TYPE_ID     0x10        /* Internally used packet types */
#define PKT_TYPE_BAD    0x11
#define PKT_TYPE_NONE   0x12

/*
** Define packet size
*/
#define HCI_DM1_PACKET_SIZE         17
#define HCI_DH1_PACKET_SIZE         27
#define HCI_DM3_PACKET_SIZE         121
#define HCI_DH3_PACKET_SIZE         183
#define HCI_DM5_PACKET_SIZE         224
#define HCI_DH5_PACKET_SIZE         339
#define HCI_AUX1_PACKET_SIZE        29
#define HCI_HV1_PACKET_SIZE         10
#define HCI_HV2_PACKET_SIZE         20
#define HCI_HV3_PACKET_SIZE         30
#define HCI_DV_PACKET_SIZE          9
#define HCI_EDR2_DH1_PACKET_SIZE    54
#define HCI_EDR2_DH3_PACKET_SIZE    367
#define HCI_EDR2_DH5_PACKET_SIZE    679
#define HCI_EDR3_DH1_PACKET_SIZE    83
#define HCI_EDR3_DH3_PACKET_SIZE    552
#define HCI_EDR3_DH5_PACKET_SIZE    1021

/* Feature Pages */
#define HCI_EXT_FEATURES_PAGE_0     0       /* Extended Feature Page 0 (regular features) */
#define HCI_EXT_FEATURES_PAGE_1     1       /* Extended Feature Page 1 */
#define HCI_EXT_FEATURES_PAGE_2     2       /* Extended Feature Page 2 */
#define HCI_EXT_FEATURES_PAGE_MAX   HCI_EXT_FEATURES_PAGE_2

#define HCI_FEATURE_BYTES_PER_PAGE      8

#define HCI_FEATURES_KNOWN(x) ((x[0] | x[1] | x[2] | x[3] | x[4] | x[5] | x[6] | x[7]) != 0)

/*
**   LMP features encoding - page 0
*/
#define HCI_FEATURE_3_SLOT_PACKETS_MASK 0x01
#define HCI_FEATURE_3_SLOT_PACKETS_OFF  0
#define HCI_3_SLOT_PACKETS_SUPPORTED(x) ((x)[HCI_FEATURE_3_SLOT_PACKETS_OFF] & HCI_FEATURE_3_SLOT_PACKETS_MASK)

#define HCI_FEATURE_5_SLOT_PACKETS_MASK 0x02
#define HCI_FEATURE_5_SLOT_PACKETS_OFF  0
#define HCI_5_SLOT_PACKETS_SUPPORTED(x) ((x)[HCI_FEATURE_5_SLOT_PACKETS_OFF] & HCI_FEATURE_5_SLOT_PACKETS_MASK)

#define HCI_FEATURE_ENCRYPTION_MASK     0x04
#define HCI_FEATURE_ENCRYPTION_OFF      0
#define HCI_ENCRYPTION_SUPPORTED(x)     ((x)[HCI_FEATURE_ENCRYPTION_OFF] & HCI_FEATURE_ENCRYPTION_MASK)

#define HCI_FEATURE_SLOT_OFFSET_MASK    0x08
#define HCI_FEATURE_SLOT_OFFSET_OFF     0
#define HCI_SLOT_OFFSET_SUPPORTED(x)    ((x)[HCI_FEATURE_SLOT_OFFSET_OFF] & HCI_FEATURE_SLOT_OFFSET_MASK)

#define HCI_FEATURE_TIMING_ACC_MASK     0x10
#define HCI_FEATURE_TIMING_ACC_OFF      0
#define HCI_TIMING_ACC_SUPPORTED(x)     ((x)[HCI_FEATURE_TIMING_ACC_OFF] & HCI_FEATURE_TIMING_ACC_MASK)

#define HCI_FEATURE_SWITCH_MASK         0x20
#define HCI_FEATURE_SWITCH_OFF          0
#define HCI_SWITCH_SUPPORTED(x)         ((x)[HCI_FEATURE_SWITCH_OFF] & HCI_FEATURE_SWITCH_MASK)

#define HCI_FEATURE_HOLD_MODE_MASK      0x40
#define HCI_FEATURE_HOLD_MODE_OFF       0
#define HCI_HOLD_MODE_SUPPORTED(x)      ((x)[HCI_FEATURE_HOLD_MODE_OFF] & HCI_FEATURE_HOLD_MODE_MASK)

#define HCI_FEATURE_SNIFF_MODE_MASK     0x80
#define HCI_FEATURE_SNIFF_MODE_OFF      0
#define HCI_SNIFF_MODE_SUPPORTED(x)      ((x)[HCI_FEATURE_SNIFF_MODE_OFF] & HCI_FEATURE_SNIFF_MODE_MASK)

#define HCI_FEATURE_PARK_MODE_MASK      0x01
#define HCI_FEATURE_PARK_MODE_OFF       1
#define HCI_PARK_MODE_SUPPORTED(x)      ((x)[HCI_FEATURE_PARK_MODE_OFF] & HCI_FEATURE_PARK_MODE_MASK)

#define HCI_FEATURE_RSSI_MASK           0x02
#define HCI_FEATURE_RSSI_OFF            1
#define HCI_RSSI_SUPPORTED(x)           ((x)[HCI_FEATURE_RSSI_OFF] & HCI_FEATURE_RSSI_MASK)

#define HCI_FEATURE_CQM_DATA_RATE_MASK  0x04
#define HCI_FEATURE_CQM_DATA_RATE_OFF   1
#define HCI_CQM_DATA_RATE_SUPPORTED(x)  ((x)[HCI_FEATURE_CQM_DATA_RATE_OFF] & HCI_FEATURE_CQM_DATA_RATE_MASK)

#define HCI_FEATURE_SCO_LINK_MASK       0x08
#define HCI_FEATURE_SCO_LINK_OFF        1
#define HCI_SCO_LINK_SUPPORTED(x)       ((x)[HCI_FEATURE_SCO_LINK_OFF] & HCI_FEATURE_SCO_LINK_MASK)

#define HCI_FEATURE_HV2_PACKETS_MASK    0x10
#define HCI_FEATURE_HV2_PACKETS_OFF     1
#define HCI_HV2_PACKETS_SUPPORTED(x)    ((x)[HCI_FEATURE_HV2_PACKETS_OFF] & HCI_FEATURE_HV2_PACKETS_MASK)

#define HCI_FEATURE_HV3_PACKETS_MASK    0x20
#define HCI_FEATURE_HV3_PACKETS_OFF     1
#define HCI_HV3_PACKETS_SUPPORTED(x)    ((x)[HCI_FEATURE_HV3_PACKETS_OFF] & HCI_FEATURE_HV3_PACKETS_MASK)

#define HCI_FEATURE_U_LAW_MASK          0x40
#define HCI_FEATURE_U_LAW_OFF           1
#define HCI_LMP_U_LAW_SUPPORTED(x)      ((x)[HCI_FEATURE_U_LAW_OFF] & HCI_FEATURE_U_LAW_MASK)

#define HCI_FEATURE_A_LAW_MASK          0x80
#define HCI_FEATURE_A_LAW_OFF           1
#define HCI_LMP_A_LAW_SUPPORTED(x)      ((x)[HCI_FEATURE_A_LAW_OFF] & HCI_FEATURE_A_LAW_MASK)

#define HCI_FEATURE_CVSD_MASK           0x01
#define HCI_FEATURE_CVSD_OFF            2
#define HCI_LMP_CVSD_SUPPORTED(x)       ((x)[HCI_FEATURE_CVSD_OFF] & HCI_FEATURE_CVSD_MASK)

#define HCI_FEATURE_PAGING_SCHEME_MASK  0x02
#define HCI_FEATURE_PAGING_SCHEME_OFF   2
#define HCI_PAGING_SCHEME_SUPPORTED(x) ((x)[HCI_FEATURE_PAGING_SCHEME_OFF] & HCI_FEATURE_PAGING_SCHEME_MASK)

#define HCI_FEATURE_POWER_CTRL_MASK     0x04
#define HCI_FEATURE_POWER_CTRL_OFF      2
#define HCI_POWER_CTRL_SUPPORTED(x)     ((x)[HCI_FEATURE_POWER_CTRL_OFF] & HCI_FEATURE_POWER_CTRL_MASK)

#define HCI_FEATURE_TRANSPNT_MASK       0x08
#define HCI_FEATURE_TRANSPNT_OFF        2
#define HCI_LMP_TRANSPNT_SUPPORTED(x)   ((x)[HCI_FEATURE_TRANSPNT_OFF] & HCI_FEATURE_TRANSPNT_MASK)

#define HCI_FEATURE_FLOW_CTRL_LAG_MASK  0x70
#define HCI_FEATURE_FLOW_CTRL_LAG_OFF   2
#define HCI_FLOW_CTRL_LAG_VALUE(x)      (((x)[HCI_FEATURE_FLOW_CTRL_LAG_OFF] & HCI_FEATURE_FLOW_CTRL_LAG_MASK) >> 4)

#define HCI_FEATURE_BROADCAST_ENC_MASK  0x80
#define HCI_FEATURE_BROADCAST_ENC_OFF   2
#define HCI_LMP_BCAST_ENC_SUPPORTED(x)  ((x)[HCI_FEATURE_BROADCAST_ENC_OFF] & HCI_FEATURE_BROADCAST_ENC_MASK)

#define HCI_FEATURE_SCATTER_MODE_MASK   0x01
#define HCI_FEATURE_SCATTER_MODE_OFF    3
#define HCI_LMP_SCATTER_MODE_SUPPORTED(x) ((x)[HCI_FEATURE_SCATTER_MODE_OFF] & HCI_FEATURE_SCATTER_MODE_MASK)

#define HCI_FEATURE_EDR_ACL_2MPS_MASK   0x02
#define HCI_FEATURE_EDR_ACL_2MPS_OFF    3
#define HCI_EDR_ACL_2MPS_SUPPORTED(x)   ((x)[HCI_FEATURE_EDR_ACL_2MPS_OFF] & HCI_FEATURE_EDR_ACL_2MPS_MASK)

#define HCI_FEATURE_EDR_ACL_3MPS_MASK   0x04
#define HCI_FEATURE_EDR_ACL_3MPS_OFF    3
#define HCI_EDR_ACL_3MPS_SUPPORTED(x)   ((x)[HCI_FEATURE_EDR_ACL_3MPS_OFF] & HCI_FEATURE_EDR_ACL_3MPS_MASK)

#define HCI_FEATURE_ENHANCED_INQ_MASK   0x08
#define HCI_FEATURE_ENHANCED_INQ_OFF    3
#define HCI_ENHANCED_INQ_SUPPORTED(x)   ((x)[HCI_FEATURE_ENHANCED_INQ_OFF] & HCI_FEATURE_ENHANCED_INQ_MASK)

#define HCI_FEATURE_INTERLACED_INQ_SCAN_MASK   0x10
#define HCI_FEATURE_INTERLACED_INQ_SCAN_OFF    3
#define HCI_LMP_INTERLACED_INQ_SCAN_SUPPORTED(x) ((x)[HCI_FEATURE_INTERLACED_INQ_SCAN_OFF] & HCI_FEATURE_INTERLACED_INQ_SCAN_MASK)

#define HCI_FEATURE_INTERLACED_PAGE_SCAN_MASK  0x20
#define HCI_FEATURE_INTERLACED_PAGE_SCAN_OFF   3
#define HCI_LMP_INTERLACED_PAGE_SCAN_SUPPORTED(x) ((x)[HCI_FEATURE_INTERLACED_PAGE_SCAN_OFF] & HCI_FEATURE_INTERLACED_PAGE_SCAN_MASK)

#define HCI_FEATURE_INQ_RSSI_MASK       0x40
#define HCI_FEATURE_INQ_RSSI_OFF        3
#define HCI_LMP_INQ_RSSI_SUPPORTED(x)   ((x)[HCI_FEATURE_INQ_RSSI_OFF] & HCI_FEATURE_INQ_RSSI_MASK)

#define HCI_FEATURE_ESCO_EV3_MASK       0x80
#define HCI_FEATURE_ESCO_EV3_OFF        3
#define HCI_ESCO_EV3_SUPPORTED(x)       ((x)[HCI_FEATURE_ESCO_EV3_OFF] & HCI_FEATURE_ESCO_EV3_MASK)

#define HCI_FEATURE_ESCO_EV4_MASK       0x01
#define HCI_FEATURE_ESCO_EV4_OFF        4
#define HCI_ESCO_EV4_SUPPORTED(x)       ((x)[HCI_FEATURE_ESCO_EV4_OFF] & HCI_FEATURE_ESCO_EV4_MASK)

#define HCI_FEATURE_ESCO_EV5_MASK       0x02
#define HCI_FEATURE_ESCO_EV5_OFF        4
#define HCI_ESCO_EV5_SUPPORTED(x)       ((x)[HCI_FEATURE_ESCO_EV5_OFF] & HCI_FEATURE_ESCO_EV5_MASK)

#define HCI_FEATURE_ABSENCE_MASKS_MASK  0x04
#define HCI_FEATURE_ABSENCE_MASKS_OFF   4
#define HCI_LMP_ABSENCE_MASKS_SUPPORTED(x) ((x)[HCI_FEATURE_ABSENCE_MASKS_OFF] & HCI_FEATURE_ABSENCE_MASKS_MASK)

#define HCI_FEATURE_AFH_CAP_SLAVE_MASK  0x08
#define HCI_FEATURE_AFH_CAP_SLAVE_OFF   4
#define HCI_LMP_AFH_CAP_SLAVE_SUPPORTED(x) ((x)[HCI_FEATURE_AFH_CAP_SLAVE_OFF] & HCI_FEATURE_AFH_CAP_SLAVE_MASK)

#define HCI_FEATURE_AFH_CLASS_SLAVE_MASK 0x10
#define HCI_FEATURE_AFH_CLASS_SLAVE_OFF  4
#define HCI_LMP_AFH_CLASS_SLAVE_SUPPORTED(x) ((x)[HCI_FEATURE_AFH_CLASS_SLAVE_OFF] & HCI_FEATURE_AFH_CLASS_SLAVE_MASK)

#if 1
#define HCI_FEATURE_BREDR_NOT_SPT_MASK     0x20
#define HCI_FEATURE_BREDR_NOT_SPT_OFF      4
#define HCI_BREDR_NOT_SPT_SUPPORTED(x) ((x)[HCI_FEATURE_BREDR_NOT_SPT_OFF] & HCI_FEATURE_BREDR_NOT_SPT_MASK)

#define HCI_FEATURE_LE_SPT_MASK      0x40
#define HCI_FEATURE_LE_SPT_OFF       4
#define HCI_LE_SPT_SUPPORTED(x)  ((x)[HCI_FEATURE_LE_SPT_OFF] & HCI_FEATURE_LE_SPT_MASK)
#else

#define HCI_FEATURE_ALIAS_AUTH_MASK     0x20
#define HCI_FEATURE_ALIAS_AUTH_OFF      4
#define HCI_LMP_ALIAS_AUTH_SUPPORTED(x) ((x)[HCI_FEATURE_ALIAS_AUTH_OFF] & HCI_FEATURE_ALIAS_AUTH_MASK)

#define HCI_FEATURE_ANON_MODE_MASK      0x40
#define HCI_FEATURE_ANON_MODE_OFF       4
#define HCI_LMP_ANON_MODE_SUPPORTED(x)  ((x)[HCI_FEATURE_ANON_MODE_OFF] & HCI_FEATURE_ANON_MODE_MASK)
#endif

#define HCI_FEATURE_3_SLOT_EDR_ACL_MASK 0x80
#define HCI_FEATURE_3_SLOT_EDR_ACL_OFF  4
#define HCI_3_SLOT_EDR_ACL_SUPPORTED(x) ((x)[HCI_FEATURE_3_SLOT_EDR_ACL_OFF] & HCI_FEATURE_3_SLOT_EDR_ACL_MASK)

#define HCI_FEATURE_5_SLOT_EDR_ACL_MASK 0x01
#define HCI_FEATURE_5_SLOT_EDR_ACL_OFF  5
#define HCI_5_SLOT_EDR_ACL_SUPPORTED(x) ((x)[HCI_FEATURE_5_SLOT_EDR_ACL_OFF] & HCI_FEATURE_5_SLOT_EDR_ACL_MASK)

#define HCI_FEATURE_SNIFF_SUB_RATE_MASK 0x02
#define HCI_FEATURE_SNIFF_SUB_RATE_OFF  5
#define HCI_SNIFF_SUB_RATE_SUPPORTED(x) ((x)[HCI_FEATURE_SNIFF_SUB_RATE_OFF] & HCI_FEATURE_SNIFF_SUB_RATE_MASK)

#define HCI_FEATURE_ATOMIC_ENCRYPT_MASK 0x04
#define HCI_FEATURE_ATOMIC_ENCRYPT_OFF  5
#define HCI_ATOMIC_ENCRYPT_SUPPORTED(x) ((x)[HCI_FEATURE_ATOMIC_ENCRYPT_OFF] & HCI_FEATURE_ATOMIC_ENCRYPT_MASK)

#define HCI_FEATURE_AFH_CAP_MASTR_MASK  0x08
#define HCI_FEATURE_AFH_CAP_MASTR_OFF   5
#define HCI_LMP_AFH_CAP_MASTR_SUPPORTED(x) ((x)[HCI_FEATURE_AFH_CAP_MASTR_OFF] & HCI_FEATURE_AFH_CAP_MASTR_MASK)

#define HCI_FEATURE_AFH_CLASS_MASTR_MASK 0x10
#define HCI_FEATURE_AFH_CLASS_MASTR_OFF  5
#define HCI_LMP_AFH_CLASS_MASTR_SUPPORTED(x) ((x)[HCI_FEATURE_AFH_CLASS_MASTR_OFF] & HCI_FEATURE_AFH_CLASS_MASTR_MASK)

#define HCI_FEATURE_EDR_ESCO_2MPS_MASK  0x20
#define HCI_FEATURE_EDR_ESCO_2MPS_OFF   5
#define HCI_EDR_ESCO_2MPS_SUPPORTED(x)  ((x)[HCI_FEATURE_EDR_ESCO_2MPS_OFF] & HCI_FEATURE_EDR_ESCO_2MPS_MASK)

#define HCI_FEATURE_EDR_ESCO_3MPS_MASK  0x40
#define HCI_FEATURE_EDR_ESCO_3MPS_OFF   5
#define HCI_EDR_ESCO_3MPS_SUPPORTED(x)  ((x)[HCI_FEATURE_EDR_ESCO_3MPS_OFF] & HCI_FEATURE_EDR_ESCO_3MPS_MASK)

#define HCI_FEATURE_3_SLOT_EDR_ESCO_MASK 0x80
#define HCI_FEATURE_3_SLOT_EDR_ESCO_OFF  5
#define HCI_3_SLOT_EDR_ESCO_SUPPORTED(x) ((x)[HCI_FEATURE_3_SLOT_EDR_ESCO_OFF] & HCI_FEATURE_3_SLOT_EDR_ESCO_MASK)

#define HCI_FEATURE_EXT_INQ_RSP_MASK    0x01
#define HCI_FEATURE_EXT_INQ_RSP_OFF     6
#define HCI_EXT_INQ_RSP_SUPPORTED(x)    ((x)[HCI_FEATURE_EXT_INQ_RSP_OFF] & HCI_FEATURE_EXT_INQ_RSP_MASK)

#if 1 /* TOKYO spec definition */
#define HCI_FEATURE_SIMUL_LE_BREDR_MASK 0x02
#define HCI_FEATURE_SIMUL_LE_BREDR_OFF  6
#define HCI_SIMUL_LE_BREDR_SUPPORTED(x) ((x)[HCI_FEATURE_SIMUL_LE_BREDR_OFF] & HCI_FEATURE_SIMUL_LE_BREDR_MASK)

#else
#define HCI_FEATURE_ANUM_PIN_AWARE_MASK 0x02
#define HCI_FEATURE_ANUM_PIN_AWARE_OFF  6
#define HCI_ANUM_PIN_AWARE_SUPPORTED(x) ((x)[HCI_FEATURE_ANUM_PIN_AWARE_OFF] & HCI_FEATURE_ANUM_PIN_AWARE_MASK)
#endif

#define HCI_FEATURE_ANUM_PIN_CAP_MASK   0x04
#define HCI_FEATURE_ANUM_PIN_CAP_OFF    6
#define HCI_ANUM_PIN_CAP_SUPPORTED(x)   ((x)[HCI_FEATURE_ANUM_PIN_CAP_OFF] & HCI_FEATURE_ANUM_PIN_CAP_MASK)

#define HCI_FEATURE_SIMPLE_PAIRING_MASK 0x08
#define HCI_FEATURE_SIMPLE_PAIRING_OFF  6
#define HCI_SIMPLE_PAIRING_SUPPORTED(x) ((x)[HCI_FEATURE_SIMPLE_PAIRING_OFF] & HCI_FEATURE_SIMPLE_PAIRING_MASK)

#define HCI_FEATURE_ENCAP_PDU_MASK      0x10
#define HCI_FEATURE_ENCAP_PDU_OFF       6
#define HCI_ENCAP_PDU_SUPPORTED(x)      ((x)[HCI_FEATURE_ENCAP_PDU_OFF] & HCI_FEATURE_ENCAP_PDU_MASK)

#define HCI_FEATURE_ERROR_DATA_MASK     0x20
#define HCI_FEATURE_ERROR_DATA_OFF      6
#define HCI_ERROR_DATA_SUPPORTED(x)     ((x)[HCI_FEATURE_ERROR_DATA_OFF] & HCI_FEATURE_ERROR_DATA_MASK)

#define HCI_FEATURE_NON_FLUSHABLE_PB_MASK      0x40
#define HCI_FEATURE_NON_FLUSHABLE_PB_OFF       6

#define HCI_NON_FLUSHABLE_PB_SUPPORTED(x)      ((x)[HCI_FEATURE_NON_FLUSHABLE_PB_OFF] & HCI_FEATURE_NON_FLUSHABLE_PB_MASK)

#define HCI_FEATURE_LINK_SUP_TO_EVT_MASK 0x01
#define HCI_FEATURE_LINK_SUP_TO_EVT_OFF  7
#define HCI_LINK_SUP_TO_EVT_SUPPORTED(x) ((x)[HCI_FEATURE_LINK_SUP_TO_EVT_OFF] & HCI_FEATURE_LINK_SUP_TO_EVT_MASK)

#define HCI_FEATURE_INQ_RESP_TX_MASK     0x02
#define HCI_FEATURE_INQ_RESP_TX_OFF      7
#define HCI_INQ_RESP_TX_SUPPORTED(x)     ((x)[HCI_FEATURE_INQ_RESP_TX_OFF] & HCI_FEATURE_INQ_RESP_TX_MASK)

#define HCI_FEATURE_EXTENDED_MASK       0x80
#define HCI_FEATURE_EXTENDED_OFF        7
#define HCI_LMP_EXTENDED_SUPPORTED(x)   ((x)[HCI_FEATURE_EXTENDED_OFF] & HCI_FEATURE_EXTENDED_MASK)

/*
**   LMP features encoding - page 1
*/
#define HCI_EXT_FEATURE_SSP_HOST_MASK 0x01
#define HCI_EXT_FEATURE_SSP_HOST_OFF  0
#define HCI_SSP_HOST_SUPPORTED(x) ((x)[HCI_EXT_FEATURE_SSP_HOST_OFF] & HCI_EXT_FEATURE_SSP_HOST_MASK)

#define HCI_EXT_FEATURE_LE_HOST_MASK 0x02
#define HCI_EXT_FEATURE_LE_HOST_OFF  0
#define HCI_LE_HOST_SUPPORTED(x) ((x)[HCI_EXT_FEATURE_LE_HOST_OFF] | HCI_EXT_FEATURE_LE_HOST_MASK)

#define HCI_EXT_FEATURE_SIMUL_DUMO_HOST_MASK 0x04
#define HCI_EXT_FEATURE_SIMUL_DUMO_HOST_OFF  0
#define HCI_SIMUL_DUMO_HOST_SUPPORTED(x) ((x)[HCI_EXT_FEATURE_SIMUL_DUMO_HOST_OFF] & HCI_EXT_FEATURE_SIMUL_DUMO_HOST_MASK)

/*
**   LMP features encoding - page 2
*/
#define HCI_EXT_FEATURE_CSB_MASTER_MASK         0x01
#define HCI_EXT_FEATURE_CSB_MASTER_OFF          0
#define HCI_CSB_MASTER_SUPPORTED(x) ((x)[HCI_EXT_FEATURE_CSB_MASTER_OFF] & HCI_EXT_FEATURE_CSB_MASTER_MASK)

#define HCI_EXT_FEATURE_CSB_SLAVE_MASK          0x02
#define HCI_EXT_FEATURE_CSB_SLAVE_OFF           0
#define HCI_CSB_SLAVE_SUPPORTED(x) ((x)[HCI_EXT_FEATURE_CSB_SLAVE_OFF] & HCI_EXT_FEATURE_CSB_SLAVE_MASK)

#define HCI_EXT_FEATURE_SYNC_TRAIN_MASTER_MASK  0x04
#define HCI_EXT_FEATURE_SYNC_TRAIN_MASTER_OFF   0
#define HCI_SYNC_TRAIN_MASTER_SUPPORTED(x) ((x)[HCI_EXT_FEATURE_SYNC_TRAIN_MASTER_OFF] & HCI_EXT_FEATURE_SYNC_TRAIN_MASTER_MASK)

#define HCI_EXT_FEATURE_SYNC_SCAN_SLAVE_MASK    0x08
#define HCI_EXT_FEATURE_SYNC_SCAN_SLAVE_OFF     0
#define HCI_SYNC_SCAN_SLAVE_SUPPORTED(x) ((x)[HCI_EXT_FEATURE_SYNC_SCAN_SLAVE_OFF] & HCI_EXT_FEATURE_SYNC_SCAN_SLAVE_MASK)

#define HCI_EXT_FEATURE_INQ_RESP_NOTIF_MASK     0x10
#define HCI_EXT_FEATURE_INQ_RESP_NOTIF_OFF      0
#define HCI_INQ_RESP_NOTIF_SUPPORTED(x) ((x)[HCI_EXT_FEATURE_INQ_RESP_NOTIF_OFF] & HCI_EXT_FEATURE_INQ_RESP_NOTIF_MASK)

/*
**   LE features encoding - page 0 (the only page for now)
*/
#define HCI_LE_FEATURE_LE_ENCRYPTION_MASK       0x01
#define HCI_LE_FEATURE_LE_ENCRYPTION_OFF        0
#define HCI_LE_ENCRYPTION_SUPPORTED(x) ((x)[HCI_LE_FEATURE_LE_ENCRYPTION_OFF] & HCI_LE_FEATURE_LE_ENCRYPTION_MASK)


/*
**   Local Supported Commands encoding
*/
#define HCI_NUM_SUPP_COMMANDS_BYTES           64

#define HCI_SUPP_COMMANDS_INQUIRY_MASK 0x01
#define HCI_SUPP_COMMANDS_INQUIRY_OFF  0
#define HCI_INQUIRY_SUPPORTED(x) ((x)[HCI_SUPP_COMMANDS_INQUIRY_OFF] & HCI_SUPP_COMMANDS_INQUIRY_MASK)

#define HCI_SUPP_COMMANDS_INQUIRY_CANCEL_MASK 0x02
#define HCI_SUPP_COMMANDS_INQUIRY_CANCEL_OFF  0
#define HCI_INQUIRY_CANCEL_SUPPORTED(x) ((x)[HCI_SUPP_COMMANDS_INQUIRY_CANCEL_OFF] & HCI_SUPP_COMMANDS_INQUIRY_CANCEL_MASK)

#define HCI_SUPP_COMMANDS_PERIODIC_INQUIRY_MASK     0x04
#define HCI_SUPP_COMMANDS_PERIODIC_INQUIRY_OFF      0
#define HCI_PERIODIC_INQUIRY_SUPPORTED(x)     ((x)[HCI_SUPP_COMMANDS_PERIODIC_INQUIRY_OFF] & HCI_SUPP_COMMANDS_PERIODIC_INQUIRY_MASK)

#define HCI_SUPP_COMMANDS_EXIT_PERIODIC_INQUIRY_MASK    0x08
#define HCI_SUPP_COMMANDS_EXIT_PERIODIC_INQUIRY_OFF     0
#define HCI_EXIT_PERIODIC_INQUIRY_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_EXIT_PERIODIC_INQUIRY_OFF] & HCI_SUPP_COMMANDS_EXIT_PERIODIC_INQUIRY_MASK)

#define HCI_SUPP_COMMANDS_CREATE_CONN_MASK     0x10
#define HCI_SUPP_COMMANDS_CREATE_CONN_OFF      0
#define HCI_CREATE_CONN_SUPPORTED(x)     ((x)[HCI_SUPP_COMMANDS_CREATE_CONN_OFF] & HCI_SUPP_COMMANDS_CREATE_CONN_MASK)

#define HCI_SUPP_COMMANDS_DISCONNECT_MASK         0x20
#define HCI_SUPP_COMMANDS_DISCONNECT_OFF          0
#define HCI_DISCONNECT_SUPPORTED(x)         ((x)[HCI_SUPP_COMMANDS_DISCONNECT_OFF] & HCI_SUPP_COMMANDS_DISCONNECT_MASK)

#define HCI_SUPP_COMMANDS_ADD_SCO_CONN_MASK      0x40
#define HCI_SUPP_COMMANDS_ADD_SCO_CONN_OFF       0
#define HCI_ADD_SCO_CONN_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_ADD_SCO_CONN_OFF] & HCI_SUPP_COMMANDS_ADD_SCO_CONN_MASK)

#define HCI_SUPP_COMMANDS_CANCEL_CREATE_CONN_MASK     0x80
#define HCI_SUPP_COMMANDS_CANCEL_CREATE_CONN_OFF      0
#define HCI_CANCEL_CREATE_CONN_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_CANCEL_CREATE_CONN_OFF] & HCI_SUPP_COMMANDS_CANCEL_CREATE_CONN_MASK)

#define HCI_SUPP_COMMANDS_ACCEPT_CONN_REQUEST_MASK      0x01
#define HCI_SUPP_COMMANDS_ACCEPT_CONN_REQUEST_OFF       1
#define HCI_ACCEPT_CONN_REQUEST_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_ACCEPT_CONN_REQUEST_OFF] & HCI_SUPP_COMMANDS_ACCEPT_CONN_REQUEST_MASK)

#define HCI_SUPP_COMMANDS_REJECT_CONN_REQUEST_MASK           0x02
#define HCI_SUPP_COMMANDS_REJECT_CONN_REQUEST_OFF            1
#define HCI_REJECT_CONN_REQUEST_SUPPORTED(x)           ((x)[HCI_SUPP_COMMANDS_REJECT_CONN_REQUEST_OFF] & HCI_SUPP_COMMANDS_REJECT_CONN_REQUEST_MASK)

#define HCI_SUPP_COMMANDS_LINK_KEY_REQUEST_REPLY_MASK  0x04
#define HCI_SUPP_COMMANDS_LINK_KEY_REQUEST_REPLY_OFF   1
#define HCI_LINK_KEY_REQUEST_REPLY_SUPPORTED(x)  ((x)[HCI_SUPP_COMMANDS_LINK_KEY_REQUEST_REPLY_OFF] & HCI_SUPP_COMMANDS_LINK_KEY_REQUEST_REPLY_MASK)

#define HCI_SUPP_COMMANDS_LINK_KEY_REQUEST_NEG_REPLY_MASK       0x08
#define HCI_SUPP_COMMANDS_LINK_KEY_REQUEST_NEG_REPLY_OFF        1
#define HCI_LINK_KEY_REQUEST_NEG_REPLY_SUPPORTED(x)       ((x)[HCI_SUPP_COMMANDS_LINK_KEY_REQUEST_NEG_REPLY_OFF] & HCI_SUPP_COMMANDS_LINK_KEY_REQUEST_NEG_REPLY_MASK)

#define HCI_SUPP_COMMANDS_PIN_CODE_REQUEST_REPLY_MASK    0x10
#define HCI_SUPP_COMMANDS_PIN_CODE_REQUEST_REPLY_OFF     1
#define HCI_PIN_CODE_REQUEST_REPLY_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_PIN_CODE_REQUEST_REPLY_OFF] & HCI_SUPP_COMMANDS_PIN_CODE_REQUEST_REPLY_MASK)

#define HCI_SUPP_COMMANDS_PIN_CODE_REQUEST_NEG_REPLY_MASK    0x20
#define HCI_SUPP_COMMANDS_PIN_CODE_REQUEST_NEG_REPLY_OFF     1
#define HCI_PIN_CODE_REQUEST_NEG_REPLY_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_PIN_CODE_REQUEST_NEG_REPLY_OFF] & HCI_SUPP_COMMANDS_PIN_CODE_REQUEST_NEG_REPLY_MASK)

#define HCI_SUPP_COMMANDS_CHANGE_CONN_PKT_TYPE_MASK          0x40
#define HCI_SUPP_COMMANDS_CHANGE_CONN_PKT_TYPE_OFF           1
#define HCI_CHANGE_CONN_PKT_TYPE_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_CHANGE_CONN_PKT_TYPE_OFF] & HCI_SUPP_COMMANDS_CHANGE_CONN_PKT_TYPE_MASK)

#define HCI_SUPP_COMMANDS_AUTH_REQUEST_MASK          0x80
#define HCI_SUPP_COMMANDS_AUTH_REQUEST_OFF           1
#define HCI_AUTH_REQUEST_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_AUTH_REQUEST_OFF] & HCI_SUPP_COMMANDS_AUTH_REQUEST_MASK)

#define HCI_SUPP_COMMANDS_SET_CONN_ENCRYPTION_MASK      0x01
#define HCI_SUPP_COMMANDS_SET_CONN_ENCRYPTION_OFF       2
#define HCI_SET_CONN_ENCRYPTION_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_SET_CONN_ENCRYPTION_OFF] & HCI_SUPP_COMMANDS_SET_CONN_ENCRYPTION_MASK)

#define HCI_SUPP_COMMANDS_CHANGE_CONN_LINK_KEY_MASK           0x02
#define HCI_SUPP_COMMANDS_CHANGE_CONN_LINK_KEY_OFF            2
#define HCI_CHANGE_CONN_LINK_KEY_SUPPORTED(x)           ((x)[HCI_SUPP_COMMANDS_CHANGE_CONN_LINK_KEY_OFF] & HCI_SUPP_COMMANDS_CHANGE_CONN_LINK_KEY_MASK)

#define HCI_SUPP_COMMANDS_MASTER_LINK_KEY_MASK  0x04
#define HCI_SUPP_COMMANDS_MASTER_LINK_KEY_OFF   2
#define HCI_MASTER_LINK_KEY_SUPPORTED(x)  ((x)[HCI_SUPP_COMMANDS_MASTER_LINK_KEY_OFF] & HCI_SUPP_COMMANDS_MASTER_LINK_KEY_MASK)

#define HCI_SUPP_COMMANDS_REMOTE_NAME_REQUEST_MASK       0x08
#define HCI_SUPP_COMMANDS_REMOTE_NAME_REQUEST_OFF        2
#define HCI_REMOTE_NAME_REQUEST_SUPPORTED(x)       ((x)[HCI_SUPP_COMMANDS_REMOTE_NAME_REQUEST_OFF] & HCI_SUPP_COMMANDS_REMOTE_NAME_REQUEST_MASK)

#define HCI_SUPP_COMMANDS_CANCEL_REMOTE_NAME_REQUEST_MASK    0x10
#define HCI_SUPP_COMMANDS_CANCEL_REMOTE_NAME_REQUEST_OFF     2
#define HCI_CANCEL_REMOTE_NAME_REQUEST_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_CANCEL_REMOTE_NAME_REQUEST_OFF] & HCI_SUPP_COMMANDS_CANCEL_REMOTE_NAME_REQUEST_MASK)

#define HCI_SUPP_COMMANDS_READ_REMOTE_SUPP_FEATURES_MASK    0x20
#define HCI_SUPP_COMMANDS_READ_REMOTE_SUPP_FEATURES_OFF     2
#define HCI_READ_REMOTE_SUPP_FEATURES_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_READ_REMOTE_SUPP_FEATURES_OFF] & HCI_SUPP_COMMANDS_READ_REMOTE_SUPP_FEATURES_MASK)

#define HCI_SUPP_COMMANDS_READ_REMOTE_EXT_FEATURES_MASK          0x40
#define HCI_SUPP_COMMANDS_READ_REMOTE_EXT_FEATURES_OFF           2
#define HCI_READ_REMOTE_EXT_FEATURES_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_READ_REMOTE_EXT_FEATURES_OFF] & HCI_SUPP_COMMANDS_READ_REMOTE_EXT_FEATURES_MASK)

#define HCI_SUPP_COMMANDS_READ_REMOTE_VER_INFO_MASK          0x80
#define HCI_SUPP_COMMANDS_READ_REMOTE_VER_INFO_OFF           2
#define HCI_READ_REMOTE_VER_INFO_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_READ_REMOTE_VER_INFO_OFF] & HCI_SUPP_COMMANDS_READ_REMOTE_VER_INFO_MASK)

#define HCI_SUPP_COMMANDS_READ_CLOCK_OFFSET_MASK           0x01
#define HCI_SUPP_COMMANDS_READ_CLOCK_OFFSET_OFF            3
#define HCI_READ_CLOCK_OFFSET_SUPPORTED(x)       ((x)[HCI_SUPP_COMMANDS_READ_CLOCK_OFFSET_OFF] & HCI_SUPP_COMMANDS_READ_CLOCK_OFFSET_MASK)

#define HCI_SUPP_COMMANDS_READ_LMP_HANDLE_MASK  0x02
#define HCI_SUPP_COMMANDS_READ_LMP_HANDLE_OFF   3
#define HCI_READ_LMP_HANDLE_SUPPORTED(x) ((x)[HCI_SUPP_COMMANDS_READ_LMP_HANDLE_OFF] & HCI_SUPP_COMMANDS_READ_LMP_HANDLE_MASK)

#define HCI_SUPP_COMMANDS_HOLD_MODE_CMD_MASK           0x02
#define HCI_SUPP_COMMANDS_HOLD_MODE_CMD_OFF            4
#define HCI_HOLD_MODE_CMD_SUPPORTED(x)           ((x)[HCI_SUPP_COMMANDS_HOLD_MODE_CMD_OFF] & HCI_SUPP_COMMANDS_HOLD_MODE_CMD_MASK)

#define HCI_SUPP_COMMANDS_SNIFF_MODE_CMD_MASK  0x04
#define HCI_SUPP_COMMANDS_SNIFF_MODE_CMD_OFF   4
#define HCI_SNIFF_MODE_CMD_SUPPORTED(x)  ((x)[HCI_SUPP_COMMANDS_SNIFF_MODE_CMD_OFF] & HCI_SUPP_COMMANDS_SNIFF_MODE_CMD_MASK)

#define HCI_SUPP_COMMANDS_EXIT_SNIFF_MODE_MASK       0x08
#define HCI_SUPP_COMMANDS_EXIT_SNIFF_MODE_OFF        4
#define HCI_EXIT_SNIFF_MODE_SUPPORTED(x)       ((x)[HCI_SUPP_COMMANDS_EXIT_SNIFF_MODE_OFF] & HCI_SUPP_COMMANDS_EXIT_SNIFF_MODE_MASK)

#define HCI_SUPP_COMMANDS_PARK_STATE_MASK    0x10
#define HCI_SUPP_COMMANDS_PARK_STATE_OFF     4
#define HCI_PARK_STATE_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_PARK_STATE_OFF] & HCI_SUPP_COMMANDS_PARK_STATE_MASK)

#define HCI_SUPP_COMMANDS_EXIT_PARK_STATE_MASK    0x20
#define HCI_SUPP_COMMANDS_EXIT_PARK_STATE_OFF     4
#define HCI_EXIT_PARK_STATE_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_EXIT_PARK_STATE_OFF] & HCI_SUPP_COMMANDS_EXIT_PARK_STATE_MASK)

#define HCI_SUPP_COMMANDS_QOS_SETUP_MASK          0x40
#define HCI_SUPP_COMMANDS_QOS_SETUP_OFF           4
#define HCI_QOS_SETUP_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_QOS_SETUP_OFF] & HCI_SUPP_COMMANDS_QOS_SETUP_MASK)

#define HCI_SUPP_COMMANDS_ROLE_DISCOVERY_MASK          0x80
#define HCI_SUPP_COMMANDS_ROLE_DISCOVERY_OFF           4
#define HCI_ROLE_DISCOVERY_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_ROLE_DISCOVERY_OFF] & HCI_SUPP_COMMANDS_ROLE_DISCOVERY_MASK)

#define HCI_SUPP_COMMANDS_SWITCH_ROLE_MASK      0x01
#define HCI_SUPP_COMMANDS_SWITCH_ROLE_OFF       5
#define HCI_SWITCH_ROLE_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_SWITCH_ROLE_OFF] & HCI_SUPP_COMMANDS_SWITCH_ROLE_MASK)

#define HCI_SUPP_COMMANDS_READ_LINK_POLICY_SET_MASK           0x02
#define HCI_SUPP_COMMANDS_READ_LINK_POLICY_SET_OFF            5
#define HCI_READ_LINK_POLICY_SET_SUPPORTED(x)           ((x)[HCI_SUPP_COMMANDS_READ_LINK_POLICY_SET_OFF] & HCI_SUPP_COMMANDS_READ_LINK_POLICY_SET_MASK)

#define HCI_SUPP_COMMANDS_WRITE_LINK_POLICY_SET_MASK  0x04
#define HCI_SUPP_COMMANDS_WRITE_LINK_POLICY_SET_OFF   5
#define HCI_WRITE_LINK_POLICY_SET_SUPPORTED(x)  ((x)[HCI_SUPP_COMMANDS_WRITE_LINK_POLICY_SET_OFF] & HCI_SUPP_COMMANDS_WRITE_LINK_POLICY_SET_MASK)

#define HCI_SUPP_COMMANDS_READ_DEF_LINK_POLICY_SET_MASK       0x08
#define HCI_SUPP_COMMANDS_READ_DEF_LINK_POLICY_SET_OFF        5
#define HCI_READ_DEF_LINK_POLICY_SET_SUPPORTED(x)       ((x)[HCI_SUPP_COMMANDS_READ_DEF_LINK_POLICY_SET_OFF] & HCI_SUPP_COMMANDS_READ_DEF_LINK_POLICY_SET_MASK)

#define HCI_SUPP_COMMANDS_WRITE_DEF_LINK_POLICY_SET_MASK    0x10
#define HCI_SUPP_COMMANDS_WRITE_DEF_LINK_POLICY_SET_OFF     5
#define HCI_WRITE_DEF_LINK_POLICY_SET_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_WRITE_DEF_LINK_POLICY_SET_OFF] & HCI_SUPP_COMMANDS_WRITE_DEF_LINK_POLICY_SET_MASK)

#define HCI_SUPP_COMMANDS_FLOW_SPECIFICATION_MASK    0x20
#define HCI_SUPP_COMMANDS_FLOW_SPECIFICATION_OFF     5
#define HCI_FLOW_SPECIFICATION_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_FLOW_SPECIFICATION_OFF] & HCI_SUPP_COMMANDS_FLOW_SPECIFICATION_MASK)

#define HCI_SUPP_COMMANDS_SET_EVENT_MASK_MASK          0x40
#define HCI_SUPP_COMMANDS_SET_EVENT_MASK_OFF           5
#define HCI_SET_EVENT_MASK_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_SET_EVENT_MASK_OFF] & HCI_SUPP_COMMANDS_SET_EVENT_MASK_MASK)

#define HCI_SUPP_COMMANDS_RESET_MASK          0x80
#define HCI_SUPP_COMMANDS_RESET_OFF           5
#define HCI_RESET_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_RESET_OFF] & HCI_SUPP_COMMANDS_RESET_MASK)

#define HCI_SUPP_COMMANDS_SET_EVENT_FILTER_MASK      0x01
#define HCI_SUPP_COMMANDS_SET_EVENT_FILTER_OFF       6
#define HCI_SET_EVENT_FILTER_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_SET_EVENT_FILTER_OFF] & HCI_SUPP_COMMANDS_SET_EVENT_FILTER_MASK)

#define HCI_SUPP_COMMANDS_FLUSH_MASK           0x02
#define HCI_SUPP_COMMANDS_FLUSH_OFF            6
#define HCI_FLUSH_SUPPORTED(x)           ((x)[HCI_SUPP_COMMANDS_FLUSH_OFF] & HCI_SUPP_COMMANDS_FLUSH_MASK)

#define HCI_SUPP_COMMANDS_READ_PIN_TYPE_MASK  0x04
#define HCI_SUPP_COMMANDS_READ_PIN_TYPE_OFF   6
#define HCI_READ_PIN_TYPE_SUPPORTED(x)  ((x)[HCI_SUPP_COMMANDS_READ_PIN_TYPE_OFF] & HCI_SUPP_COMMANDS_READ_PIN_TYPE_MASK)

#define HCI_SUPP_COMMANDS_WRITE_PIN_TYPE_MASK       0x08
#define HCI_SUPP_COMMANDS_WRITE_PIN_TYPE_OFF        6
#define HCI_WRITE_PIN_TYPE_SUPPORTED(x)       ((x)[HCI_SUPP_COMMANDS_WRITE_PIN_TYPE_OFF] & HCI_SUPP_COMMANDS_WRITE_PIN_TYPE_MASK)

#define HCI_SUPP_COMMANDS_CREATE_NEW_UNIT_KEY_MASK    0x10
#define HCI_SUPP_COMMANDS_CREATE_NEW_UNIT_KEY_OFF     6
#define HCI_CREATE_NEW_UNIT_KEY_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_CREATE_NEW_UNIT_KEY_OFF] & HCI_SUPP_COMMANDS_CREATE_NEW_UNIT_KEY_MASK)

#define HCI_SUPP_COMMANDS_READ_STORED_LINK_KEY_MASK    0x20
#define HCI_SUPP_COMMANDS_READ_STORED_LINK_KEY_OFF     6
#define HCI_READ_STORED_LINK_KEY_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_READ_STORED_LINK_KEY_OFF] & HCI_SUPP_COMMANDS_READ_STORED_LINK_KEY_MASK)

#define HCI_SUPP_COMMANDS_WRITE_STORED_LINK_KEY_MASK          0x40
#define HCI_SUPP_COMMANDS_WRITE_STORED_LINK_KEY_OFF           6
#define HCI_WRITE_STORED_LINK_KEY_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_WRITE_STORED_LINK_KEY_OFF] & HCI_SUPP_COMMANDS_WRITE_STORED_LINK_KEY_MASK)

#define HCI_SUPP_COMMANDS_DELETE_STORED_LINK_KEY_MASK          0x80
#define HCI_SUPP_COMMANDS_DELETE_STORED_LINK_KEY_OFF           6
#define HCI_DELETE_STORED_LINK_KEY_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_DELETE_STORED_LINK_KEY_OFF] & HCI_SUPP_COMMANDS_DELETE_STORED_LINK_KEY_MASK)

#define HCI_SUPP_COMMANDS_WRITE_LOCAL_NAME_MASK      0x01
#define HCI_SUPP_COMMANDS_WRITE_LOCAL_NAME_OFF       7
#define HCI_WRITE_LOCAL_NAME_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_WRITE_LOCAL_NAME_OFF] & HCI_SUPP_COMMANDS_WRITE_LOCAL_NAME_MASK)

#define HCI_SUPP_COMMANDS_READ_LOCAL_NAME_MASK           0x02
#define HCI_SUPP_COMMANDS_READ_LOCAL_NAME_OFF            7
#define HCI_READ_LOCAL_NAME_SUPPORTED(x)           ((x)[HCI_SUPP_COMMANDS_READ_LOCAL_NAME_OFF] & HCI_SUPP_COMMANDS_READ_LOCAL_NAME_MASK)

#define HCI_SUPP_COMMANDS_READ_CONN_ACCEPT_TOUT_MASK  0x04
#define HCI_SUPP_COMMANDS_READ_CONN_ACCEPT_TOUT_OFF   7
#define HCI_READ_CONN_ACCEPT_TOUT_SUPPORTED(x)  ((x)[HCI_SUPP_COMMANDS_READ_CONN_ACCEPT_TOUT_OFF] & HCI_SUPP_COMMANDS_READ_CONN_ACCEPT_TOUT_MASK)

#define HCI_SUPP_COMMANDS_WRITE_CONN_ACCEPT_TOUT_MASK       0x08
#define HCI_SUPP_COMMANDS_WRITE_CONN_ACCEPT_TOUT_OFF        7
#define HCI_WRITE_CONN_ACCEPT_TOUT_SUPPORTED(x)       ((x)[HCI_SUPP_COMMANDS_WRITE_CONN_ACCEPT_TOUT_OFF] & HCI_SUPP_COMMANDS_WRITE_CONN_ACCEPT_TOUT_MASK)

#define HCI_SUPP_COMMANDS_READ_PAGE_TOUT_MASK    0x10
#define HCI_SUPP_COMMANDS_READ_PAGE_TOUT_OFF     7
#define HCI_READ_PAGE_TOUT_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_READ_PAGE_TOUT_OFF] & HCI_SUPP_COMMANDS_READ_PAGE_TOUT_MASK)

#define HCI_SUPP_COMMANDS_WRITE_PAGE_TOUT_MASK    0x20
#define HCI_SUPP_COMMANDS_WRITE_PAGE_TOUT_OFF     7
#define HCI_WRITE_PAGE_TOUT_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_WRITE_PAGE_TOUT_OFF] & HCI_SUPP_COMMANDS_WRITE_PAGE_TOUT_MASK)

#define HCI_SUPP_COMMANDS_READ_SCAN_ENABLE_MASK          0x40
#define HCI_SUPP_COMMANDS_READ_SCAN_ENABLE_OFF           7
#define HCI_READ_SCAN_ENABLE_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_READ_SCAN_ENABLE_OFF] & HCI_SUPP_COMMANDS_READ_SCAN_ENABLE_MASK)

#define HCI_SUPP_COMMANDS_WRITE_SCAN_ENABLE_MASK          0x80
#define HCI_SUPP_COMMANDS_WRITE_SCAN_ENABLE_OFF           7
#define HCI_WRITE_SCAN_ENABLE_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_WRITE_SCAN_ENABLE_OFF] & HCI_SUPP_COMMANDS_WRITE_SCAN_ENABLE_MASK)

#define HCI_SUPP_COMMANDS_READ_PAGE_SCAN_ACTIVITY_MASK      0x01
#define HCI_SUPP_COMMANDS_READ_PAGE_SCAN_ACTIVITY_OFF       8
#define HCI_READ_PAGE_SCAN_ACTIVITY_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_READ_PAGE_SCAN_ACTIVITY_OFF] & HCI_SUPP_COMMANDS_READ_PAGE_SCAN_ACTIVITY_MASK)

#define HCI_SUPP_COMMANDS_WRITE_PAGE_SCAN_ACTIVITY_MASK           0x02
#define HCI_SUPP_COMMANDS_WRITE_PAGE_SCAN_ACTIVITY_OFF            8
#define HCI_WRITE_PAGE_SCAN_ACTIVITY_SUPPORTED(x)           ((x)[HCI_SUPP_COMMANDS_WRITE_PAGE_SCAN_ACTIVITY_OFF] & HCI_SUPP_COMMANDS_WRITE_PAGE_SCAN_ACTIVITY_MASK)

#define HCI_SUPP_COMMANDS_READ_INQURIY_SCAN_ACTIVITY_MASK  0x04
#define HCI_SUPP_COMMANDS_READ_INQURIY_SCAN_ACTIVITY_OFF   8
#define HCI_READ_INQURIY_SCAN_ACTIVITY_SUPPORTED(x)  ((x)[HCI_SUPP_COMMANDS_READ_INQURIY_SCAN_ACTIVITY_OFF] & HCI_SUPP_COMMANDS_READ_INQURIY_SCAN_ACTIVITY_MASK)

#define HCI_SUPP_COMMANDS_WRITE_INQURIY_SCAN_ACTIVITY_MASK       0x08
#define HCI_SUPP_COMMANDS_WRITE_INQURIY_SCAN_ACTIVITY_OFF        8
#define HCI_WRITE_INQURIY_SCAN_ACTIVITY_SUPPORTED(x)       ((x)[HCI_SUPP_COMMANDS_WRITE_INQURIY_SCAN_ACTIVITY_OFF] & HCI_SUPP_COMMANDS_WRITE_INQURIY_SCAN_ACTIVITY_MASK)

#define HCI_SUPP_COMMANDS_READ_AUTH_ENABLE_MASK    0x10
#define HCI_SUPP_COMMANDS_READ_AUTH_ENABLE_OFF     8
#define HCI_READ_AUTH_ENABLE_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_READ_AUTH_ENABLE_OFF] & HCI_SUPP_COMMANDS_READ_AUTH_ENABLE_MASK)

#define HCI_SUPP_COMMANDS_WRITE_AUTH_ENABLE_MASK    0x20
#define HCI_SUPP_COMMANDS_WRITE_AUTH_ENABLE_OFF     8
#define HCI_WRITE_AUTH_ENABLE_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_WRITE_AUTH_ENABLE_OFF] & HCI_SUPP_COMMANDS_WRITE_AUTH_ENABLE_MASK)

#define HCI_SUPP_COMMANDS_READ_ENCRYPT_ENABLE_MASK          0x40
#define HCI_SUPP_COMMANDS_READ_ENCRYPT_ENABLE_OFF           8
#define HCI_READ_ENCRYPT_ENABLE_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_READ_ENCRYPT_ENABLE_OFF] & HCI_SUPP_COMMANDS_READ_ENCRYPT_ENABLE_MASK)

#define HCI_SUPP_COMMANDS_WRITE_ENCRYPT_ENABLE_MASK          0x80
#define HCI_SUPP_COMMANDS_WRITE_ENCRYPT_ENABLE_OFF           8
#define HCI_WRITE_ENCRYPT_ENABLE_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_WRITE_ENCRYPT_ENABLE_OFF] & HCI_SUPP_COMMANDS_WRITE_ENCRYPT_ENABLE_MASK)

#define HCI_SUPP_COMMANDS_READ_CLASS_DEVICE_MASK      0x01
#define HCI_SUPP_COMMANDS_READ_CLASS_DEVICE_OFF       9
#define HCI_READ_CLASS_DEVICE_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_READ_CLASS_DEVICE_OFF] & HCI_SUPP_COMMANDS_READ_CLASS_DEVICE_MASK)

#define HCI_SUPP_COMMANDS_WRITE_CLASS_DEVICE_MASK           0x02
#define HCI_SUPP_COMMANDS_WRITE_CLASS_DEVICE_OFF            9
#define HCI_WRITE_CLASS_DEVICE_SUPPORTED(x)           ((x)[HCI_SUPP_COMMANDS_WRITE_CLASS_DEVICE_OFF] & HCI_SUPP_COMMANDS_WRITE_CLASS_DEVICE_MASK)

#define HCI_SUPP_COMMANDS_READ_VOICE_SETTING_MASK  0x04
#define HCI_SUPP_COMMANDS_READ_VOICE_SETTING_OFF   9
#define HCI_READ_VOICE_SETTING_SUPPORTED(x)  ((x)[HCI_SUPP_COMMANDS_READ_VOICE_SETTING_OFF] & HCI_SUPP_COMMANDS_READ_VOICE_SETTING_MASK)

#define HCI_SUPP_COMMANDS_WRITE_VOICE_SETTING_MASK       0x08
#define HCI_SUPP_COMMANDS_WRITE_VOICE_SETTING_OFF        9
#define HCI_WRITE_VOICE_SETTING_SUPPORTED(x)       ((x)[HCI_SUPP_COMMANDS_WRITE_VOICE_SETTING_OFF] & HCI_SUPP_COMMANDS_WRITE_VOICE_SETTING_MASK)

#define HCI_SUPP_COMMANDS_READ_AUTO_FLUSH_TOUT_MASK    0x10
#define HCI_SUPP_COMMANDS_READ_AUTO_FLUSH_TOUT_OFF     9
#define HCI_READ_AUTO_FLUSH_TOUT_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_READ_AUTO_FLUSH_TOUT_OFF] & HCI_SUPP_COMMANDS_READ_AUTO_FLUSH_TOUT_MASK)

#define HCI_SUPP_COMMANDS_WRITE_AUTO_FLUSH_TOUT_MASK    0x20
#define HCI_SUPP_COMMANDS_WRITE_AUTO_FLUSH_TOUT_OFF     9
#define HCI_WRITE_AUTO_FLUSH_TOUT_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_WRITE_AUTO_FLUSH_TOUT_OFF] & HCI_SUPP_COMMANDS_WRITE_AUTO_FLUSH_TOUT_MASK)

#define HCI_SUPP_COMMANDS_READ_NUM_BROAD_RETRANS_MASK          0x40
#define HCI_SUPP_COMMANDS_READ_NUM_BROAD_RETRANS_OFF           9
#define HCI_READ_NUM_BROAD_RETRANS_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_READ_NUM_BROAD_RETRANS_OFF] & HCI_SUPP_COMMANDS_READ_NUM_BROAD_RETRANS_MASK)

#define HCI_SUPP_COMMANDS_WRITE_NUM_BROAD_RETRANS_MASK          0x80
#define HCI_SUPP_COMMANDS_WRITE_NUM_BROAD_RETRANS_OFF           9
#define HCI_WRITE_NUM_BROAD_RETRANS_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_WRITE_NUM_BROAD_RETRANS_OFF] & HCI_SUPP_COMMANDS_WRITE_NUM_BROAD_RETRANS_MASK)

#define HCI_SUPP_COMMANDS_READ_HOLD_MODE_ACTIVITY_MASK      0x01
#define HCI_SUPP_COMMANDS_READ_HOLD_MODE_ACTIVITY_OFF       10
#define HCI_READ_HOLD_MODE_ACTIVITY_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_READ_HOLD_MODE_ACTIVITY_OFF] & HCI_SUPP_COMMANDS_READ_HOLD_MODE_ACTIVITY_MASK)

#define HCI_SUPP_COMMANDS_WRITE_HOLD_MODE_ACTIVITY_MASK           0x02
#define HCI_SUPP_COMMANDS_WRITE_HOLD_MODE_ACTIVITY_OFF            10
#define HCI_WRITE_HOLD_MODE_ACTIVITY_SUPPORTED(x)           ((x)[HCI_SUPP_COMMANDS_WRITE_HOLD_MODE_ACTIVITY_OFF] & HCI_SUPP_COMMANDS_WRITE_HOLD_MODE_ACTIVITY_MASK)

#define HCI_SUPP_COMMANDS_READ_TRANS_PWR_LEVEL_MASK  0x04
#define HCI_SUPP_COMMANDS_READ_TRANS_PWR_LEVEL_OFF   10
#define HCI_READ_TRANS_PWR_LEVEL_SUPPORTED(x)  ((x)[HCI_SUPP_COMMANDS_READ_TRANS_PWR_LEVEL_OFF] & HCI_SUPP_COMMANDS_READ_TRANS_PWR_LEVEL_MASK)

#define HCI_SUPP_COMMANDS_READ_SYNCH_FLOW_CTRL_ENABLE_MASK       0x08
#define HCI_SUPP_COMMANDS_READ_SYNCH_FLOW_CTRL_ENABLE_OFF        10
#define HCI_READ_SYNCH_FLOW_CTRL_ENABLE_SUPPORTED(x)       ((x)[HCI_SUPP_COMMANDS_READ_SYNCH_FLOW_CTRL_ENABLE_OFF] & HCI_SUPP_COMMANDS_READ_SYNCH_FLOW_CTRL_ENABLE_MASK)

#define HCI_SUPP_COMMANDS_WRITE_SYNCH_FLOW_CTRL_ENABLE_MASK    0x10
#define HCI_SUPP_COMMANDS_WRITE_SYNCH_FLOW_CTRL_ENABLE_OFF     10
#define HCI_WRITE_SYNCH_FLOW_CTRL_ENABLE_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_WRITE_SYNCH_FLOW_CTRL_ENABLE_OFF] & HCI_SUPP_COMMANDS_WRITE_SYNCH_FLOW_CTRL_ENABLE_MASK)

#define HCI_SUPP_COMMANDS_SET_HOST_CTRLR_TO_HOST_FC_MASK    0x20
#define HCI_SUPP_COMMANDS_SET_HOST_CTRLR_TO_HOST_FC_OFF     10
#define HCI_SET_HOST_CTRLR_TO_HOST_FC_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_SET_HOST_CTRLR_TO_HOST_FC_OFF] & HCI_SUPP_COMMANDS_SET_HOST_CTRLR_TO_HOST_FC_MASK)

#define HCI_SUPP_COMMANDS_HOST_BUFFER_SIZE_MASK          0x40
#define HCI_SUPP_COMMANDS_HOST_BUFFER_SIZE_OFF           10
#define HCI_HOST_BUFFER_SIZE_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_HOST_BUFFER_SIZE_OFF] & HCI_SUPP_COMMANDS_HOST_BUFFER_SIZE_MASK)

#define HCI_SUPP_COMMANDS_HOST_NUM_COMPLETED_PKTS_MASK          0x80
#define HCI_SUPP_COMMANDS_HOST_NUM_COMPLETED_PKTS_OFF           10
#define HCI_HOST_NUM_COMPLETED_PKTS_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_HOST_NUM_COMPLETED_PKTS_OFF] & HCI_SUPP_COMMANDS_HOST_NUM_COMPLETED_PKTS_MASK)

#define HCI_SUPP_COMMANDS_READ_LINK_SUP_TOUT_MASK      0x01
#define HCI_SUPP_COMMANDS_READ_LINK_SUP_TOUT_OFF       11
#define HCI_READ_LINK_SUP_TOUT_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_READ_LINK_SUP_TOUT_OFF] & HCI_SUPP_COMMANDS_READ_LINK_SUP_TOUT_MASK)

#define HCI_SUPP_COMMANDS_WRITE_LINK_SUP_TOUT_MASK           0x02
#define HCI_SUPP_COMMANDS_WRITE_LINK_SUP_TOUT_OFF            11
#define HCI_WRITE_LINK_SUP_TOUT_SUPPORTED(x)           ((x)[HCI_SUPP_COMMANDS_WRITE_LINK_SUP_TOUT_OFF] & HCI_SUPP_COMMANDS_WRITE_LINK_SUP_TOUT_MASK)

#define HCI_SUPP_COMMANDS_READ_NUM_SUPP_IAC_MASK  0x04
#define HCI_SUPP_COMMANDS_READ_NUM_SUPP_IAC_OFF   11
#define HCI_READ_NUM_SUPP_IAC_SUPPORTED(x)  ((x)[HCI_SUPP_COMMANDS_READ_NUM_SUPP_IAC_OFF] & HCI_SUPP_COMMANDS_READ_NUM_SUPP_IAC_MASK)

#define HCI_SUPP_COMMANDS_READ_CURRENT_IAC_LAP_MASK       0x08
#define HCI_SUPP_COMMANDS_READ_CURRENT_IAC_LAP_OFF        11
#define HCI_READ_CURRENT_IAC_LAP_SUPPORTED(x)       ((x)[HCI_SUPP_COMMANDS_READ_CURRENT_IAC_LAP_OFF] & HCI_SUPP_COMMANDS_READ_CURRENT_IAC_LAP_MASK)

#define HCI_SUPP_COMMANDS_WRITE_CURRENT_IAC_LAP_MASK    0x10
#define HCI_SUPP_COMMANDS_WRITE_CURRENT_IAC_LAP_OFF     11
#define HCI_WRITE_CURRENT_IAC_LAP_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_WRITE_CURRENT_IAC_LAP_OFF] & HCI_SUPP_COMMANDS_WRITE_CURRENT_IAC_LAP_MASK)

#define HCI_SUPP_COMMANDS_READ_PAGE_SCAN_PER_MODE_MASK    0x20
#define HCI_SUPP_COMMANDS_READ_PAGE_SCAN_PER_MODE_OFF     11
#define HCI_READ_PAGE_SCAN_PER_MODE_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_READ_PAGE_SCAN_PER_MODE_OFF] & HCI_SUPP_COMMANDS_READ_PAGE_SCAN_PER_MODE_MASK)

#define HCI_SUPP_COMMANDS_WRITE_PAGE_SCAN_PER_MODE_MASK          0x40
#define HCI_SUPP_COMMANDS_WRITE_PAGE_SCAN_PER_MODE_OFF           11
#define HCI_WRITE_PAGE_SCAN_PER_MODE_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_WRITE_PAGE_SCAN_PER_MODE_OFF] & HCI_SUPP_COMMANDS_WRITE_PAGE_SCAN_PER_MODE_MASK)

#define HCI_SUPP_COMMANDS_READ_PAGE_SCAN_MODE_MASK          0x80
#define HCI_SUPP_COMMANDS_READ_PAGE_SCAN_MODE_OFF           11
#define HCI_READ_PAGE_SCAN_MODE_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_READ_PAGE_SCAN_MODE_OFF] & HCI_SUPP_COMMANDS_READ_PAGE_SCAN_MODE_MASK)

#define HCI_SUPP_COMMANDS_WRITE_PAGE_SCAN_MODE_MASK      0x01
#define HCI_SUPP_COMMANDS_WRITE_PAGE_SCAN_MODE_OFF       12
#define HCI_WRITE_PAGE_SCAN_MODE_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_WRITE_PAGE_SCAN_MODE_OFF] & HCI_SUPP_COMMANDS_WRITE_PAGE_SCAN_MODE_MASK)

#define HCI_SUPP_COMMANDS_SET_AFH_CHNL_CLASS_MASK           0x02
#define HCI_SUPP_COMMANDS_SET_AFH_CHNL_CLASS_OFF            12
#define HCI_SET_AFH_CHNL_CLASS_SUPPORTED(x)           ((x)[HCI_SUPP_COMMANDS_SET_AFH_CHNL_CLASS_OFF] & HCI_SUPP_COMMANDS_SET_AFH_CHNL_CLASS_MASK)

#define HCI_SUPP_COMMANDS_READ_INQUIRY_SCAN_TYPE_MASK    0x10
#define HCI_SUPP_COMMANDS_READ_INQUIRY_SCAN_TYPE_OFF     12
#define HCI_READ_INQUIRY_SCAN_TYPE_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_READ_INQUIRY_SCAN_TYPE_OFF] & HCI_SUPP_COMMANDS_READ_INQUIRY_SCAN_TYPE_MASK)

#define HCI_SUPP_COMMANDS_WRITE_INQUIRY_SCAN_TYPE_MASK    0x20
#define HCI_SUPP_COMMANDS_WRITE_INQUIRY_SCAN_TYPE_OFF     12
#define HCI_WRITE_INQUIRY_SCAN_TYPE_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_WRITE_INQUIRY_SCAN_TYPE_OFF] & HCI_SUPP_COMMANDS_WRITE_INQUIRY_SCAN_TYPE_MASK)

#define HCI_SUPP_COMMANDS_READ_INQUIRY_MODE_MASK          0x40
#define HCI_SUPP_COMMANDS_READ_INQUIRY_MODE_OFF           12
#define HCI_READ_INQUIRY_MODE_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_READ_INQUIRY_MODE_OFF] & HCI_SUPP_COMMANDS_READ_INQUIRY_MODE_MASK)

#define HCI_SUPP_COMMANDS_WRITE_INQUIRY_MODE_MASK          0x80
#define HCI_SUPP_COMMANDS_WRITE_INQUIRY_MODE_OFF           12
#define HCI_WRITE_INQUIRY_MODE_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_WRITE_INQUIRY_MODE_OFF] & HCI_SUPP_COMMANDS_WRITE_INQUIRY_MODE_MASK)

#define HCI_SUPP_COMMANDS_READ_PAGE_SCAN_TYPE_MASK      0x01
#define HCI_SUPP_COMMANDS_READ_PAGE_SCAN_TYPE_OFF       13
#define HCI_READ_PAGE_SCAN_TYPE_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_READ_PAGE_SCAN_TYPE_OFF] & HCI_SUPP_COMMANDS_READ_PAGE_SCAN_TYPE_MASK)

#define HCI_SUPP_COMMANDS_WRITE_PAGE_SCAN_TYPE_MASK           0x02
#define HCI_SUPP_COMMANDS_WRITE_PAGE_SCAN_TYPE_OFF            13
#define HCI_WRITE_PAGE_SCAN_TYPE_SUPPORTED(x)           ((x)[HCI_SUPP_COMMANDS_WRITE_PAGE_SCAN_TYPE_OFF] & HCI_SUPP_COMMANDS_WRITE_PAGE_SCAN_TYPE_MASK)

#define HCI_SUPP_COMMANDS_READ_AFH_CHNL_ASSESS_MODE_MASK  0x04
#define HCI_SUPP_COMMANDS_READ_AFH_CHNL_ASSESS_MODE_OFF   13
#define HCI_READ_AFH_CHNL_ASSESS_MODE_SUPPORTED(x)  ((x)[HCI_SUPP_COMMANDS_READ_AFH_CHNL_ASSESS_MODE_OFF] & HCI_SUPP_COMMANDS_READ_AFH_CHNL_ASSESS_MODE_MASK)

#define HCI_SUPP_COMMANDS_WRITE_AFH_CHNL_ASSESS_MODE_MASK       0x08
#define HCI_SUPP_COMMANDS_WRITE_AFH_CHNL_ASSESS_MODE_OFF        13
#define HCI_WRITE_AFH_CHNL_ASSESS_MODE_SUPPORTED(x)       ((x)[HCI_SUPP_COMMANDS_WRITE_AFH_CHNL_ASSESS_MODE_OFF] & HCI_SUPP_COMMANDS_WRITE_AFH_CHNL_ASSESS_MODE_MASK)

#define HCI_SUPP_COMMANDS_READ_LOCAL_VER_INFO_MASK       0x08
#define HCI_SUPP_COMMANDS_READ_LOCAL_VER_INFO_OFF        14
#define HCI_READ_LOCAL_VER_INFO_SUPPORTED(x)       ((x)[HCI_SUPP_COMMANDS_READ_LOCAL_VER_INFO_OFF] & HCI_SUPP_COMMANDS_READ_LOCAL_VER_INFO_MASK)

#define HCI_SUPP_COMMANDS_READ_LOCAL_SUP_CMDS_MASK       0x10
#define HCI_SUPP_COMMANDS_READ_LOCAL_SUP_CMDS_OFF        14
#define HCI_READ_LOCAL_SUP_CMDS_SUPPORTED(x)       ((x)[HCI_SUPP_COMMANDS_READ_LOCAL_SUP_CMDS_OFF] & HCI_SUPP_COMMANDS_READ_LOCAL_SUP_CMDS_MASK)

#define HCI_SUPP_COMMANDS_READ_LOCAL_SUPP_FEATURES_MASK    0x20
#define HCI_SUPP_COMMANDS_READ_LOCAL_SUPP_FEATURES_OFF     14
#define HCI_READ_LOCAL_SUPP_FEATURES_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_READ_LOCAL_SUPP_FEATURES_OFF] & HCI_SUPP_COMMANDS_READ_LOCAL_SUPP_FEATURES_MASK)

#define HCI_SUPP_COMMANDS_READ_LOCAL_EXT_FEATURES_MASK          0x40
#define HCI_SUPP_COMMANDS_READ_LOCAL_EXT_FEATURES_OFF           14
#define HCI_READ_LOCAL_EXT_FEATURES_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_READ_LOCAL_EXT_FEATURES_OFF] & HCI_SUPP_COMMANDS_READ_LOCAL_EXT_FEATURES_MASK)

#define HCI_SUPP_COMMANDS_READ_BUFFER_SIZE_MASK          0x80
#define HCI_SUPP_COMMANDS_READ_BUFFER_SIZE_OFF           14
#define HCI_READ_BUFFER_SIZE_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_READ_BUFFER_SIZE_OFF] & HCI_SUPP_COMMANDS_READ_BUFFER_SIZE_MASK)

#define HCI_SUPP_COMMANDS_READ_COUNTRY_CODE_MASK      0x01
#define HCI_SUPP_COMMANDS_READ_COUNTRY_CODE_OFF       15
#define HCI_READ_COUNTRY_CODE_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_READ_COUNTRY_CODE_OFF] & HCI_SUPP_COMMANDS_READ_COUNTRY_CODE_MASK)

#define HCI_SUPP_COMMANDS_READ_BD_ADDR_MASK           0x02
#define HCI_SUPP_COMMANDS_READ_BD_ADDR_OFF            15
#define HCI_READ_BD_ADDR_SUPPORTED(x)           ((x)[HCI_SUPP_COMMANDS_READ_BD_ADDR_OFF] & HCI_SUPP_COMMANDS_READ_BD_ADDR_MASK)

#define HCI_SUPP_COMMANDS_READ_FAIL_CONTACT_CNTR_MASK  0x04
#define HCI_SUPP_COMMANDS_READ_FAIL_CONTACT_CNTR_OFF   15
#define HCI_READ_FAIL_CONTACT_CNTR_SUPPORTED(x)  ((x)[HCI_SUPP_COMMANDS_READ_FAIL_CONTACT_CNTR_OFF] & HCI_SUPP_COMMANDS_READ_FAIL_CONTACT_CNTR_MASK)

#define HCI_SUPP_COMMANDS_RESET_FAIL_CONTACT_CNTR_MASK       0x08
#define HCI_SUPP_COMMANDS_RESET_FAIL_CONTACT_CNTR_OFF        15
#define HCI_RESET_FAIL_CONTACT_CNTR_SUPPORTED(x)       ((x)[HCI_SUPP_COMMANDS_RESET_FAIL_CONTACT_CNTR_OFF] & HCI_SUPP_COMMANDS_RESET_FAIL_CONTACT_CNTR_MASK)

#define HCI_SUPP_COMMANDS_GET_LINK_QUALITY_MASK    0x10
#define HCI_SUPP_COMMANDS_GET_LINK_QUALITY_OFF     15
#define HCI_GET_LINK_QUALITY_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_GET_LINK_QUALITY_OFF] & HCI_SUPP_COMMANDS_GET_LINK_QUALITY_MASK)

#define HCI_SUPP_COMMANDS_READ_RSSI_MASK    0x20
#define HCI_SUPP_COMMANDS_READ_RSSI_OFF     15
#define HCI_READ_RSSI_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_READ_RSSI_OFF] & HCI_SUPP_COMMANDS_READ_RSSI_MASK)

#define HCI_SUPP_COMMANDS_READ_AFH_CH_MAP_MASK          0x40
#define HCI_SUPP_COMMANDS_READ_AFH_CH_MAP_OFF           15
#define HCI_READ_AFH_CH_MAP_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_READ_AFH_CH_MAP_OFF] & HCI_SUPP_COMMANDS_READ_AFH_CH_MAP_MASK)

#define HCI_SUPP_COMMANDS_READ_BD_CLOCK_MASK          0x80
#define HCI_SUPP_COMMANDS_READ_BD_CLOCK_OFF           15
#define HCI_READ_BD_CLOCK_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_READ_BD_CLOCK_OFF] & HCI_SUPP_COMMANDS_READ_BD_CLOCK_MASK)

#define HCI_SUPP_COMMANDS_READ_LOOPBACK_MODE_MASK      0x01
#define HCI_SUPP_COMMANDS_READ_LOOPBACK_MODE_OFF       16
#define HCI_READ_LOOPBACK_MODE_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_READ_LOOPBACK_MODE_OFF] & HCI_SUPP_COMMANDS_READ_LOOPBACK_MODE_MASK)

#define HCI_SUPP_COMMANDS_WRITE_LOOPBACK_MODE_MASK           0x02
#define HCI_SUPP_COMMANDS_WRITE_LOOPBACK_MODE_OFF            16
#define HCI_WRITE_LOOPBACK_MODE_SUPPORTED(x)           ((x)[HCI_SUPP_COMMANDS_WRITE_LOOPBACK_MODE_OFF] & HCI_SUPP_COMMANDS_WRITE_LOOPBACK_MODE_MASK)

#define HCI_SUPP_COMMANDS_ENABLE_DEV_UNDER_TEST_MASK  0x04
#define HCI_SUPP_COMMANDS_ENABLE_DEV_UNDER_TEST_OFF   16
#define HCI_ENABLE_DEV_UNDER_TEST_SUPPORTED(x)  ((x)[HCI_SUPP_COMMANDS_ENABLE_DEV_UNDER_TEST_OFF] & HCI_SUPP_COMMANDS_ENABLE_DEV_UNDER_TEST_MASK)

#define HCI_SUPP_COMMANDS_SETUP_SYNCH_CONN_MASK       0x08
#define HCI_SUPP_COMMANDS_SETUP_SYNCH_CONN_OFF        16
#define HCI_SETUP_SYNCH_CONN_SUPPORTED(x)       ((x)[HCI_SUPP_COMMANDS_SETUP_SYNCH_CONN_OFF] & HCI_SUPP_COMMANDS_SETUP_SYNCH_CONN_MASK)

#define HCI_SUPP_COMMANDS_ACCEPT_SYNCH_CONN_MASK    0x10
#define HCI_SUPP_COMMANDS_ACCEPT_SYNCH_CONN_OFF     16
#define HCI_ACCEPT_SYNCH_CONN_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_ACCEPT_SYNCH_CONN_OFF] & HCI_SUPP_COMMANDS_ACCEPT_SYNCH_CONN_MASK)

#define HCI_SUPP_COMMANDS_REJECT_SYNCH_CONN_MASK    0x20
#define HCI_SUPP_COMMANDS_REJECT_SYNCH_CONN_OFF     16
#define HCI_REJECT_SYNCH_CONN_SUPPORTED(x)    ((x)[HCI_SUPP_COMMANDS_REJECT_SYNCH_CONN_OFF] & HCI_SUPP_COMMANDS_REJECT_SYNCH_CONN_MASK)

#define HCI_SUPP_COMMANDS_READ_EXT_INQUIRY_RESP_MASK   0x01
#define HCI_SUPP_COMMANDS_READ_EXT_INQUIRY_RESP_OFF    17
#define HCI_READ_EXT_INQUIRY_RESP_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_READ_EXT_INQUIRY_RESP_OFF] & HCI_SUPP_COMMANDS_READ_EXT_INQUIRY_RESP_MASK)

#define HCI_SUPP_COMMANDS_WRITE_EXT_INQUIRY_RESP_MASK  0x02
#define HCI_SUPP_COMMANDS_WRITE_EXT_INQUIRY_RESP_OFF   17
#define HCI_WRITE_EXT_INQUIRY_RESP_SUPPORTED(x)  ((x)[HCI_SUPP_COMMANDS_WRITE_EXT_INQUIRY_RESP_OFF] & HCI_SUPP_COMMANDS_WRITE_EXT_INQUIRY_RESP_MASK)

#define HCI_SUPP_COMMANDS_REFRESH_ENCRYPTION_KEY_MASK   0x04
#define HCI_SUPP_COMMANDS_REFRESH_ENCRYPTION_KEY_OFF    17
#define HCI_REFRESH_ENCRYPTION_KEY_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_REFRESH_ENCRYPTION_KEY_OFF] & HCI_SUPP_COMMANDS_REFRESH_ENCRYPTION_KEY_MASK)

/* Octet 17, bit 3 is reserved */

#define HCI_SUPP_COMMANDS_SNIFF_SUB_RATE_MASK       0x10
#define HCI_SUPP_COMMANDS_SNIFF_SUB_RATE_OFF        17
#define HCI_SNIFF_SUB_RATE_CMD_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_SNIFF_SUB_RATE_OFF] & HCI_SUPP_COMMANDS_SNIFF_SUB_RATE_MASK)

#define HCI_SUPP_COMMANDS_READ_SIMPLE_PAIRING_MODE_MASK   0x20
#define HCI_SUPP_COMMANDS_READ_SIMPLE_PAIRING_MODE_OFF    17
#define HCI_READ_SIMPLE_PAIRING_MODE_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_READ_SIMPLE_PAIRING_MODE_OFF] & HCI_SUPP_COMMANDS_READ_SIMPLE_PAIRING_MODE_MASK)

#define HCI_SUPP_COMMANDS_WRITE_SIMPLE_PAIRING_MODE_MASK   0x40
#define HCI_SUPP_COMMANDS_WRITE_SIMPLE_PAIRING_MODE_OFF    17
#define HCI_WRITE_SIMPLE_PAIRING_MODE_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_WRITE_SIMPLE_PAIRING_MODE_OFF] & HCI_SUPP_COMMANDS_WRITE_SIMPLE_PAIRING_MODE_MASK)

#define HCI_SUPP_COMMANDS_READ_LOCAL_OOB_DATA_MASK   0x80
#define HCI_SUPP_COMMANDS_READ_LOCAL_OOB_DATA_OFF    17
#define HCI_READ_LOCAL_OOB_DATA_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_READ_LOCAL_OOB_DATA_OFF] & HCI_SUPP_COMMANDS_READ_LOCAL_OOB_DATA_MASK)

#define HCI_SUPP_COMMANDS_READ_INQUIRY_RESPONSE_TX_POWER_MASK   0x01
#define HCI_SUPP_COMMANDS_READ_INQUIRY_RESPONSE_TX_POWER_OFF    18
#define HCI_READ_INQUIRY_RESPONSE_TX_POWER_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_READ_INQUIRY_RESPONSE_TX_POWER_OFF] & HCI_SUPP_COMMANDS_READ_INQUIRY_RESPONSE_TX_POWER_MASK)

#define HCI_SUPP_COMMANDS_WRITE_INQUIRY_RESPONSE_TX_POWER_MASK   0x02
#define HCI_SUPP_COMMANDS_WRITE_INQUIRY_RESPONSE_TX_POWER_OFF    18
#define HCI_WRITE_INQUIRY_RESPONSE_TX_POWER_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_WRITE_INQUIRY_RESPONSE_TX_POWER_OFF] & HCI_SUPP_COMMANDS_WRITE_INQUIRY_RESPONSE_TX_POWER_MASK)

#define HCI_SUPP_COMMANDS_READ_DEFAULT_ERRONEOUS_DATA_REPORTING_MASK   0x04
#define HCI_SUPP_COMMANDS_READ_DEFAULT_ERRONEOUS_DATA_REPORTING_OFF    18
#define HCI_READ_DEFAULT_ERRONEOUS_DATA_REPORTING_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_READ_DEFAULT_ERRONEOUS_DATA_REPORTING_OFF] & HCI_SUPP_COMMANDS_READ_DEFAULT_ERRONEOUS_DATA_REPORTING_MASK)

#define HCI_SUPP_COMMANDS_WRITE_DEFAULT_ERRONEOUS_DATA_REPORTING_MASK   0x08
#define HCI_SUPP_COMMANDS_WRITE_DEFAULT_ERRONEOUS_DATA_REPORTING_OFF    18
#define HCI_WRITE_DEFAULT_ERRONEOUS_DATA_REPORTING_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_WRITE_DEFAULT_ERRONEOUS_DATA_REPORTING_OFF] & HCI_SUPP_COMMANDS_WRITE_DEFAULT_ERRONEOUS_DATA_REPORTING_MASK)

#define HCI_SUPP_COMMANDS_IO_CAPABILITY_RESPONSE_MASK   0x80
#define HCI_SUPP_COMMANDS_IO_CAPABILITY_RESPONSE_OFF    18
#define HCI_IO_CAPABILITY_RESPONSE_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_IO_CAPABILITY_RESPONSE_OFF] & HCI_SUPP_COMMANDS_IO_CAPABILITY_RESPONSE_MASK)

#define HCI_SUPP_COMMANDS_USER_CONFIRMATION_REQUEST_REPLY_MASK   0x01
#define HCI_SUPP_COMMANDS_USER_CONFIRMATION_REQUEST_REPLY_OFF    19
#define HCI_USER_CONFIRMATION_REQUEST_REPLY_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_USER_CONFIRMATION_REQUEST_REPLY_OFF] & HCI_SUPP_COMMANDS_USER_CONFIRMATION_REQUEST_REPLY_MASK)

#define HCI_SUPP_COMMANDS_USER_CONFIRMATION_REQUEST_NEG_REPLY_MASK   0x02
#define HCI_SUPP_COMMANDS_USER_CONFIRMATION_REQUEST_NEG_REPLY_OFF    19
#define HCI_USER_CONFIRMATION_REQUEST_NEG_REPLY_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_USER_CONFIRMATION_REQUEST_NEG_REPLY_OFF] & HCI_SUPP_COMMANDS_USER_CONFIRMATION_REQUEST_NEG_REPLY_MASK)

#define HCI_SUPP_COMMANDS_USER_PASSKEY_REQUEST_REPLY_MASK   0x04
#define HCI_SUPP_COMMANDS_USER_PASSKEY_REQUEST_REPLY_OFF    19
#define HCI_USER_PASSKEY_REQUEST_REPLY_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_USER_PASSKEY_REQUEST_REPLY_OFF] & HCI_SUPP_COMMANDS_USER_PASSKEY_REQUEST_REPLY_MASK)

#define HCI_SUPP_COMMANDS_USER_PASSKEY_REQUEST_NEG_REPLY_MASK   0x08
#define HCI_SUPP_COMMANDS_USER_PASSKEY_REQUEST_NEG_REPLY_OFF    19
#define HCI_USER_PASSKEY_REQUEST_NEG_REPLY_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_USER_PASSKEY_REQUEST_NEG_REPLY_OFF] & HCI_SUPP_COMMANDS_USER_PASSKEY_REQUEST_NEG_REPLY_MASK)

#define HCI_SUPP_COMMANDS_REMOTE_OOB_DATA_REQUEST_REPLY_MASK   0x10
#define HCI_SUPP_COMMANDS_REMOTE_OOB_DATA_REQUEST_REPLY_OFF    19
#define HCI_REMOTE_OOB_DATA_REQUEST_REPLY_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_REMOTE_OOB_DATA_REQUEST_REPLY_OFF] & HCI_SUPP_COMMANDS_REMOTE_OOB_DATA_REQUEST_REPLY_MASK)

#define HCI_SUPP_COMMANDS_WRITE_SIMPLE_PAIRING_DBG_MODE_MASK       0x20
#define HCI_SUPP_COMMANDS_WRITE_SIMPLE_PAIRING_DBG_MODE_OFF        19
#define HCI_WRITE_SIMPLE_PAIRING_DBG_MODE_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_WRITE_SIMPLE_PAIRING_DBG_MODE_OFF] & HCI_SUPP_COMMANDS_WRITE_SIMPLE_PAIRING_DBG_MODE_MASK)

#define HCI_SUPP_COMMANDS_ENHANCED_FLUSH_MASK   0x40
#define HCI_SUPP_COMMANDS_ENHANCED_FLUSH_OFF    19
#define HCI_ENHANCED_FLUSH_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_ENHANCED_FLUSH_OFF] & HCI_SUPP_COMMANDS_ENHANCED_FLUSH_MASK)

#define HCI_SUPP_COMMANDS_REMOTE_OOB_DATA_REQUEST_NEG_REPLY_MASK       0x80
#define HCI_SUPP_COMMANDS_REMOTE_OOB_DATA_REQUEST_NEG_REPLY_OFF        19
#define HCI_REMOTE_OOB_DATA_REQUEST_NEG_REPLY_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_REMOTE_OOB_DATA_REQUEST_NEG_REPLY_OFF] & HCI_SUPP_COMMANDS_REMOTE_OOB_DATA_REQUEST_NEG_REPLY_MASK)

/* Supported Commands (Byte 20) */
#define HCI_SUPP_COMMANDS_SEND_KEYPRESS_NOTIF_MASK       0x04
#define HCI_SUPP_COMMANDS_SEND_KEYPRESS_NOTIF_OFF        20
#define HCI_SEND_NOTIF_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_SEND_KEYPRESS_NOTIF_OFF] & HCI_SUPP_COMMANDS_SEND_KEYPRESS_NOTIF_MASK)

#define HCI_SUPP_COMMANDS_IO_CAP_REQ_NEG_REPLY_MASK      0x08
#define HCI_SUPP_COMMANDS_IO_CAP_REQ_NEG_REPLY_OFF       20
#define HCI_IO_CAP_REQ_NEG_REPLY_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_IO_CAP_REQ_NEG_REPLY_OFF] & HCI_SUPP_COMMANDS_IO_CAP_REQ_NEG_REPLY_MASK)

#define HCI_SUPP_COMMANDS_READ_ENCR_KEY_SIZE_MASK      0x10
#define HCI_SUPP_COMMANDS_READ_ENCR_KEY_SIZE_OFF       20
#define HCI_READ_ENCR_KEY_SIZE_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_READ_ENCR_KEY_SIZE_OFF] & HCI_SUPP_COMMANDS_READ_ENCR_KEY_SIZE_MASK)

/* Supported Commands (Byte 21) */
#define HCI_SUPP_COMMANDS_CREATE_PHYSICAL_LINK_MASK   0x01
#define HCI_SUPP_COMMANDS_CREATE_PHYSICAL_LINK_OFF    21
#define HCI_CREATE_PHYSICAL_LINK_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_CREATE_PHYSICAL_LINK_OFF] & HCI_SUPP_COMMANDS_CREATE_PHYSICAL_LINK_MASK)

#define HCI_SUPP_COMMANDS_ACCEPT_PHYSICAL_LINK_MASK   0x02
#define HCI_SUPP_COMMANDS_ACCEPT_PHYSICAL_LINK_OFF    21
#define HCI_ACCEPT_PHYSICAL_LINK_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_ACCEPT_PHYSICAL_LINK_OFF] & HCI_SUPP_COMMANDS_ACCEPT_PHYSICAL_LINK_MASK)

#define HCI_SUPP_COMMANDS_DISCONNECT_PHYSICAL_LINK_MASK   0x04
#define HCI_SUPP_COMMANDS_DISCONNECT_PHYSICAL_LINK_OFF    21
#define HCI_DISCONNECT_PHYSICAL_LINK_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_DISCONNECT_PHYSICAL_LINK_OFF] & HCI_SUPP_COMMANDS_DISCONNECT_PHYSICAL_LINK_MASK)

#define HCI_SUPP_COMMANDS_CREATE_LOGICAL_LINK_MASK   0x08
#define HCI_SUPP_COMMANDS_CREATE_LOGICAL_LINK_OFF    21
#define HCI_CREATE_LOGICAL_LINK_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_CREATE_LOGICAL_LINK_OFF] & HCI_SUPP_COMMANDS_CREATE_LOGICAL_LINK_MASK)

#define HCI_SUPP_COMMANDS_ACCEPT_LOGICAL_LINK_MASK   0x10
#define HCI_SUPP_COMMANDS_ACCEPT_LOGICAL_LINK_OFF    21
#define HCI_ACCEPT_LOGICAL_LINK_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_ACCEPT_LOGICAL_LINK_OFF] & HCI_SUPP_COMMANDS_ACCEPT_LOGICAL_LINK_MASK)

#define HCI_SUPP_COMMANDS_DISCONNECT_LOGICAL_LINK_MASK   0x20
#define HCI_SUPP_COMMANDS_DISCONNECT_LOGICAL_LINK_OFF    21
#define HCI_DISCONNECT_LOGICAL_LINK_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_DISCONNECT_LOGICAL_LINK_OFF] & HCI_SUPP_COMMANDS_DISCONNECT_LOGICAL_LINK_MASK)

#define HCI_SUPP_COMMANDS_LOGICAL_LINK_CANCEL_MASK   0x40
#define HCI_SUPP_COMMANDS_LOGICAL_LINK_CANCEL_OFF    21
#define HCI_LOGICAL_LINK_CANCEL_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_LOGICAL_LINK_CANCEL_OFF] & HCI_SUPP_COMMANDS_LOGICAL_LINK_CANCEL_MASK)

#define HCI_SUPP_COMMANDS_FLOW_SPEC_MODIFY_MASK       0x80
#define HCI_SUPP_COMMANDS_FLOW_SPEC_MODIFY_OFF        21
#define HCI_FLOW_SPEC_MODIFY_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_FLOW_SPEC_MODIFY_OFF] & HCI_SUPP_COMMANDS_FLOW_SPEC_MODIFY_MASK)

/* Supported Commands (Byte 22) */
#define HCI_SUPP_COMMANDS_READ_LOGICAL_LINK_ACCEPT_TIMEOUT_MASK   0x01
#define HCI_SUPP_COMMANDS_READ_LOGICAL_LINK_ACCEPT_TIMEOUT_OFF    22
#define HCI_READ_LOGICAL_LINK_ACCEPT_TIMEOUT_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_READ_LOGICAL_LINK_ACCEPT_TIMEOUT_OFF] & HCI_SUPP_COMMANDS_READ_LOGICAL_LINK_ACCEPT_TIMEOUT_MASK)

#define HCI_SUPP_COMMANDS_WRITE_LOGICAL_LINK_ACCEPT_TIMEOUT_MASK   0x02
#define HCI_SUPP_COMMANDS_WRITE_LOGICAL_LINK_ACCEPT_TIMEOUT_OFF    22
#define HCI_WRITE_LOGICAL_LINK_ACCEPT_TIMEOUT_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_WRITE_LOGICAL_LINK_ACCEPT_TIMEOUT_OFF] & HCI_SUPP_COMMANDS_WRITE_LOGICAL_LINK_ACCEPT_TIMEOUT_MASK)

#define HCI_SUPP_COMMANDS_SET_EVENT_MASK_PAGE_2_MASK   0x04
#define HCI_SUPP_COMMANDS_SET_EVENT_MASK_PAGE_2_OFF    22
#define HCI_SET_EVENT_MASK_PAGE_2_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_SET_EVENT_MASK_PAGE_2_OFF] & HCI_SUPP_COMMANDS_SET_EVENT_MASK_PAGE_2_MASK)

#define HCI_SUPP_COMMANDS_READ_LOCATION_DATA_MASK   0x08
#define HCI_SUPP_COMMANDS_READ_LOCATION_DATA_OFF    22
#define HCI_READ_LOCATION_DATA_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_READ_LOCATION_DATA_OFF] & HCI_SUPP_COMMANDS_READ_LOCATION_DATA_MASK)

#define HCI_SUPP_COMMANDS_WRITE_LOCATION_DATA_MASK   0x10
#define HCI_SUPP_COMMANDS_WRITE_LOCATION_DATA_OFF    22
#define HCI_WRITE_LOCATION_DATA_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_WRITE_LOCATION_DATA_OFF] & HCI_SUPP_COMMANDS_WRITE_LOCATION_DATA_MASK)

#define HCI_SUPP_COMMANDS_READ_LOCAL_AMP_INFO_MASK   0x20
#define HCI_SUPP_COMMANDS_READ_LOCAL_AMP_INFO_OFF    22
#define HCI_READ_LOCAL_AMP_INFO_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_READ_LOCAL_AMP_INFO_OFF] & HCI_SUPP_COMMANDS_READ_LOCAL_AMP_INFO_MASK)

#define HCI_SUPP_COMMANDS_READ_LOCAL_AMP_ASSOC_MASK   0x40
#define HCI_SUPP_COMMANDS_READ_LOCAL_AMP_ASSOC_OFF    22
#define HCI_READ_LOCAL_AMP_ASSOC_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_READ_LOCAL_AMP_ASSOC_OFF] & HCI_SUPP_COMMANDS_READ_LOCAL_AMP_ASSOC_MASK)

#define HCI_SUPP_COMMANDS_WRITE_REMOTE_AMP_ASSOC_MASK   0x80
#define HCI_SUPP_COMMANDS_WRITE_REMOTE_AMP_ASSOC_OFF    22
#define HCI_WRITE_REMOTE_AMP_ASSOC_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_WRITE_REMOTE_AMP_ASSOC_OFF] & HCI_SUPP_COMMANDS_WRITE_REMOTE_AMP_ASSOC_MASK)

/* Supported Commands (Byte 23) */
#define HCI_SUPP_COMMANDS_READ_FLOW_CONTROL_MODE_MASK   0x01
#define HCI_SUPP_COMMANDS_READ_FLOW_CONTROL_MODE_OFF    23
#define HCI_READ_FLOW_CONTROL_MODE_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_READ_FLOW_CONTROL_MODE_OFF] & HCI_SUPP_COMMANDS_READ_FLOW_CONTROL_MODE_MASK)

#define HCI_SUPP_COMMANDS_WRITE_FLOW_CONTROL_MODE_MASK   0x02
#define HCI_SUPP_COMMANDS_WRITE_FLOW_CONTROL_MODE_OFF    23
#define HCI_WRITE_FLOW_CONTROL_MODE_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_WRITE_FLOW_CONTROL_MODE_OFF] & HCI_SUPP_COMMANDS_WRITE_FLOW_CONTROL_MODE_MASK)

#define HCI_SUPP_COMMANDS_READ_DATA_BLOCK_SIZE_MASK   0x04
#define HCI_SUPP_COMMANDS_READ_DATA_BLOCK_SIZE_OFF    23
#define HCI_READ_DATA_BLOCK_SIZE_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_READ_DATA_BLOCK_SIZE_OFF] & HCI_SUPP_COMMANDS_READ_DATA_BLOCK_SIZE_MASK)

#define HCI_SUPP_COMMANDS_ENABLE_AMP_RCVR_REPORTS_MASK   0x20
#define HCI_SUPP_COMMANDS_ENABLE_AMP_RCVR_REPORTS_OFF    23
#define HCI_ENABLE_AMP_RCVR_REPORTS_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_ENABLE_AMP_RCVR_REPORTS_OFF] & HCI_SUPP_COMMANDS_ENABLE_AMP_RCVR_REPORTS_MASK)

#define HCI_SUPP_COMMANDS_AMP_TEST_END_MASK   0x40
#define HCI_SUPP_COMMANDS_AMP_TEST_END_OFF    23
#define HCI_AMP_TEST_END_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_AMP_TEST_END_OFF] & HCI_SUPP_COMMANDS_AMP_TEST_END_MASK)

#define HCI_SUPP_COMMANDS_AMP_TEST_MASK   0x80
#define HCI_SUPP_COMMANDS_AMP_TEST_OFF    23
#define HCI_AMP_TEST_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_AMP_TEST_OFF] & HCI_SUPP_COMMANDS_AMP_TEST_MASK)

/* Supported Commands (Byte 24) */
#define HCI_SUPP_COMMANDS_READ_TRANSMIT_POWER_LEVEL_MASK   0x01
#define HCI_SUPP_COMMANDS_READ_TRANSMIT_POWER_LEVEL_OFF    24
#define HCI_READ_TRANSMIT_POWER_LEVEL_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_READ_TRANSMIT_POWER_LEVEL_OFF] & HCI_SUPP_COMMANDS_READ_TRANSMIT_POWER_LEVEL_MASK)

#define HCI_SUPP_COMMANDS_READ_BE_FLUSH_TOUT_MASK   0x04
#define HCI_SUPP_COMMANDS_READ_BE_FLUSH_TOUT_OFF    24
#define HCI_READ_BE_FLUSH_TOUT_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_READ_BE_FLUSH_TOUT_OFF] & HCI_SUPP_COMMANDS_READ_BE_FLUSH_TOUT_MASK)

#define HCI_SUPP_COMMANDS_WRITE_BE_FLUSH_TOUT_MASK   0x08
#define HCI_SUPP_COMMANDS_WRITE_BE_FLUSH_TOUT_OFF    24
#define HCI_WRITE_BE_FLUSH_TOUT_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_WRITE_BE_FLUSH_TOUT_OFF] & HCI_SUPP_COMMANDS_WRITE_BE_FLUSH_TOUT_MASK)

#define HCI_SUPP_COMMANDS_SHORT_RANGE_MODE_MASK   0x10
#define HCI_SUPP_COMMANDS_SHORT_RANGE_MODE_OFF    24
#define HCI_SHORT_RANGE_MODE_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_SHORT_RANGE_MODE_OFF] & HCI_SUPP_COMMANDS_SHORT_RANGE_MODE_MASK)

/* LE commands TBD
** Supported Commands (Byte 24 continued)
** Supported Commands (Byte 25)
** Supported Commands (Byte 26)
** Supported Commands (Byte 27)
** Supported Commands (Byte 28)
*/

/* Supported Commands (Byte 29) */
#define HCI_SUPP_COMMANDS_ENH_SETUP_SYNCH_CONN_MASK     0x08
#define HCI_SUPP_COMMANDS_ENH_SETUP_SYNCH_CONN_OFF      29
#define HCI_READ_ENH_SETUP_SYNCH_CONN_SUPPORTED(x)      ((x)[HCI_SUPP_COMMANDS_ENH_SETUP_SYNCH_CONN_OFF] & HCI_SUPP_COMMANDS_ENH_SETUP_SYNCH_CONN_MASK)

#define HCI_SUPP_COMMANDS_ENH_ACCEPT_SYNCH_CONN_MASK    0x10
#define HCI_SUPP_COMMANDS_ENH_ACCEPT_SYNCH_CONN_OFF     29
#define HCI_READ_ENH_ACCEPT_SYNCH_CONN_SUPPORTED(x)     ((x)[HCI_SUPP_COMMANDS_ENH_ACCEPT_SYNCH_CONN_OFF] & HCI_SUPP_COMMANDS_ENH_ACCEPT_SYNCH_CONN_MASK)

#define HCI_SUPP_COMMANDS_READ_LOCAL_CODECS_MASK        0x20
#define HCI_SUPP_COMMANDS_READ_LOCAL_CODECS_OFF         29
#define HCI_READ_LOCAL_CODECS_SUPPORTED(x)              ((x)[HCI_SUPP_COMMANDS_READ_LOCAL_CODECS_OFF] & HCI_SUPP_COMMANDS_READ_LOCAL_CODECS_MASK)

#define HCI_SUPP_COMMANDS_SET_MWS_CHANN_PARAM_MASK      0x40
#define HCI_SUPP_COMMANDS_SET_MWS_CHANN_PARAM_OFF       29
#define HCI_SET_MWS_CHANNEL_PARAMETERS_SUPPORTED(x)     ((x)[HCI_SUPP_COMMANDS_SET_MWS_CHANN_PARAM_OFF] & HCI_SUPP_COMMANDS_SET_MWS_CHANN_PARAM_MASK)

#define HCI_SUPP_COMMANDS_SET_EXT_FRAME_CONF_MASK       0x80
#define HCI_SUPP_COMMANDS_SET_EXT_FRAME_CONF_OFF        29
#define HCI_SET_EXTERNAL_FRAME_CONFIGURATION_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_SET_EXT_FRAME_CONF_OFF] & HCI_SUPP_COMMANDS_SET_EXT_FRAME_CONF_MASK)


/* Supported Commands (Byte 30) */
#define HCI_SUPP_COMMANDS_SET_MWS_SIGNALING_MASK     0x01
#define HCI_SUPP_COMMANDS_SET_MWS_SIGNALING_OFF      30
#define HCI_SET_MWS_SIGNALING_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_SET_MWS_SIGNALING_OFF] & HCI_SUPP_COMMANDS_SET_MWS_SIGNALING_MASK)

#define HCI_SUPP_COMMANDS_SET_MWS_TRANS_LAYER_MASK   0x02
#define HCI_SUPP_COMMANDS_SET_MWS_TRANS_LAYER_OFF    30
#define HCI_SET_MWS_TRANSPORT_LAYER_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_SET_MWS_TRANS_LAYER_OFF] & HCI_SUPP_COMMANDS_SET_MWS_TRANS_LAYER_MASK)

#define HCI_SUPP_COMMANDS_SET_MWS_SCAN_FREQ_TABLE_MASK   0x04
#define HCI_SUPP_COMMANDS_SET_MWS_SCAN_FREQ_TABLE_OFF    30
#define HCI_SET_MWS_SCAN_FREQUENCY_TABLE_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_SET_MWS_SCAN_FREQ_TABLE_OFF] & HCI_SUPP_COMMANDS_SET_MWS_SCAN_FREQ_TABLE_MASK)

#define HCI_SUPP_COMMANDS_GET_TRANS_LAYER_CONF_MASK      0x08
#define HCI_SUPP_COMMANDS_GET_TRANS_LAYER_CONF_OFF    30
#define HCI_GET_MWS_TRANS_LAYER_CFG_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_GET_TRANS_LAYER_CONF_OFF] & HCI_SUPP_COMMANDS_GET_TRANS_LAYER_CONF_MASK)

#define HCI_SUPP_COMMANDS_SET_MWS_PATTERN_CONF_MASK      0x10
#define HCI_SUPP_COMMANDS_SET_MWS_PATTERN_CONF_OFF       30
#define HCI_SET_MWS_PATTERN_CONFIGURATION_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_SET_MWS_PATTERN_CONF_OFF] & HCI_SUPP_COMMANDS_SET_MWS_PATTERN_CONF_MASK)

/* Supported Commands (Byte 30 bit 5) */
#define HCI_SUPP_COMMANDS_SET_TRIG_CLK_CAP_MASK         0x20
#define HCI_SUPP_COMMANDS_SET_TRIG_CLK_CAP_OFF          30
#define HCI_SET_TRIG_CLK_CAP_SUPPORTED(x)               ((x)[HCI_SUPP_COMMANDS_SET_TRIG_CLK_CAP_OFF] & HCI_SUPP_COMMANDS_SET_TRIG_CLK_CAP_MASK)


/* Supported Commands (Byte 30 bit 6-7) */
#define HCI_SUPP_COMMANDS_TRUNCATED_PAGE             0x06
#define HCI_SUPP_COMMANDS_TRUNCATED_PAGE_OFF         30
#define HCI_TRUNCATED_PAGE_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_TRUNCATED_PAGE_OFF] & HCI_SUPP_COMMANDS_TRUNCATED_PAGE)

#define HCI_SUPP_COMMANDS_TRUNCATED_PAGE_CANCEL             0x07
#define HCI_SUPP_COMMANDS_TRUNCATED_PAGE_CANCEL_OFF         30
#define HCI_TRUNCATED_PAGE_CANCEL_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_TRUNCATED_PAGE_CANCEL_OFF] & HCI_SUPP_COMMANDS_TRUNCATED_PAGE_CANCEL)

/* Supported Commands (Byte 31 bit 6-7) */
#define HCI_SUPP_COMMANDS_SET_CONLESS_SLAVE_BRCST             0x00
#define HCI_SUPP_COMMANDS_SET_CONLESS_SLAVE_BRCST_OFF         31
#define HCI_SET_CONLESS_SLAVE_BRCST_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_SET_CONLESS_SLAVE_BRCST_OFF] & HCI_SUPP_COMMANDS_SET_CONLESS_SLAVE_BRCST)

#define HCI_SUPP_COMMANDS_SET_CONLESS_SLAVE_BRCST_RECEIVE             0x01
#define HCI_SUPP_COMMANDS_SET_CONLESS_SLAVE_BRCST_RECEIVE_OFF         31
#define HCI_SET_CONLESS_SLAVE_BRCST_RECEIVE_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_SET_CONLESS_SLAVE_BRCST_RECEIVE_OFF] & HCI_SUPP_COMMANDS_SET_CONLESS_SLAVE_BRCST_RECEIVE)

#define HCI_SUPP_COMMANDS_START_SYNC_TRAIN             0x02
#define HCI_SUPP_COMMANDS_START_SYNC_TRAIN_OFF         31
#define HCI_START_SYNC_TRAIN_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_START_SYNC_TRAIN_OFF] & HCI_SUPP_COMMANDS_START_SYNC_TRAIN)

#define HCI_SUPP_COMMANDS_RECEIVE_SYNC_TRAIN             0x03
#define HCI_SUPP_COMMANDS_RECEIVE_SYNC_TRAIN_OFF         31
#define HCI_RECEIVE_SYNC_TRAIN_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_RECEIVE_SYNC_TRAIN_OFF] & HCI_SUPP_COMMANDS_RECEIVE_SYNC_TRAIN)

#define HCI_SUPP_COMMANDS_SET_RESERVED_LT_ADDR             0x04
#define HCI_SUPP_COMMANDS_SET_RESERVED_LT_ADDR_OFF         31
#define HCI_SET_RESERVED_LT_ADDR_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_SET_RESERVED_LT_ADDR_OFF] & HCI_SUPP_COMMANDS_SET_RESERVED_LT_ADDR)

#define HCI_SUPP_COMMANDS_DELETE_RESERVED_LT_ADDR             0x05
#define HCI_SUPP_COMMANDS_DELETE_RESERVED_LT_ADDR_OFF         31
#define HCI_DELETE_RESERVED_LT_ADDR_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_DELETE_RESERVED_LT_ADDR_OFF] & HCI_SUPP_COMMANDS_DELETE_RESERVED_LT_ADDR)

#define HCI_SUPP_COMMANDS_SET_CONLESS_SLAVE_BRCST_DATA             0x06
#define HCI_SUPP_COMMANDS_SET_CONLESS_SLAVE_BRCST_DATA_OFF         31
#define HCI_SET_CONLESS_SLAVE_BRCST_DATA_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_SET_CONLESS_SLAVE_BRCST_DATA_OFF] & HCI_SUPP_COMMANDS_SET_CONLESS_SLAVE_BRCST_DATA)

#define HCI_SUPP_COMMANDS_READ_SYNC_TRAIN_PARAM             0x07
#define HCI_SUPP_COMMANDS_READ_SYNC_TRAIN_PARAM_OFF         31
#define HCI_READ_SYNC_TRAIN_PARAM_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_READ_SYNC_TRAIN_PARAM_OFF] & HCI_SUPP_COMMANDS_READ_SYNC_TRAIN_PARAM)

/* Supported Commands (Byte 32 bit 0) */
#define HCI_SUPP_COMMANDS_WRITE_SYNC_TRAIN_PARAM             0x00
#define HCI_SUPP_COMMANDS_WRITE_SYNC_TRAIN_PARAM_OFF         32
#define HCI_WRITE_SYNC_TRAIN_PARAM_SUPPORTED(x)   ((x)[HCI_SUPP_COMMANDS_WRITE_SYNC_TRAIN_PARAM_OFF] & HCI_SUPP_COMMANDS_WRITE_SYNC_TRAIN_PARAM)




/*
Commands of HCI_GRP_VENDOR_SPECIFIC group for WIDCOMM SW LM Simulator
*/
#ifdef _WIDCOMM

#define HCI_SET_HCI_TRACE               (0x0001 | HCI_GRP_VENDOR_SPECIFIC)
#define HCI_SET_LM_TRACE                (0x0002 | HCI_GRP_VENDOR_SPECIFIC)
#define HCI_WRITE_COUNTRY_CODE          (0x0004 | HCI_GRP_VENDOR_SPECIFIC)
#define HCI_READ_LM_HISTORY             (0x0005 | HCI_GRP_VENDOR_SPECIFIC)
#define HCI_WRITE_BD_ADDR               (0x0006 | HCI_GRP_VENDOR_SPECIFIC)
#define HCI_DISABLE_ENCRYPTION          (0x0007 | HCI_GRP_VENDOR_SPECIFIC)
#define HCI_DISABLE_AUTHENTICATION      (0x0008 | HCI_GRP_VENDOR_SPECIFIC)
#define HCI_GENERIC_LC_CMD              (0x000A | HCI_GRP_VENDOR_SPECIFIC)
#define HCI_INCR_POWER                  (0x000B | HCI_GRP_VENDOR_SPECIFIC)
#define HCI_DECR_POWER                  (0x000C | HCI_GRP_VENDOR_SPECIFIC)

/* Definitions for the local transactions */
#define LM_DISCONNECT                  (0x00D0 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_AUTHENTICATION_REQUESTED    (0x00D1 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_SET_CONN_ENCRYPTION         (0x00D2 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_START_ENCRYPT_KEY_SIZE      (0x00D3 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_START_ENCRYPTION            (0x00D4 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_STOP_ENCRYPTION             (0x00D5 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_CHANGE_CONN_PACKET_TYPE     (0x00D6 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_RMT_NAME_REQUEST            (0x00D7 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_READ_RMT_FEATURES           (0x00D8 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_READ_RMT_VERSION_INFO       (0x00D9 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_READ_RMT_TIMING_INFO        (0x00DA | HCI_GRP_VENDOR_SPECIFIC)
#define LM_READ_RMT_CLOCK_OFFSET       (0x00DB | HCI_GRP_VENDOR_SPECIFIC)
#define LM_HOLD_MODE                   (0x00DC | HCI_GRP_VENDOR_SPECIFIC)
#define LM_EXIT_PARK_MODE              (0x00DD | HCI_GRP_VENDOR_SPECIFIC)

#define LM_SCO_LINK_REQUEST            (0x00E0 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_SCO_CHANGE                  (0x00E4 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_SCO_REMOVE                  (0x00E8 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_MAX_SLOTS                   (0x00F1 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_MAX_SLOTS_REQUEST           (0x00F2 | HCI_GRP_VENDOR_SPECIFIC)

#ifdef INCLUDE_OPTIONAL_PAGING_SCHEME
#define LM_OPTIONAL_PAGE_REQUEST       (0x00F3 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_OPTIONAL_PAGESCAN_REQUEST   (0x00F4 | HCI_GRP_VENDOR_SPECIFIC)
#endif

#define LM_SETUP_COMPLETE              (0x00FF | HCI_GRP_VENDOR_SPECIFIC)

#define LM_HIST_SEND_LMP_FRAME         (0x0100 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_HIST_RECV_LMP_FRAME         (0x0101 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_HIST_HCIT_ERROR             (0x0102 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_HIST_PER_INQ_TOUT           (0x0103 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_HIST_INQ_SCAN_TOUT          (0x0104 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_HIST_PAGE_SCAN_TOUT         (0x0105 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_HIST_RESET_TOUT             (0x0106 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_HIST_MANDAT_PSCAN_TOUT      (0x0107 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_HIST_ACL_START_TRANS        (0x0108 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_HIST_ACL_HOST_REPLY         (0x0109 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_HIST_ACL_TIMEOUT            (0x010A | HCI_GRP_VENDOR_SPECIFIC)
#define LM_HIST_ACL_TX_COMP            (0x010B | HCI_GRP_VENDOR_SPECIFIC)
#define LM_HIST_ACL_HCID_SUSPENDED     (0x010C | HCI_GRP_VENDOR_SPECIFIC)
#define LM_HIST_ACL_FAILED             (0x010D | HCI_GRP_VENDOR_SPECIFIC)
#define LM_HIST_HCI_COMMAND            (0x010E | HCI_GRP_VENDOR_SPECIFIC)

#define LM_HIST_HCI_EVENT              (0x010F | HCI_GRP_VENDOR_SPECIFIC)
#define LM_HIST_HCI_UPDATA             (0x0110 | HCI_GRP_VENDOR_SPECIFIC)
#define LM_HIST_HCI_DNDATA             (0x0111 | HCI_GRP_VENDOR_SPECIFIC)

#define HCI_ENTER_TEST_MODE            (0x0300 | HCI_GRP_VENDOR_SPECIFIC)
#define HCI_LMP_TEST_CNTRL             (0x0301 | HCI_GRP_VENDOR_SPECIFIC)
#define HCI_DEBUG_LC_CMD_MIN           (0x0300 | HCI_GRP_VENDOR_SPECIFIC)
#define HCI_DEBUG_LC_CMD_MAX           (0x03FF | HCI_GRP_VENDOR_SPECIFIC)
#define HCI_DEBUG_LC_COMMAND           HCI_DEBUG_LC_CMD_MAX

#endif


/* AMP VSE events
*/
#define AMP_VSE_CHANSPEC_CHAN_MASK      0x00ff

#define AMP_VSE_CHANSPEC_CTL_SB_MASK    0x0300
#define AMP_VSE_CHANSPEC_CTL_SB_LOWER   0x0100
#define AMP_VSE_CHANSPEC_CTL_SB_UPPER   0x0200
#define AMP_VSE_CHANSPEC_CTL_SB_NONE    0x0300

#define AMP_VSE_CHANSPEC_BW_MASK        0x0C00
#define AMP_VSE_CHANSPEC_BW_10          0x0400
#define AMP_VSE_CHANSPEC_BW_20          0x0800
#define AMP_VSE_CHANSPEC_BW_40          0x0C00

#define AMP_VSE_CHANSPEC_BAND_MASK      0xf000
#define AMP_VSE_CHANSPEC_BAND_5G        0x1000
#define AMP_VSE_CHANSPEC_BAND_2G        0x2000


#endif

