/*
 * Copyright (C) 2012-2013 Intel Mobile Communications GmbH
 *
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANDROID_INCLUDE_BTIF_TEST_H
#define ANDROID_INCLUDE_BTIF_TEST_H

__BEGIN_DECLS

#define L2CAP_PARAMETER_CLEAR           0
#define L2CAP_PARAMETER_MODE            1
#define L2CAP_PARAMETER_SEND_CONFIG     2
#define L2CAP_PARAMETER_SET_ERTM        3
#define L2CAP_PARAMETER_SET_MTU         4
#define L2CAP_PARAMETER_SET_FLUSH_TO    5
#define L2CAP_PARAMETER_SET_FCS         6
#define L2CAP_PARAMETER_SET_FCR         7

/* BNEP frame types
*/
#define BNEP_FRAME_GENERAL_ETHERNET                 0x00
#define BNEP_FRAME_CONTROL                          0x01
#define BNEP_FRAME_COMPRESSED_ETHERNET              0x02
#define BNEP_FRAME_COMPRESSED_ETHERNET_SRC_ONLY     0x03
#define BNEP_FRAME_COMPRESSED_ETHERNET_DEST_ONLY    0x04

/* BNEP filter control message types
*/
#define BNEP_CONTROL_COMMAND_NOT_UNDERSTOOD         0x00
#define BNEP_SETUP_CONNECTION_REQUEST_MSG           0x01
#define BNEP_SETUP_CONNECTION_RESPONSE_MSG          0x02
#define BNEP_FILTER_NET_TYPE_SET_MSG                0x03
#define BNEP_FILTER_NET_TYPE_RESPONSE_MSG           0x04
#define BNEP_FILTER_MULTI_ADDR_SET_MSG              0x05
#define BNEP_FILTER_MULTI_ADDR_RESPONSE_MSG         0x06
#define BNEP_SETUP_UNKNOWN_CMD_REQUEST_MSG          0x07

#define BNEP_EXTENSION_FILTER_CONTROL          0x00

#ifdef VERIFIER
#ifdef BNEP_VERIFIER
typedef struct {
    size_t size;
    void (*fnBNEPV_init) ( void * );
    void (*fnBNEPV_set_remote_bd_addr) ( BD_ADDR * );
    void (*fnBNEPV_select_test_case) ( UINT8, UINT8 * );
    UINT8 (*fnBNEPV_get_cmd) ( void );
    void (*fnBNEPV_connect) ( void );
    void (*fnBNEPV_send_control_msg) ( UINT8 );
    void (*fnBNEPV_disconnect) ( void );
} bnep_verifier_interface_t;
#endif

#ifdef AVDTP_VERIFIER
typedef struct {
    size_t size;
    void (*fnAVDTPV_init) ( void * );
    void (*fnAVDTPV_set_remote_bd_addr) ( BD_ADDR * );
    void (*fnAVDTV_set_invalid_mode) ( int );
    void (*fnAVDTPV_select_test_case) ( UINT8, UINT8 * );
    UINT8 (*fnAVDTPV_get_cmd) ( void );
    void (*fnAVDTPV_connect) ( void );
    void (*fnAVDTPV_send_control_msg) ( UINT8 );
    void (*fnAVDTPV_disconnect) ( void );
} avdtp_verifier_interface_t;
#endif //AVDTP_VERIFIER


#endif // VERIFIER

#ifdef TESTER
#ifdef L2CAP_TESTER
typedef struct {
    size_t size;
    uint16_t (*L2CAPTest_init)(void);
    void (*L2CAPTest_set_default_parameters)(void);
    void (*L2CAPTest_set_parameters)(UINT8, void *);
    void (*L2CAPTest_set_remote_bd_addr)(BD_ADDR *);
    void (*L2CAPTest_connect)(void);
    void (*L2CAPTest_disconnect)(void);
    void (*L2CAPTest_senddata)(uint16_t);
    void (*L2CAPTest_ping)(UINT8);
    void (*L2CAPTest_cleanup)(void);
} l2cap_test_interface_t;
#endif
#ifdef BNEP_TESTER
typedef struct {
    size_t size;
    void (*BNEPTest_init)(void);
    void (*BNEPTest_send_control_msg)(UINT8);
} bnep_test_interface_t;
#endif

#ifdef AVDTP_TESTER
typedef struct {
    size_t size;
    void (*AVDTPTest_init)(void);
    void (*AVDTPTest_send_control_msg)(UINT8);
    void (*AVDTPTest_set_remote_bd_addr) ( BD_ADDR * );
} avdtp_test_interface_t;
#endif //AVDTP_TESTER

#endif  // TESTER

__END_DECLS

#endif /* ANDROID_INCLUDE_BTIF_TEST_H */
