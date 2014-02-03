/******************************************************************************
 *
 *  Copyright (C) 2012-2013 Intel Mobile Communications GmbH
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

/************************************************************************************
 *
 *  Filename:      bluedroidtest.c
 *
 *  Description:   Bluedroid Test application
 *
 ***********************************************************************************/


#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include <private/android_filesystem_config.h>
#include <android/log.h>

#include <hardware/hardware.h>
#include <hardware/bluetooth.h>
#include <hardware/bt_sock.h>
#include <hardware/bt_test.h>

#include "stack.h"

/************************************************************************************
**  Constants & Macros
************************************************************************************/

#define PID_FILE "/data/.bdt_pid"
#define filename "/data/exp"
#ifndef MAX
#define MAX(x, y) ((x) > (y) ? (x) : (y))
#endif

#define CASE_RETURN_STR(const) case const: return #const;
typedef enum
{
    RESULT_SUCCESS,
    RESULT_TIMEOUT,
    RESULT_UNKNOWN
}bt_test_results_t;
#define WAIT_TIME_SECONDS 30 /* 5 sec */
#ifdef BDT_LOG_ENABLE
#define BDT_LOG_FUNC_NAME() bdt_log("%s", __func__)
#define BDT_LOG(str, ...)   bdt_log(str, ##__VA_ARGS__)
#define BDT_LOG_NEW(str, ...)   bdt_log_new(str, ##__VA_ARGS__)
#else
#define BDT_LOG_FUNC_NAME() ;
#define BDT_LOG(str, ...) ;
#define BDT_LOG_NEW(str, ...) ;
#endif
/************************************************************************************
**  Local type definitions
************************************************************************************/
/************************************************************************************
**  Static Declarations
************************************************************************************/
static void adapter_properties_cb(bt_status_t status,int num_properties,bt_property_t *properties);
static void device_found_cb(int num_properties,bt_property_t *properties);
static void remote_device_properties_cb(bt_status_t status,bt_bdaddr_t *bd_addr,int num_properties,bt_property_t *properties);
static void bond_state_changed_cb(bt_status_t status,bt_bdaddr_t *bd_addr,bt_bond_state_t state);
/************************************************************************************
**  Static variables
************************************************************************************/
static volatile int quit=0;
static int listen_on=0;
static unsigned char main_done = 0;
static bt_status_t status;
static btsock_interface_t *btsock_if=NULL;
static bt_bdaddr_t *local_bd_addr;
/* Main API */
static bluetooth_device_t* bt_device;
typedef struct
{
    bt_bdaddr_t bd_addr;
    char name[256];
} bt_dev;

int num_device=0;

const bt_interface_t* sBtInterface = NULL;

/*test*/
#ifdef VERIFER
#ifdef BNEP_VERIFIER
const bnep_verifier_interface_t *sBtBNEPVInterface = NULL;
#endif
#ifdef AVDTP_VERIFIER
const avdtp_verifier_interface_t *sBtAVDTPVInterface = NULL;
#endif //AVDTP_VERIFIER

#endif // VERIFIER

#ifdef TESTER
#ifdef BNEP_TESTER
const bnep_test_interface_t *sBtBNEPTestInterface = NULL;
#endif
#ifdef AVDTP_TESTER
const avdtp_test_interface_t *sBtAVDTPTestInterface = NULL;
#endif //AVDTP_TESTER

#ifdef L2CAP_TESTER
const l2cap_test_interface_t *sBtL2CAPTestInterface = NULL;
#endif
#endif // TESTER

static gid_t groups[] = { AID_NET_BT, AID_INET, AID_NET_BT_ADMIN,
                          AID_SYSTEM, AID_MISC, AID_SDCARD_RW,
                          AID_NET_ADMIN, AID_VPN
                        };

/* Set to 1 when the Bluedroid stack is enabled */
static unsigned char bt_enabled = 0;
static pthread_mutex_t mutex     = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  condition_var   = PTHREAD_COND_INITIALIZER;
static struct timespec   ts;
static struct timeval    tp;
static int test_result;
static node_t *stack = NULL;
static FILE *file;
/************************************************************************************
**  Static functions
************************************************************************************/

static void process_cmd(char *p, unsigned char is_job);
static void job_handler(void *param);
static void bdt_log(const char *fmt_str, ...);
static void bdt_log_new(const char *fmt_str, ...);


/************************************************************************************
**  Externs
************************************************************************************/
extern int adb_send(char *param);
/************************************************************************************
**  Functions
************************************************************************************/


/************************************************************************************
**  Shutdown helper functions
************************************************************************************/

static void bdt_shutdown(void)
{
    BDT_LOG("shutdown bdroid test app\n");
    main_done = 1;
}


/*****************************************************************************
** Android's init.rc does not yet support applying linux capabilities
*****************************************************************************/

static void config_permissions(void)
{
    struct __user_cap_header_struct header;
    struct __user_cap_data_struct cap;

    BDT_LOG("set_aid_and_cap : pid %d, uid %d gid %d", getpid(), getuid(), getgid());

    header.pid = 0;

    prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0);

    setuid(AID_BLUETOOTH);
    setgid(AID_BLUETOOTH);

    header.version = _LINUX_CAPABILITY_VERSION;

    cap.effective = cap.permitted =  cap.inheritable =
                                         1 << CAP_NET_RAW |
                                         1 << CAP_NET_ADMIN |
                                         1 << CAP_NET_BIND_SERVICE |
                                         1 << CAP_SYS_RAWIO |
                                         1 << CAP_SYS_NICE |
                                         1 << CAP_SETGID;

    capset(&header, &cap);
    setgroups(sizeof(groups)/sizeof(groups[0]), groups);
}



/*****************************************************************************
**   Logger API
*****************************************************************************/

void bdt_log(const char *fmt_str, ...)
{
    static char buffer[1024];
    va_list ap;

    va_start(ap, fmt_str);
    vsnprintf(buffer, 1024, fmt_str, ap);
    va_end(ap);

    fprintf(stdout, "\t%s\n", buffer);
}

/*******************************************************************************
 ** Misc helper functions
 *******************************************************************************/
static void cond_wait()
{
    int rc;
    test_result = RESULT_UNKNOWN;
    rc = pthread_mutex_lock(&mutex);
    rc =  gettimeofday(&tp, NULL);
    ts.tv_sec  = tp.tv_sec;
    ts.tv_nsec = tp.tv_usec * 1000;
    ts.tv_sec += WAIT_TIME_SECONDS;
    rc = pthread_cond_timedwait(&condition_var, &mutex, &ts);
    if (rc == ETIMEDOUT)
    {
        printf("Operation timed out! FAIL");
        test_result = RESULT_TIMEOUT;
    }
    else
        test_result = RESULT_SUCCESS;
    pthread_mutex_unlock(&mutex);
}

static void cond_wait_without_timeout()
{
    int rc;
    test_result = RESULT_UNKNOWN;
    rc = pthread_mutex_lock(&mutex);
    pthread_cond_wait(&condition_var, &mutex );
    pthread_mutex_unlock(&mutex);
}

static void cond_signal()
{
    pthread_mutex_lock(&mutex);
        pthread_cond_signal(&condition_var);
    pthread_mutex_unlock(&mutex);
}

void bdt_log_new(const char *fmt_str, ...)
{
    static char buffer[1024];
    va_list ap;

    va_start(ap, fmt_str);
    vsnprintf(buffer, 1024, fmt_str, ap);
    va_end(ap);

    fprintf(stdout, "\t%s", buffer);
}

static const char* dump_bt_status(bt_status_t status)
{
    switch(status)
    {
        CASE_RETURN_STR(BT_STATUS_SUCCESS)
        CASE_RETURN_STR(BT_STATUS_FAIL)
        CASE_RETURN_STR(BT_STATUS_NOT_READY)
        CASE_RETURN_STR(BT_STATUS_NOMEM)
        CASE_RETURN_STR(BT_STATUS_BUSY)
        CASE_RETURN_STR(BT_STATUS_UNSUPPORTED)

    default:
        return "unknown status code";
    }
}

static void hex_dump(char *msg, void *data, int size, int trunc)
{
    unsigned char *p = data;
    unsigned char c;
    int n;
    char bytestr[4] = {0};
    char addrstr[10] = {0};
    char hexstr[ 16*3 + 5] = {0};
    char charstr[16*1 + 5] = {0};

    BDT_LOG("%s  \n", msg);

    /* truncate */
    if(trunc && (size>32))
        size = 32;

    for(n=1; n<=size; n++)
    {
        if (n%16 == 1)
        {
            /* store address for this line */
            snprintf(addrstr, sizeof(addrstr), "%.4x",
                     ((unsigned int)p-(unsigned int)data) );
        }

        c = *p;
        if (isalnum(c) == 0)
        {
            c = '.';
        }

        /* store hex str (for left side) */
        snprintf(bytestr, sizeof(bytestr), "%02X ", *p);
        strncat(hexstr, bytestr, sizeof(hexstr)-strlen(hexstr)-1);

        /* store char str (for right side) */
        snprintf(bytestr, sizeof(bytestr), "%c", c);
        strncat(charstr, bytestr, sizeof(charstr)-strlen(charstr)-1);

        if(n%16 == 0)
        {
            /* line completed */
            BDT_LOG("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
            hexstr[0] = 0;
            charstr[0] = 0;
        }
        else if(n%8 == 0)
        {
            /* half line: add whitespaces */
            strncat(hexstr, "  ", sizeof(hexstr)-strlen(hexstr)-1);
            strncat(charstr, " ", sizeof(charstr)-strlen(charstr)-1);
        }
        p++; /* next byte */
    }

    if (strlen(hexstr) > 0)
    {
        /* print rest of buffer if not empty */
        BDT_LOG("[%4.4s]   %-50.50s  %s\n", addrstr, hexstr, charstr);
    }
}

/*******************************************************************************
 ** Console helper functions
 *******************************************************************************/

void skip_blanks(char **p)
{
    while (**p == ' ')
        (*p)++;
}

uint32_t get_int(char **p, int DefaultValue)
{
    uint32_t Value = 0;
    unsigned char   UseDefault;

    UseDefault = 1;
    skip_blanks(p);

    while ( ((**p)<= '9' && (**p)>= '0') )
    {
        Value = Value * 10 + (**p) - '0';
        UseDefault = 0;
        (*p)++;
    }

    if (UseDefault)
        return DefaultValue;
    else
        return Value;
}

int get_signed_int(char **p, int DefaultValue)
{
    int    Value = 0;
    unsigned char   UseDefault;
    unsigned char  NegativeNum = 0;

    UseDefault = 1;
    skip_blanks(p);

    if ( (**p) == '-')
    {
        NegativeNum = 1;
        (*p)++;
    }
    while ( ((**p)<= '9' && (**p)>= '0') )
    {
        Value = Value * 10 + (**p) - '0';
        UseDefault = 0;
        (*p)++;
    }

    if (UseDefault)
        return DefaultValue;
    else
        return ((NegativeNum == 0)? Value : -Value);
}

void get_str(char **p, char *Buffer)
{
    skip_blanks(p);

    while (**p != 0 && **p != ' ')
    {
        *Buffer = **p;
        (*p)++;
        Buffer++;
    }

    *Buffer = 0;
}

uint32_t get_hex(char **p, int DefaultValue)
{
    uint32_t Value = 0;
    unsigned char   UseDefault;

    UseDefault = 1;
    skip_blanks(p);

    while ( ((**p)<= '9' && (**p)>= '0') ||
            ((**p)<= 'f' && (**p)>= 'a') ||
            ((**p)<= 'F' && (**p)>= 'A') )
    {
        if (**p >= 'a')
            Value = Value * 16 + (**p) - 'a' + 10;
        else if (**p >= 'A')
            Value = Value * 16 + (**p) - 'A' + 10;
        else
            Value = Value * 16 + (**p) - '0';
        UseDefault = 0;
        (*p)++;
    }

    if (UseDefault)
        return DefaultValue;
    else
        return Value;
}

void get_bdaddr(const char *str, bt_bdaddr_t *bd)
{
    char *d = ((char *)bd), *endp;
    int i;
    for(i = 0; i < 6; i++)
    {
        *d++ = strtol(str, &endp, 16);
        if (*endp != ':' && i != 5)
        {
            memset(bd, 0, sizeof(bt_bdaddr_t));
            return;
        }
        str = endp + 1;
    }
}

#define is_cmd(str) ((strlen(str) == strlen(cmd)) && strncmp((const char *)&cmd, str, strlen(str)) == 0)
#define if_cmd(str)  if (is_cmd(str))

typedef void (t_console_cmd_handler) (char *p);

typedef struct
{
    const char *name;
    t_console_cmd_handler *handler;
    const char *help;
    unsigned char is_job;
} t_cmd;


const t_cmd console_cmd_list[];
static int console_cmd_maxlen = 0;

static void cmdjob_handler(void *param)
{
    char *job_cmd = (char*)param;

    BDT_LOG("cmdjob starting (%s)", job_cmd);

    process_cmd(job_cmd, 1);

    BDT_LOG("cmdjob terminating");

    free(job_cmd);
}

static int create_cmdjob(char *cmd)
{
    pthread_t thread_id;
    char *job_cmd;

    job_cmd = malloc(strlen(cmd)+1); /* freed in job handler */
    strcpy(job_cmd, cmd);

    if (pthread_create(&thread_id, NULL,
                       (void*)cmdjob_handler, (void*)job_cmd)!=0)
        perror("pthread_create");

    return 0;
}

/*******************************************************************************
 ** Load stack lib
 *******************************************************************************/

int HAL_load(void)
{
    int err = 0;

    hw_module_t* module;
    hw_device_t* device;

    printf("\tLoading HAL lib + extensions\n");

    err = hw_get_module(BT_HARDWARE_MODULE_ID, (hw_module_t const**)&module);
    if (err == 0)
    {
        err = module->methods->open(module, BT_HARDWARE_MODULE_ID, &device);
        if (err == 0)
        {
            bt_device = (bluetooth_device_t *)device;
            sBtInterface = bt_device->get_bluetooth_interface();
        }
    }

    printf("\tHAL library loaded (%s)\n", strerror(err));

    return err;
}

int HAL_unload(void)
{
    int err = 0;

    printf("\tUnloading HAL lib\n");

    sBtInterface = NULL;

    printf("\tHAL library unloaded (%s)\n", strerror(err));

    return err;
}

/*******************************************************************************
 ** HAL test functions & callbacks
 *******************************************************************************/

void setup_test_env(void)
{
    int i = 0;

    while (console_cmd_list[i].name != NULL)
    {
        console_cmd_maxlen = MAX(console_cmd_maxlen, (int)strlen(console_cmd_list[i].name));
        i++;
    }
}

void check_return_status(bt_status_t status)
{
    if (status != BT_STATUS_SUCCESS)
    {
        printf("\tHAL REQUEST FAILED status : %d (%s)\n", status, dump_bt_status(status));
    }
    else
    {
        printf("\tHAL REQUEST SUCCESS\n");
    }
}

static void adapter_state_changed(bt_state_t state)
{
    BDT_LOG_FUNC_NAME();

    BDT_LOG("ADAPTER STATE UPDATED : %s", (state == BT_STATE_OFF)?"OFF":"ON");
    if (state == BT_STATE_ON)
    {
        bt_enabled = 1;
    }
    else
    {
        bt_enabled = 0;
    }
    cond_signal();
}

static void dut_mode_recv(uint16_t opcode, uint8_t *buf, uint8_t len)
{
    BDT_LOG_FUNC_NAME();
    BDT_LOG("DUT MODE RECV : NOT IMPLEMENTED");
}

static void adapter_properties_cb(bt_status_t status,int num_properties,bt_property_t *properties)
{
    int i;
    bt_bdaddr_t *bd_addr;

    BDT_LOG_FUNC_NAME();
    //BDT_LOG("Number of properties : %d",num_properties);

    for(i=0; i<num_properties; i++)
    {

        if(properties[i].type==BT_PROPERTY_BDNAME)
        {
            if (bt_enabled)
            {
                BDT_LOG("Device Name = %s", properties[i].val);
            }
        }
        else if(properties[i].type==BT_PROPERTY_BDADDR)
        {
            bd_addr = (bt_bdaddr_t*) properties[i].val;

            if (bt_enabled)
                BDT_LOG("BT Address = %x:%x:%x:%x:%x:%x", bd_addr->address[0], bd_addr->address[1], bd_addr->address[2],
                        bd_addr->address[3], bd_addr->address[4], bd_addr->address[5]);
        }
        else if(properties[i].type==BT_PROPERTY_ADAPTER_BONDED_DEVICES)
        {
            bd_addr = (bt_bdaddr_t*) properties[i].val;

            if (bt_enabled)
            {
                BDT_LOG("Bonded Device BT Address = %x:%x:%x:%x:%x:%x", bd_addr->address[0], bd_addr->address[1],
                        bd_addr->address[2], bd_addr->address[3], bd_addr->address[4], bd_addr->address[5]);
            }
        }

    }
    return;
}

static void device_found_cb(int num_properties,bt_property_t *properties)
{
    int i=0;
    int j=0;
    char *name;
    for(i=0; i<num_properties; i++)
    {
        if(properties[i].type==BT_PROPERTY_BDNAME)
        {
            j=0;
            printf("Device Name = %s",(char *)properties[i].val);
            name = (char*)properties[i].val;
            while(name[j]!='\0')
            {
                j++;
            }

        }
        if(properties[i].type==BT_PROPERTY_BDADDR)
        {
            bt_bdaddr_t *bd_addr = (bt_bdaddr_t*)properties[i].val;
            if (bd_addr)
            {
                printf("BT Address = %x:%x:%x:%x:%x:%x",bd_addr->address[0],bd_addr->address[1],
                        bd_addr->address[2],bd_addr->address[3],bd_addr->address[4],bd_addr->address[5]);
            }
        }
    }
    num_device++;
    cond_signal();
    bdt_log("\n");

}
/*
void remote_device_properties_cb(bt_status_t status,bt_bdaddr_t *bd_addr,int num_properties,bt_property_t *properties)
{
    int i=0;
    bdt_log("%s",__func__);
    bdt_log("BDT addr = ");
    bdt_log("%x:%x:%x:%x:%x:%x",bd_addr->address[0],bd_addr->address[1],bd_addr->address[2],bd_addr->address[3],bd_addr->address[4],bd_addr->address[5]);
    for(i=0;i<num_properties;i++)
    {
        if(properties[i].type==BT_PROPERTY_BDNAME)
        {
            bdt_log("Device Name = %s",properties[i].val);
        }

    }
}
*/

static void bond_state_changed_cb(bt_status_t status,bt_bdaddr_t *bd_addr,bt_bond_state_t state)
{
    BDT_LOG_FUNC_NAME();

    BDT_LOG("Status = \t%d", status);BDT_LOG("State = \t%d", state);
    BDT_LOG("State = %d",state);

    if (state == 2)
        cond_signal();
}

static void le_test_mode(bt_status_t status, uint16_t packet_count)
{
    bdt_log("LE TEST MODE END status:%s number_of_packets:%d", dump_bt_status(status), packet_count);
}

static void ssp_request_cb(bt_bdaddr_t *remote_bd_addr,bt_bdname_t *bd_name,uint32_t cod,
                    bt_ssp_variant_t pairing_variant,uint32_t pass_key)
{
    BDT_LOG_FUNC_NAME();

    BDT_LOG("Remote BTADDR= %02x:%02x:%02x:%02x:%02x:%02x",remote_bd_addr->address[0],remote_bd_addr->address[1],
            remote_bd_addr->address[2],remote_bd_addr->address[3],remote_bd_addr->address[4], remote_bd_addr->address[5]);
    BDT_LOG("Remote name = %s",bd_name);
    BDT_LOG("cod = %d",cod);
    BDT_LOG("Pairing variant = %d",pairing_variant);
    BDT_LOG("Pass Key = %d",pass_key);
    BDT_LOG("Confirming the pass key");
    sBtInterface->ssp_reply(remote_bd_addr,0,1,pass_key);

}

static void acl_state_changed_cb(bt_status_t status,bt_bdaddr_t *bd_addr,bt_acl_state_t state)
{
    BDT_LOG_FUNC_NAME();

    BDT_LOG("%d",status);
    BDT_LOG("BT Address = %02x:%02x:%02x:%02x:%02x:%02x",bd_addr->address[0],bd_addr->address[1],
            bd_addr->address[2],bd_addr->address[3],bd_addr->address[4],bd_addr->address[5]);
    BDT_LOG("acl_state %d",state);
}

static void pin_request_cb(bt_bdaddr_t *remote_bdaddr,bt_bdname_t *bd_name,uint32_t cod)
{
    BDT_LOG_FUNC_NAME();
}

static bt_callbacks_t bt_callbacks =
{
    sizeof(bt_callbacks_t),
    adapter_state_changed,
    adapter_properties_cb, /*adapter_properties_cb */
    NULL, /* remote_device_properties_cb */
    device_found_cb, /* device_found_cb */
    NULL, /* discovery_state_changed_cb */
    pin_request_cb, /* pin_request_cb  */
    ssp_request_cb, /* ssp_request_cb  */
    bond_state_changed_cb, /*bond_state_changed_cb */
    acl_state_changed_cb, /* acl_state_changed_cb */
    NULL, /* thread_evt_cb */
    dut_mode_recv, /*dut_mode_recv_cb */
//    NULL, /*authorize_request_cb */
#if BLE_INCLUDED == TRUE
    le_test_mode /* le_test_mode_cb */
#else
    NULL
#endif
};

void bdt_init(void)
{
    printf("\tINIT BT\n");

    status = sBtInterface->init(&bt_callbacks);
    check_return_status(status);
}

void bdt_enable(void)
{
    BDT_LOG_FUNC_NAME();

    if (bt_enabled)
    {
        BDT_LOG("Bluetooth is already enabled");
        return;
    }
    status = sBtInterface->enable();

    check_return_status(status);
}

void bdt_disable(void)
{
    BDT_LOG_FUNC_NAME();

    if (!bt_enabled)
    {
        BDT_LOG("Bluetooth is already disabled");
        return;
    }
    status = sBtInterface->disable();

    check_return_status(status);
}

void bdt_dut_mode_configure(char *p)
{
    int32_t mode = -1;

    BDT_LOG_FUNC_NAME();

    if (!bt_enabled)
    {
        BDT_LOG("Bluetooth must be enabled for test_mode to work.");
        return;
    }
    mode = get_signed_int(&p, mode);
    if ((mode != 0) && (mode != 1))
    {
        BDT_LOG("Please specify mode: 1 to enter, 0 to exit :: ");
        return;
    }
    status = sBtInterface->dut_mode_configure(mode);

    check_return_status(status);
}

#define HCI_LE_RECEIVER_TEST_OPCODE 0x201D
#define HCI_LE_TRANSMITTER_TEST_OPCODE 0x201E
#define HCI_LE_END_TEST_OPCODE 0x201F

void bdt_le_test_mode(char *p)
{
    int cmd;
    unsigned char buf[3];
    int arg1, arg2, arg3;

    bdt_log("BT LE TEST MODE");
    if (!bt_enabled) {
        bdt_log("Bluetooth must be enabled for le_test to work.");
        return;
    }

    memset(buf, 0, sizeof(buf));
    cmd = get_int(&p, 0);
    switch (cmd)
    {
        case 0x1: /* RX TEST */
           arg1 = get_int(&p, -1);
           if (arg1 < 0) bdt_log("%s Invalid arguments", __FUNCTION__);
           buf[0] = arg1;
           status = sBtInterface->le_test_mode(HCI_LE_RECEIVER_TEST_OPCODE, buf, 1);
           break;
        case 0x2: /* TX TEST */
            arg1 = get_int(&p, -1);
            arg2 = get_int(&p, -1);
            arg3 = get_int(&p, -1);
            if ((arg1 < 0) || (arg2 < 0) || (arg3 < 0))
                bdt_log("%s Invalid arguments", __FUNCTION__);
            buf[0] = arg1;
            buf[1] = arg2;
            buf[2] = arg3;
            status = sBtInterface->le_test_mode(HCI_LE_TRANSMITTER_TEST_OPCODE, buf, 3);
           break;
        case 0x3: /* END TEST */
            status = sBtInterface->le_test_mode(HCI_LE_END_TEST_OPCODE, buf, 0);
           break;
        default:
            bdt_log("Unsupported command");
            return;
            break;
    }
    if (status != BT_STATUS_SUCCESS)
    {
        bdt_log("%s Test 0x%x Failed with status:0x%x", __FUNCTION__, cmd, status);
    }
    return;
}

void bdt_cleanup(void)
{
    BDT_LOG_FUNC_NAME();

    sBtInterface->cleanup();
}

void bdt_get_profile_interface(char *profile)
{
    bdt_log("%s",__func__);
    btsock_if=(btsock_interface_t*) sBtInterface->get_profile_interface(profile);
    return;
}

int bdt_start_discovery(void)
{
    bdt_log("Start Discovery");
    bdt_log("List of Devices\n");
    return sBtInterface->start_discovery();
}

int bdt_discovery_cancel()
{
    return sBtInterface->cancel_discovery();
}

int bdt_get_adapter_property(bt_property_type_t type)
{

    bdt_log("%s",__func__);
    return sBtInterface->get_adapter_property(type);

}
int bdt_set_adapter_property(bt_property_t *property)
{
    bdt_log("%s",__func__);
    return sBtInterface->set_adapter_property(property);
}
int bdt_create_bond(bt_bdaddr_t *bd_addr)
{
    bdt_log("%s",__func__);
    return sBtInterface->create_bond(bd_addr);
}

#ifdef DYNAMIC_HCI_LOGGING
int bdt_hci_logging(int status)
{
    bdt_log("%s",__func__);
    return sBtInterface->hci_logging(status);
}
int bdt_set_hci_logging(int status)
{
    bdt_log("%s",__func__);
    return sBtInterface->set_hci_logging(status);
}
#endif

int bdt_rfcomm_socket_connect(bt_bdaddr_t *bd_addr,btsock_type_t type,const uint8_t *uuid,
                              int channel,int *sock_fd,int flags)
{
    bdt_log("%s",__func__);
    return btsock_if->connect(bd_addr,type,uuid,channel,sock_fd,flags);

}

int bdt_rfcomm_socket_listen( btsock_type_t type,char const *service_name,const uint8_t *service_uuid,int channel,
                              int *sock_fd,int flags)
{
    bdt_log("%s",__func__);
    return btsock_if->listen(type,service_name,service_uuid,channel,sock_fd,flags);
}
/*******************************************************************************
 ** Console commands
 *******************************************************************************/

void do_help(char *p)
{
    int i = 0;
    int max = 0;
    char line[128];
    int pos = 0;

    while (console_cmd_list[i].name != NULL)
    {
        pos = sprintf(line, "%s", (char*)console_cmd_list[i].name);
        printf("\t%s %s\n", (char*)line, (char*)console_cmd_list[i].help);
        i++;
    }
}

void do_quit(char *p)
{

    if(listen_on==1)
    {
        quit=1;

        while(quit==1);
    }

    bdt_shutdown();
}

/*******************************************************************
 *
 *  BT TEST  CONSOLE COMMANDS
 *
 *  Parses argument lists and passes to API test function
 *
*/

void do_init(char *p)
{
    bdt_init();
}

void do_enable(char *p)
{
    bdt_enable();
    cond_wait();
}

void do_disable(char *p)
{
    bdt_disable();
    cond_wait();
}
void do_dut_mode_configure(char *p)
{
    bdt_dut_mode_configure(p);
}

void do_le_test_mode(char *p)
{
    bdt_le_test_mode(p);
}

void do_cleanup(char *p)
{
    bdt_cleanup();
}

void do_start_discovery()
{
    bdt_start_discovery();
    cond_wait();
}

void do_discovery_cancel()
{
    bdt_discovery_cancel();
}

void do_connect(char* param)
{
    int i=0;
    bt_bdaddr_t remote_bd_addr;
    bdt_log("%s OUTSIDE remote_bd_addr:%s", __func__, param);
    if (strcmp(param, "") != 0)
    {
        bdt_log("%s remote_bd_addr:%s", __func__, param);
        get_bdaddr(param, &remote_bd_addr);
        bdt_create_bond(&remote_bd_addr);
    }
    cond_wait();
    return;

}
#ifdef DYNAMIC_HCI_LOGGING
void do_hci_enable()
{
    bdt_hci_logging(0);

}
void do_hci_disable()
{
    bdt_hci_logging(1);
}

void do_set_hci_enable()
{
    bdt_set_hci_logging(1);
}
void do_set_hci_disable()
{
    bdt_set_hci_logging(0);
}
#endif

void do_rfcomm_socket_connect(bt_bdaddr_t *bd_addr,btsock_type_t type,const uint8_t *uuid,
                              int channel,int *sock_fd,int flags)
{
    bdt_rfcomm_socket_connect(bd_addr,type,uuid,channel,sock_fd,flags);

}

void do_rfcomm_socket_listen(btsock_type_t type,const char *service_name,const uint8_t *service_uuid,int channel,
                             int *sock_fd,int flags)
{
    bdt_rfcomm_socket_listen(type,service_name,service_uuid,channel,sock_fd,flags);
}
void do_read_thread()
{
    uint8_t service_uuid=0x03;
    int sock_fd=-1;
    int flags=0;
    int res =1;
    int n;
    FILE *fp;
    int i=0;
    char buffer[1024];
    char crap[1024];
    struct msghdr msg;
    struct cmsghdr *cmd;
    struct iovec io;
    int data_fd=-1;
    char data_buffer[256];
    struct pollfd fds;
    int timeout=1000;

    do_rfcomm_socket_listen(BTSOCK_RFCOMM,"OBEX Object push",&service_uuid,10,&sock_fd,flags);
    bdt_log("Sock fd = %d",sock_fd);
    fds.fd=sock_fd;
    fds.events=POLLIN | POLLERR | POLLRDNORM;
    fds.revents=0;
    while(1)
    {
        n = poll(&fds, 1, timeout);

        if(n==0)
        {

            if(quit==1)
            {
                quit=0;
                break;
            }
        }
        else
        {
            io.iov_base=buffer;
            io.iov_len=1024;
            msg.msg_iov=&io;
            msg.msg_iovlen=1;
            memset(crap,0,1024);
            msg.msg_control=&crap;
            msg.msg_controllen=sizeof(crap);
            res=recvmsg(sock_fd,&msg,MSG_NOSIGNAL);
            if(res>0)
            {
                cmd=CMSG_FIRSTHDR(&msg);
                for(; cmd!=NULL; cmd=CMSG_NXTHDR(&msg,cmd))
                {
                    if(cmd->cmsg_level==SOL_SOCKET&&cmd->cmsg_type==SCM_RIGHTS)
                    {

                        //bdt_log("Data Received is %d",*(int*)(CMSG_DATA(cmd)));
                        data_fd=*(int*)(CMSG_DATA(cmd));
                    }
                }
                if(data_fd>0)
                {
//////////////file transfer////////////////
                    fp = fopen(filename, "wab");
                    if (fp == NULL)
                    {
                        printf("File not found!\n");
                        return;
                    }
                    else
                    {
                        printf("Found file %s\n", filename);
                    }

                    /* Time to Receive the File */
                    while (1)
                    {
                        bzero(buffer,256);
                        // n = read(thisfd,buffer,255);
                        res=recv(data_fd,data_buffer,256,0);
                        if (res < 0)
                        {
                            printf("ERROR reading from socket");
                            break;
                        }
                        if(res==0)
                        {
                            printf("Connection closed");
                            break;
                        }
                        if(res>0 && res == 6)
                        {
                            if (strncmp (data_buffer,"Theend",6) == 0)
                            {

                                break;
                            }
                        }

                        res = fwrite(data_buffer, res, 1, fp);
                        if (res < 0)
                            printf("ERROR writing in file");

                    } /* end child while loop */
                    bdt_log("File received and stored");
                    fclose(fp);
                    /*
                        if(res>0)
                        {
                            for(i=0;i<res;i++)
                            {
                                bdt_log("%c",data_buffer[i]);
                            }
                        }
                        res=recv(data_fd,data_buffer,256,0);
                        bdt_log("DATA received of length = %d",res);
                        if(res>0)
                        {
                            for(i=0;i<res;i++)
                            {
                                bdt_log("%c",data_buffer[i]);
                            }
                        }*/
                }
            }
        }
    }
    cond_signal();
}
void do_listen()
{
    char cmd[128];
    listen_on=1;
    pthread_t thread_id;
    pthread_create(&thread_id,NULL,(void*)do_read_thread,NULL);
    sprintf(cmd,"file_RX %x:%x:%x:%x:%x:%x",local_bd_addr->address[0],local_bd_addr->address[1],
                    local_bd_addr->address[2],local_bd_addr->address[3],local_bd_addr->address[4],local_bd_addr->address[5]);
    //adb_send(cmd);
    cond_wait_without_timeout();
}

void do_discoverable()
{
    bt_property_t property;
    bt_scan_mode_t mode;
    mode=BT_SCAN_MODE_CONNECTABLE_DISCOVERABLE;
    property.type=BT_PROPERTY_ADAPTER_SCAN_MODE;
    property.val =&mode;
    property.len=sizeof(mode);
    bdt_set_adapter_property(&property);
}
void do_bonded_device()
{
    bt_property_t property;
    property.type=BT_PROPERTY_ADAPTER_BONDED_DEVICES;
    bdt_get_adapter_property(property.type);
}

void do_file (char* param)
{
    char name_file[100];
    int iteration = 0;
    char line[1024] = {0};
    char arg[64] = {0};
    int i;

    bzero(name_file, 100);
    sscanf(param,"%99s %d", name_file, &iteration);
    if((iteration > 50) || (iteration < 1))
    {
        bdt_log("invalid Iteration value %d", iteration);
        return;
    }
    bdt_log("%s %d", name_file, iteration);
    if (strncmp (name_file, "", 100) != 0)
    {
        for (i=0; i < iteration; i++)
        {
            file = fopen (name_file, "r");
            if (file != NULL)
            {
                while (fgets (line, sizeof(line), file) != NULL)
                {
                    //sleep (1);
                    if (line[0] == ' ')
                        sscanf(line,"%[* ]%[^\n]", arg, line);
                    else
                        sscanf(line,"%[^\n]", line);
                    printf("line:%s: args:%s\n", line, arg);
                    process_cmd(line, 0);
                    if (test_result != RESULT_SUCCESS)
                    {
                        printf("Failed!!!!");
                        fclose (file);
                        exit(0);
                    }
                }
                fclose (file);
            }
        }
    }
}

void do_delay(char* param)
{
    int time;
    sscanf(param,"%d", &time);
    if (time > 0)
        sleep(time);
}

void do_repeat(char* param)
{
    node_t* temp;
    long int offset;
    int it_count = atoi(param);
    bdt_log("%s it_count:%d", __func__, it_count);
    if (it_count != 0)
    {
        offset = ftell(file);
        bdt_log("repeat call: offset:%ld it_count:%d\n", offset, it_count);
        push(&stack, create_node(offset, it_count));
    }
    else if (strcmp(param, " end") == 0)
    {
        temp = pop(&stack);
        if (temp != NULL)
        {
            if (temp->it_count > 1)
            {
                printf("repeat end call. seek to:%ld it_count:%d\n", temp->offset, temp->it_count);
                fseek (file, temp->offset, SEEK_SET);
                push(&stack, create_node(temp->offset, temp->it_count-1));
            }
            free(temp);
        }
    }
}

void do_async(char* param)
{
    //TODO: implement multiprofile scenarios
}

/*******************************************************************************
 ** L2CAP test functions & callbacks
 *******************************************************************************/
#ifdef TESTER
#ifdef L2CAP_TESTER

void do_L2CAPTest_init()
{
    BDT_LOG_FUNC_NAME();

    if (sBtInterface == NULL)
    {
        BDT_LOG("BT HAL Interface is null");
        return;
    }
    sBtL2CAPTestInterface = sBtInterface->get_profile_interface(BT_PROFILE_L2CAP_TESTER_ID);

    if (sBtL2CAPTestInterface == NULL)
    {
        BDT_LOG("Test Interface is NULL");
        return;
    }

    sBtL2CAPTestInterface->L2CAPTest_init();
}

void do_L2CAPTest_set_default_parameters()
{
    BDT_LOG_FUNC_NAME();

    if (sBtL2CAPTestInterface == NULL)
    {
        BDT_LOG("Test Interface is NULL");
        return;
    }

    sBtL2CAPTestInterface->L2CAPTest_set_default_parameters();
}

void do_L2CAPTest_set_parameters()
{
    int val;
    char res;

    BDT_LOG_FUNC_NAME();

    if (sBtL2CAPTestInterface == NULL)
    {
        BDT_LOG("Test Interface is NULL");
        return;
    }

    sBtL2CAPTestInterface->L2CAPTest_set_parameters(L2CAP_PARAMETER_CLEAR, NULL);

    printf("\tEnter mode : 0 - BASIC : 1 - ERM : 2 - STM : ");
    scanf("%d", &val);
    sBtL2CAPTestInterface->L2CAPTest_set_parameters(L2CAP_PARAMETER_MODE, (void *) &val);

    printf("\n\tSend Config ? (y/n): ");
    scanf(" %c", &res);
    val = (res == 'y') ? 1 : 0;
    sBtL2CAPTestInterface->L2CAPTest_set_parameters(L2CAP_PARAMETER_SEND_CONFIG, (void *) &val);

    sBtL2CAPTestInterface->L2CAPTest_set_parameters(L2CAP_PARAMETER_SET_ERTM, (void *) &val);

    printf("\n\tMTU Present ? (y/n): ");
    scanf(" %c", &res);
    val = (res == 'y') ? 1 : 0;
    sBtL2CAPTestInterface->L2CAPTest_set_parameters(L2CAP_PARAMETER_SET_MTU, (void *) &val);

    printf("\n\tFLUSH TO Present ? (y/n): ");
    scanf(" %c", &res);
    val = (res == 'y') ? 1 : 0;
    sBtL2CAPTestInterface->L2CAPTest_set_parameters(L2CAP_PARAMETER_SET_FLUSH_TO, (void *) &val);

    printf("\n\tFCS Options Present ? (y/n): ");
    scanf(" %c", &res);
    if (res == 'y')
    {
        printf("\n\tFCS present ? (y/n): ");
        scanf(" %c", &res);
        val = (res == 'y') ? 1 : 2;
    }
    else
        val = 0;

    sBtL2CAPTestInterface->L2CAPTest_set_parameters(L2CAP_PARAMETER_SET_FCS, (void *) &val);

    printf("\n\tFCR Present ? (y/n): ");
    scanf(" %c", &res);
    val = (res == 'y') ? 1 : 0;
    sBtL2CAPTestInterface->L2CAPTest_set_parameters(L2CAP_PARAMETER_SET_FCR, (void *) &val);

    printf("\n\tSet Parameters Done\n");
}

void do_L2CAPTest_set_remote_bd_addr()
{
    int index;
    char bd_addr_str[18];
    bt_bdaddr_t bd_addr;

    BDT_LOG_FUNC_NAME();

    if (sBtL2CAPTestInterface == NULL)
    {
        BDT_LOG("Test Interface is NULL");
        return;
    }

    printf("\tPlease enter BD Address of Remote Device in \"ab cd ef aa bb cc\" format : ");
    fgets(bd_addr_str, 18, stdin);

    sscanf(bd_addr_str, "%hhx %hhx %hhx %hhx %hhx %hhx", &bd_addr.address[0], &bd_addr.address[1], &bd_addr.address[2],
            &bd_addr.address[3], &bd_addr.address[4], &bd_addr.address[5]);

    printf("\n\tEntered Device Address is : %hhx %hhx %hhx %hhx %hhx %hhx\n", bd_addr.address[0], bd_addr.address[1],
            bd_addr.address[2], bd_addr.address[3], bd_addr.address[4], bd_addr.address[5]);

    sBtL2CAPTestInterface->L2CAPTest_set_remote_bd_addr(&bd_addr);
}

void do_L2CAPTest_connect()
{
    BDT_LOG_FUNC_NAME();

    if (sBtL2CAPTestInterface == NULL)
    {
        BDT_LOG("Test Interface is NULL");
        return;
    }

    sBtL2CAPTestInterface->L2CAPTest_connect();

}

void do_L2CAPTest_disconnect()
{
    BDT_LOG_FUNC_NAME();

    if (sBtL2CAPTestInterface == NULL)
    {
        BDT_LOG("Test Interface is NULL");
        return;
    }

    sBtL2CAPTestInterface->L2CAPTest_disconnect();
}

void do_L2CAPTest_senddata()
{
    int len;

    BDT_LOG_FUNC_NAME();

    if (sBtL2CAPTestInterface == NULL)
    {
        BDT_LOG("Test Interface is NULL");
        return;
    }

    printf("\tPlease enter data lenght[in byte] you want to send : ");
    scanf("%d", &len);

    sBtL2CAPTestInterface->L2CAPTest_senddata((uint16_t) len);
}

void do_L2CAPTest_ping()
{
    int val;

    BDT_LOG_FUNC_NAME();

    if (sBtL2CAPTestInterface == NULL)
    {
        BDT_LOG("Test Interface is NULL");
        return;
    }

    printf("\tEnter mode : 1 - PING : 2 - RNR : 3 - RR : ");
    scanf("%d", &val);
    sBtL2CAPTestInterface->L2CAPTest_ping(val);
}

void do_L2CAPTest_cleanup()
{
    BDT_LOG_FUNC_NAME();

    if (sBtL2CAPTestInterface == NULL)
    {
        BDT_LOG("Test Interface is NULL");
        return;
    }

    sBtL2CAPTestInterface->L2CAPTest_cleanup();
}
#endif // L2CAP_TESTER
#ifdef BNEP_TESTER
void do_BNEPTest_init()
{
    BDT_LOG_FUNC_NAME();

    if (sBtInterface == NULL)
    {
        BDT_LOG("BT HAL Interface is null");
        return;
    }

    sBtBNEPTestInterface = sBtInterface->get_profile_interface(BT_PROFILE_BNEP_TESTER_ID);

    if (sBtBNEPTestInterface == NULL)
    {
        BDT_LOG("Test Interface is NULL");
        return;
    }

    sBtBNEPTestInterface->BNEPTest_init();
}

void do_BNEPTest_send_control_msg()
{
    int which;
    if (sBtBNEPTestInterface == NULL)
     {
         BDT_LOG("Test Interface is NULL");
         return;
     }

     printf("\nWhich Command - 1 : Undefined, 2 : Setup Msg :: ");
     scanf("%d", &which);

     sBtBNEPTestInterface->BNEPTest_send_control_msg(which);
}
#endif // BNEP_TESTER

#ifdef AVDTP_TESTER

void do_AVDTPTest_init()
{
    BDT_LOG_FUNC_NAME();

    if (sBtInterface == NULL)
    {
        BDT_LOG("BT HAL Interface is null");
        return;
    }

    sBtAVDTPTestInterface = sBtInterface->get_profile_interface(BT_PROFILE_AVDTP_TESTER_ID);

    if (sBtAVDTPTestInterface == NULL)
    {
        BDT_LOG("Test Interface is NULL");
        return;
    }

    sBtAVDTPTestInterface->AVDTPTest_init();
}

void do_AVDTPTest_set_remote_addr()
{
    char bd_addr_str[18];
    bt_bdaddr_t bd_addr;

    BDT_LOG_FUNC_NAME();

    if (sBtInterface == NULL)
    {
        BDT_LOG("BT HAL Interface is null");
        return;
    }

    sBtAVDTPTestInterface = sBtInterface->get_profile_interface(BT_PROFILE_AVDTP_TESTER_ID);

    if (sBtAVDTPTestInterface == NULL)
    {
        BDT_LOG("Test Interface is NULL");
        return;
    }
    printf("\tPlease enter BD Address of Tester Device in \"ab cd ef aa bb cc\" format : ");
    fgets(bd_addr_str, 18, stdin);

    sscanf(bd_addr_str, "%hhx %hhx %hhx %hhx %hhx %hhx", &bd_addr.address[0], &bd_addr.address[1], &bd_addr.address[2],
            &bd_addr.address[3], &bd_addr.address[4], &bd_addr.address[5]);

    printf("\n\tEntered Device Address is : %hhx %hhx %hhx %hhx %hhx %hhx\n", bd_addr.address[0], bd_addr.address[1],
            bd_addr.address[2], bd_addr.address[3], bd_addr.address[4], bd_addr.address[5]);

    sBtAVDTPTestInterface->AVDTPTest_set_remote_bd_addr(&bd_addr);



}

void do_AVDTPTest_send_control_msg()
{
    int which;
    if (sBtAVDTPTestInterface == NULL)
     {
         BDT_LOG("Test Interface is NULL");
         return;
     }

     printf("\tDISCOVER   1 \tGETCAP     2 \n\tSETCONFIG  3 \tGETCONFIG  4 \n");
     printf("\tRECONFIG   5 \tOPEN       6 \n\tSTART      7 \tCLOSE      8 \n");
     printf("\tSUSPEND    9 \tABORT      10\n");
     printf("\tSET/RESET REJECT 91 - 99/90 \n");
     scanf("%d", &which);

     sBtAVDTPTestInterface->AVDTPTest_send_control_msg(which);
}
#endif //AVDTP_TESTER
#endif // TESTER

#ifdef VERIFIER
#ifdef AVDTP_VERIFIER
int tc_av_num = 0;
int tc_av_executing = 0;
int avdtp_status = 3; //TC_UNKNOWN

int w_av_evt = 1;

char *tc_av_string[] = {
"TP/SIG/SMG/BV-05-C",
"TP/SIG/SMG/BV-06-C",
"TP/SIG/SMG/BV-07-C",
"TP/SIG/SMG/BV-08-C",
"TP/SIG/SMG/BV-09-C",
"TP/SIG/SMG/BV-10-C",
"TP/SIG/SMG/BV-11-C",
"TP/SIG/SMG/BV-12-C",
"TP/SIG/SMG/BV-13-C",
"TP/SIG/SMG/BV-14-C",
"TP/SIG/SMG/BV-15-C",
"TP/SIG/SMG/BV-16-C",
"TP/SIG/SMG/BV-17-C",
"TP/SIG/SMG/BV-18-C",
"TP/SIG/SMG/BV-19-C",
"TP/SIG/SMG/BV-20-C",
"TP/SIG/SMG/BV-21-C",
"TP/SIG/SMG/BV-22-C",
"TP/SIG/SMG/BV-23-C",
"TP/SIG/SMG/BV-24-C",
"TP/SIG/SMG/BI-01-C", /*21*/
"TP/SIG/SMG/BI-02-C",
"TP/SIG/SMG/BI-03-C",
"TP/SIG/SMG/BI-04-C",
"TP/SIG/SMG/BI-05-C",
"TP/SIG/SMG/BI-06-C",
"TP/SIG/SMG/BI-07-C",
"TP/SIG/SMG/BI-08-C",
"TP/SIG/SMG/BI-09-C",
"TP/SIG/SMG/BI-10-C",
"TP/SIG/SMG/BI-11-C",
"TP/SIG/SMG/BI-12-C",
"TP/SIG/SMG/BI-13-C",
"TP/SIG/SMG/BI-14-C",
"TP/SIG/SMG/BI-15-C",
"TP/SIG/SMG/BI-16-C",
"TP/SIG/SMG/BI-17-C",
"TP/SIG/SMG/BI-18-C",
"TP/SIG/SMG/BI-19-C",
"TP/SIG/SMG/BI-20-C",
"TP/SIG/SMG/BI-21-C",
"TP/SIG/SMG/BI-22-C",
"TP/SIG/SMG/BI-23-C",
"TP/SIG/SMG/BI-24-C",
"TP/SIG/SMG/BI-25-C",
"TP/SIG/SMG/BI-26-C",
"TP/SIG/SMG/BI-27-C", /*47*/
"TP/SIG/SMG/BI-14-C2",
"TP/SIG/SMG/BI-14-C3",
NULL};

const avdtp_verifier_interface_t *sBtAVDTPVInterface = NULL;

void avdtp_callback ( uint8_t ev )
{
    switch(ev)
    {
        case TC_EVENT_CONN_CFM:
            printf("\tAVDTP Connection Established\n");
            avdtp_status = TC_SUCCESS;
        break;

        case TC_EVENT_CONN_FAILED:
            printf("\tAVDTP Connection Failed\n");
            avdtp_status = TC_FAILURE;
        break;

        case TC_EVENT_VER_PASS:
            printf("\tTest Case : PASSED\n");
        break;

        case TC_EVENT_VER_INCONC:
            printf("\tTest Case : INCONCLUSIVE\n");
        break;

        case TC_EVENT_VER_FAIL:
            printf("\tTest Case : FAILED\n");
        break;

        case TC_EVENT_EXEC_CONT:
            printf("\tReceived response to control message : CONT\n");
            avdtp_status = TC_SUCCESS;
        break;

        case TC_EVENT_EXEC_EXIT:
            printf("\tReceived response to control message : EXIT\n");
            avdtp_status = TC_FAILURE;
        break;
    }

    w_av_evt = 0;
}

void do_AVDTPV_init()
{
    BDT_LOG_FUNC_NAME();

    if (sBtInterface == NULL)
    {
        BDT_LOG("BT HAL Interface is null");
        return;
    }

    sBtAVDTPVInterface = sBtInterface->get_profile_interface(BT_PROFILE_AVDTP_VERIFIER_ID);

    if (sBtAVDTPVInterface == NULL)
    {
        BDT_LOG("AVDTP Verifier Interface is NULL");
        return;
    }

    sBtAVDTPVInterface->fnAVDTPV_init((void *)avdtp_callback);
}

void do_AVDTPV_set_remote_addr()
{
    int index;
    char bd_addr_str[18];
    bt_bdaddr_t bd_addr;

    BDT_LOG_FUNC_NAME();

    if (sBtAVDTPVInterface == NULL)
    {
        BDT_LOG("AVDTP Verifier Interface is NULL");
        return;
    }

    if(tc_av_executing)
    {
        printf("Test Case is Executing...\n");

        return;
    }

    printf("\tPlease enter BD Address of Tester Device in \"ab cd ef aa bb cc\" format : ");
    fgets(bd_addr_str, 18, stdin);

    sscanf(bd_addr_str, "%hhx %hhx %hhx %hhx %hhx %hhx", &bd_addr.address[0], &bd_addr.address[1], &bd_addr.address[2],
            &bd_addr.address[3], &bd_addr.address[4], &bd_addr.address[5]);

    printf("\n\tEntered Device Address is : %hhx %hhx %hhx %hhx %hhx %hhx\n", bd_addr.address[0], bd_addr.address[1],
            bd_addr.address[2], bd_addr.address[3], bd_addr.address[4], bd_addr.address[5]);

    sBtAVDTPVInterface->fnAVDTPV_set_remote_bd_addr(&bd_addr);
}

static int tc_av_wait_for_event ( unsigned int delay )
{
    int w_time = delay;

    w_av_evt = 1;
    while(w_time)
    {
        if(w_av_evt == 0)
        {
            break;
        }
        else
        {
            usleep(1000);
        }
        w_time--;
    }

    return (w_av_evt == 0) ? TC_SUCCESS : TC_FAILURE;
}

static void tc_av_handler( void *param )
{
    int tc_cmd = 0;
    int c_loop = 0;

    printf("\t=======================================================\n");
    printf("\tStarting Test Case %s\n", tc_av_string[tc_av_num - 1]);
    printf("\t=======================================================\n");
    sBtAVDTPVInterface->fnAVDTPV_select_test_case(tc_av_num, tc_av_string[tc_av_num - 1]);

    printf("\tVerifier will initiate connect with the IUT\n");

    avdtp_status = TC_FAILURE;
    for(c_loop = 0; c_loop < 5; c_loop++)
    {
        sBtAVDTPVInterface->fnAVDTPV_connect();
        if(tc_av_wait_for_event(1000) == TC_SUCCESS)
        {
            break;
        }

        printf("\tReinitiating the connection\n");
    }

    if((c_loop == 5) || (avdtp_status == TC_FAILURE))
    {
        printf("\tUnable to connect to IUT\n");
        printf("\tTest Case : INCONC\n");
        printf("\tPlease select an test case\n\n");

        tc_av_executing = 0;
        return;
    }

    avdtp_status = TC_FAILURE;
    do
    {
        tc_cmd = sBtAVDTPVInterface->fnAVDTPV_get_cmd();
        printf("\tCommand = %d\n", tc_cmd);
        if ( tc_cmd != TC_CMD_EXEC_WAIT )
        {
            printf("\tVerifier to send a Control Message\n");
            sBtAVDTPVInterface->fnAVDTPV_send_control_msg(tc_cmd);
            if (tc_av_wait_for_event(500) == TC_FAILURE)
            {
                avdtp_status = TC_FAILURE;
                break;
            }
        }
        else
        {
            printf("\tIUT to send a Control Message\n");
            if (tc_av_wait_for_event(50000) == TC_FAILURE)
            {
                avdtp_status = TC_FAILURE;
                break;
            }
        }

    } while ( avdtp_status != TC_FAILURE );

    printf("\tVerifier will initiate an Disconnect to IUT\n");
    sBtAVDTPVInterface->fnAVDTPV_disconnect();

    tc_av_executing = 0;
}

void do_AVDTPV_select_test_case()
{
    int tc, loop, len;
    pthread_t t_id;

    BDT_LOG_FUNC_NAME();

    if (sBtAVDTPVInterface == NULL)
    {
        BDT_LOG("\tAVDTP Verifier interface is NULL");
        return;
    }

    if(tc_av_executing)
    {
        printf("\tTest Case is Executing...\n");

        return;
    }

    tc_av_num = 0;
    tc_av_executing = 0;
    avdtp_status = TC_FAILURE;

    len = 0;
    while(tc_av_string[len] != NULL)
        len++;

    printf("\tPlease select a test case from 1 - %d\n", len);
    for(loop = 0; loop < len; loop++)
    {
        printf("\t%d. %s\n", loop + 1, (void *)tc_av_string[loop]);
    }
    scanf("%d", &tc);

    if((tc < 1) || (tc > len))
    {
        tc = 1;
    }
    tc_av_num = tc;

    if (pthread_create(&t_id, NULL, (void *)tc_av_handler, NULL) != 0)
    {
        perror("pthread_create");

        return;
    }

    tc_av_executing = 1;
}
/*
void do_AVDTPV_set_local_config()
{
    int choice;

    BDT_LOG_FUNC_NAME();

    if (sBtAVDTPVInterface == NULL)
    {
        BDT_LOG("AVDTP Verifier Interface is NULL");
        return;
    }

    if(tc_av_executing)
    {
        printf("Test Case is Executing...\n");

        return;
    }

    printf("\t1. Set Remote BD Address\n");
    printf("\t2. Set invalid command mode\n");
    scanf(" %d", &choice);

    switch(choice)
    {
        case 1:
        {
            int index;
            char bd_addr_str[18];
            bt_bdaddr_t bd_addr;

            printf("\tPlease enter BD Address of Tester Device in \"ab cd ef aa bb cc\" format : ");
            fgets(bd_addr_str, 18, stdin);

            sscanf(bd_addr_str, "%hhx %hhx %hhx %hhx %hhx %hhx", &bd_addr.address[0], &bd_addr.address[1], &bd_addr.address[2],
            &bd_addr.address[3], &bd_addr.address[4], &bd_addr.address[5]);

            printf("\n\tEntered Device Address is : %hhx %hhx %hhx %hhx %hhx %hhx\n", bd_addr.address[0], bd_addr.address[1],
            bd_addr.address[2], bd_addr.address[3], bd_addr.address[4], bd_addr.address[5]);

            sBtAVDTPVInterface->fnAVDTPV_set_remote_bd_addr(&bd_addr);
        }
        break;

        case 2:
        {
            int choice;

            printf("Choose invalid mode for");
            printf("\tDISCOVER   1 \tGETCAP     2 \n\tSETCONFIG  3 \tGETCONFIG  4 \n");
            printf("\tRECONFIG   5 \tOPEN       6 \n\tSTART      7 \tCLOSE      8 \n");
            printf("\tSUSPEND    9 \tRESET 0\n");
            scanf(" %d", &choice);
            sBtAVDTPVInterface->fnAVDTPV_set_invalid_mode(choice);
        }
        break;

    }

}
*/
#endif //AVDTP_VERIFIER

#ifdef BNEP_VERIFIER
int tc_num = 0;
int tc_executing = 0;
int bnep_status = 0;

int w_evt = 1;

char *tc_string[] = {"TP/BNEP/CTRL/BV-01-C",
                    "TP/BNEP/CTRL/BV-02-C",
                    "TP/BNEP/CTRL/BV-03-C",
                    "TP/BNEP/CTRL/BV-04-C",
                    "TP/BNEP/CTRL/BV-05-C",
                    "TP/BNEP/CTRL/BV-10-C",
                    "TP/BNEP/RX-TYPE-0/BV-11-C",
                    "TP/BNEP/RX-TYPE-0/BV-15-C",
                    "TP/BNEP/RX-TYPE-0/BV-16-C",
                    "TP/BNEP/RX-TYPE-0/BV-17-C",
                    "TP/BNEP/RX-TYPE-0/BV-18-C",
                    "TP/BNEP/CTRL/BV-19-C"};

const bnep_verifier_interface_t* sBtBNEPVInterface = NULL;

void bnep_callback ( uint8_t ev )
{
    switch(ev)
    {
        case TC_EVENT_CONN_CFM:
            printf("\tBNEP Connection Established\n");
            bnep_status = TC_SUCCESS;
        break;

        case TC_EVENT_CONN_FAILED:
            printf("\tBNEP Connection Failed\n");
            bnep_status = TC_FAILURE;
        break;

        case TC_EVENT_VER_PASS:
            printf("\tTest Case : PASSED\n");
        break;

        case TC_EVENT_VER_INCONC:
            printf("\tTest Case : INCONCLUSIVE\n");
        break;

        case TC_EVENT_VER_FAIL:
            printf("\tTest Case : FAILED\n");
        break;

        case TC_EVENT_EXEC_CONT:
            printf("\tReceived response to control message\n");
            bnep_status = TC_SUCCESS;
        break;

        case TC_EVENT_EXEC_EXIT:
            printf("\tReceived response to control message\n");
            bnep_status = TC_FAILURE;
        break;
    }

    w_evt = 0;
}

void do_BNEPV_init()
{
    BDT_LOG_FUNC_NAME();

    if (sBtInterface == NULL)
    {
        BDT_LOG("BT HAL Interface is null");
        return;
    }

    sBtBNEPVInterface = sBtInterface->get_profile_interface(BT_PROFILE_BNEP_VERIFIER_ID);

    if (sBtBNEPVInterface == NULL)
    {
        BDT_LOG("BNEP Verifier Interface is NULL");
        return;
    }

    sBtBNEPVInterface->fnBNEPV_init((void *)bnep_callback);
}

void do_BNEPV_set_remote_addr()
{
    int index;
    char bd_addr_str[18];
    bt_bdaddr_t bd_addr;

    BDT_LOG_FUNC_NAME();

    if (sBtBNEPVInterface == NULL)
    {
        BDT_LOG("BNEP Verifier Interface is NULL");
        return;
    }

    if(tc_executing)
    {
        printf("Test Case is Executing...\n");

        return;
    }

    printf("\tPlease enter BD Address of Tester Device in \"ab cd ef aa bb cc\" format : ");
    fgets(bd_addr_str, 18, stdin);

    sscanf(bd_addr_str, "%hhx %hhx %hhx %hhx %hhx %hhx", &bd_addr.address[0], &bd_addr.address[1], &bd_addr.address[2],
            &bd_addr.address[3], &bd_addr.address[4], &bd_addr.address[5]);

    printf("\n\tEntered Device Address is : %hhx %hhx %hhx %hhx %hhx %hhx\n", bd_addr.address[0], bd_addr.address[1],
            bd_addr.address[2], bd_addr.address[3], bd_addr.address[4], bd_addr.address[5]);

    sBtBNEPVInterface->fnBNEPV_set_remote_bd_addr(&bd_addr);
}

static void tc_wait_for_event ( void )
{
    int t_cmds = 0;

    w_evt = 1;
    while(1)
    {
        if(w_evt == 0)
        {
            break;
        }
        else
        {
            sleep(1);
        }

        t_cmds++;
        if(t_cmds == TC_WAIT_TIME)
        {
            bnep_status = TC_FAILURE;
            break;
        }
    }
}

static void tc_handler( void *param )
{
    int tc_cmd = 0;
    int c_loop = 0;

    printf("\t=======================================================\n");
    printf("\tStarting Test Case %s\n", tc_string[tc_num - 1]);
    printf("\t=======================================================\n");
    sBtBNEPVInterface->fnBNEPV_select_test_case(tc_num, tc_string[tc_num - 1]);

    printf("\tVerifier will initiate connect with the IUT\n");
    for(c_loop = 0; c_loop < 5; c_loop++)
    {
        sBtBNEPVInterface->fnBNEPV_connect();

        tc_wait_for_event();

        if(bnep_status == TC_SUCCESS)
        {
            break;
        }

        printf("\tReinitiating the connection\n");
    }

    if(c_loop == 5)
    {
        printf("\tUnable to connect to IUT\n");
        printf("\tTest Case : INCONC\n");
        printf("\tPlease select an test case\n\n");

        tc_executing = 0;
        return;
    }

    do
    {
        tc_cmd = sBtBNEPVInterface->fnBNEPV_get_cmd();
        printf("\tCommand = %d\n", tc_cmd);
        if ( tc_cmd != TC_CMD_EXEC_WAIT )
        {
            printf("\tVerifier to send an Control Message\n");
            sBtBNEPVInterface->fnBNEPV_send_control_msg(tc_cmd);
        }
        else
        {
            printf("\tIUT to send an Control Message\n");
        }

        tc_wait_for_event();
    } while ( bnep_status != TC_FAILURE );

    printf("\tVerifier will initiate an Disconnect to IUT\n");
    sBtBNEPVInterface->fnBNEPV_disconnect();

    tc_executing = 0;
}

void do_BNEPV_select_test_case()
{
    int tc, loop;
    pthread_t t_id;

    BDT_LOG_FUNC_NAME();

    if (sBtBNEPVInterface == NULL)
    {
        BDT_LOG("\tBNEP Verifier interface is NULL");
        return;
    }

    if(tc_executing)
    {
        printf("\tTest Case is Executing...\n");

        return;
    }

    tc_num = 0;
    tc_executing = 0;
    bnep_status = TC_FAILURE;


    printf("\tPlease select a test case from 1 - 12\n");
    for(loop = 0; loop < 12; loop++)
    {
        printf("\t%d. %s\n", loop + 1, (void *)tc_string[loop]);
    }
    scanf("%d", &tc);

    if((tc < 1) || (tc > 12))
    {
        tc = 1;
    }
    tc_num = tc;

    if (pthread_create(&t_id, NULL, (void *)tc_handler, NULL) != 0)
    {
        perror("pthread_create");

        return;
    }

    tc_executing = 1;
}
#endif // BNEP_VERIFIER
#endif // VERIFIER

/*******************************************************************
 *
 *  CONSOLE COMMAND TABLE
 *
*/

const t_cmd console_cmd_list[] =
{
    /*
     * INTERNAL
     */

    { "help", do_help, "lists all available console commands", 0 },
    { "quit", do_quit, "", 0},

    /*
     * API CONSOLE COMMANDS
     */

    /* Init and Cleanup shall be called automatically */
    { "enable", do_enable, ":: enables bluetooth", 0 },
    { "disable", do_disable, ":: disables bluetooth", 0 },
    { "dut_mode_configure", do_dut_mode_configure, ":: DUT mode - 1 to enter,0 to exit", 0 },
    { "scan", do_start_discovery,"::starts discovery",0},
    { "scan_cancel", do_discovery_cancel,"::Cancels ongoing discovery",0},
    { "connect",do_connect,"::connect to a device",0},
    { "file",do_file,"::Run stress test",0},
    { "delay",do_delay,"::To be used in Script only",0},
    { "repeat",do_repeat,"::To be used in Script only",0},
    { "async",do_async,"::To be used in Script only",0},
#ifdef DYNAMIC_HCI_LOGGING
/*
    { "hci_log_enable",do_hci_enable,"::enables hci logging",0},
    { "hci_log_disable",do_hci_disable,"::disables hci logging",0},
    { "hci_trace_enable",do_set_hci_enable,"::enables hci traces",0},
    { "hci_trace_disable",do_set_hci_disable,"::disables hci traces",0},
*/
#endif
    { "file_RX",do_listen,"::listen to our custom communication",0},
    { "discoverable",do_discoverable,":: make our device discoverable",0},
    { "bonded_devices",do_bonded_device,"::display bonded devices",0},

    { "le_test_mode", do_le_test_mode, ":: LE Test Mode - RxTest - 1 <rx_freq>, \n\t \
                      TxTest - 2 <tx_freq> <test_data_len> <payload_pattern>, \n\t \
                      End Test - 3 <no_args>", 0 },
#ifdef VERIFIER
#ifdef BNEP_VERIFIER
    { "BNEPV_init", do_BNEPV_init, ":: Initialise the BNEP Verifier Interface", 0},
    { "BNEPV_set_remote_addr", do_BNEPV_set_remote_addr, ":: Set the tester address", 0},
    { "BNEPV_select_test_case", do_BNEPV_select_test_case, ":: Select a test case to verify", 0},
#endif // BNEP_VERIFIER

#ifdef AVDTP_VERIFIER
    { "AVDTPV_init", do_AVDTPV_init, ":: Initialise the AVDTP Verifier Interface", 0},
    { "AVDTPV_set_remote_addr", do_AVDTPV_set_remote_addr,  ":: Set the tester address", 0},
//  { "AVDTPV_set_local_config", do_AVDTPV_set_local_config, ":: Set the tester address and invalid command modes", 0},
    { "AVDTPV_select_test_case", do_AVDTPV_select_test_case, ":: Select a test case to verify", 0},
#endif // AVDTP_VERIFIER

#endif // VERIFIER


#ifdef TESTER
#ifdef L2CAP_TESTER
    { "L2CAPTest_init",do_L2CAPTest_init,"::initialize l2cap test interafce",0},
    { "L2CAPTest_set_etm_parameters", do_L2CAPTest_set_default_parameters, ":: set default parameters", 0},
    { "L2CAPTest_set_parameters", do_L2CAPTest_set_parameters, ":: set parameters", 0},
    { "L2CAPTest_set_remote_bd_addr",do_L2CAPTest_set_remote_bd_addr,"::set remote device BD address",0},
    { "L2CAPTest_connect",do_L2CAPTest_connect,"::connect to a remote device",0},
    { "L2CAPTest_disconnect",do_L2CAPTest_disconnect,"::disconnect remote device",0},
    { "L2CAPTest_senddata",do_L2CAPTest_senddata,"::send data to remote device",0},
    { "L2CAPTest_ping",do_L2CAPTest_ping,"::ping L2CAP Test interafce",0},
    { "L2CAPTest_cleanup",do_L2CAPTest_cleanup,"::clean up L2CAP Test interafce",0},
#endif
#ifdef BNEP_TESTER
    { "BNEPTest_init",do_BNEPTest_init,"::initialize bnep test interface",0},
    { "BNEPTest_send_control_msg",do_BNEPTest_send_control_msg, "::BNEP Send Control Msg",0},
#endif

#ifdef AVDTP_TESTER
    { "AVDTPTest_init",do_AVDTPTest_init,"::initialize avdtp test interface",0},
    { "AVDTPTest_set_remote_addr",do_AVDTPTest_set_remote_addr,"::set remote bd address",0},
    { "AVDTPTest_send_control_msg",do_AVDTPTest_send_control_msg, "::AVDTP Send Control Msg",0},
#endif //AVDTP_TESTER

#endif // TESTER
    /* add here */

    /* last entry */
    {NULL, NULL, "", 0},
};

/*
 * Main console command handler
*/

static void process_cmd(char *p, unsigned char is_job)
{

    char cmd[1024], dummy[10];
    int i = 0;
    char *p_saved = p;

    get_str(&p, cmd);
    //sscanf(p,"%[* ]%s", dummy, p);

    bdt_log("%s command:%s: p:%s:", __func__, cmd, p);

    /* table commands */
    while (console_cmd_list[i].name != NULL)
    {
        if (is_cmd(console_cmd_list[i].name))
        {
            if (!is_job && console_cmd_list[i].is_job)
                create_cmdjob(p_saved);
            else
            {
                console_cmd_list[i].handler(p);
            }
            return;
        }
        i++;
    }
    bdt_log("%s : unknown command\n", p_saved);
    do_help(NULL);
}

int main (int argc, char * argv[])
{
    int opt;
    char line[1024];
    int args_processed = 0;
    int pid = -1;
    int i;

    config_permissions();
    bdt_log("\n:::::::::::::::::::::::::::::::::::::::::::::::::::");
    bdt_log(":: Bluedroid test app starting");

    if ( HAL_load() < 0 )
    {
        perror("HAL failed to initialize, exit\n");
        unlink(PID_FILE);
        exit(0);
    }

    setup_test_env();

    /* Automatically perform the init */
    bdt_init();
    bdt_get_profile_interface(BT_PROFILE_SOCKETS_ID);
    bdt_get_adapter_property(0x02);
    bdt_get_adapter_property(0x01);
    init_stack(&stack);
    if (argc >= 2)
    {
        sleep(2);
        bzero(line, 1024);
        for (i=1; i<argc; i++)
        {
            if (i == 1)
                sprintf(line, "%s", argv[i]);
            else
                sprintf(line, "%s %s", line, argv[i]);
        }
        bdt_log("bdt cmd line argument:%s:\n", line);
        process_cmd(line, 0);
        exit(0);
    }
    while(!main_done)
    {
        /* command prompt */
        printf( ">" );
        fflush(stdout);

        fgets (line, 128, stdin);

        if (line[0]!= '\0')
        {
            /* remove linefeed */
            line[strlen(line)-1] = 0;

            process_cmd(line, 0);
            memset(line, '\0', 128);
        }
    }

    /* FIXME: Commenting this out as for some reason, the application does not exit otherwise*/
    //bdt_cleanup();

    HAL_unload();

    BDT_LOG(":: Bluedroid test app terminating");

    return 0;
}
