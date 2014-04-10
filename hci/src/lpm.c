/******************************************************************************
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

/******************************************************************************
 *
 *  Filename:      lpm.c
 *
 *  Description:   Contains low power mode implementation
 *
 ******************************************************************************/

#define LOG_TAG "bt_lpm"

#include <utils/Log.h>
#include <signal.h>
#include <time.h>
#include "bt_hci_bdroid.h"
#include "bt_vendor_lib.h"

/******************************************************************************
**  Constants & Macros
******************************************************************************/

#ifndef BTLPM_DBG
#define BTLPM_DBG TRUE
#endif

#if (BTLPM_DBG == TRUE)
#define BTLPMDBG(param, ...) {ALOGD(param, ## __VA_ARGS__);}
#else
#define BTLPMDBG(param, ...) {}
#endif

#ifndef DEFAULT_LPM_IDLE_TIMEOUT
#define DEFAULT_LPM_IDLE_TIMEOUT    3000
#endif

/* Maximum number of L2CAP channels that L2CAP can support */
#ifndef MAX_L2CAP_CHANNELS
#define MAX_L2CAP_CHANNELS 10
#endif

/******************************************************************************
**  Externs
******************************************************************************/

extern bt_vendor_interface_t *bt_vnd_if;
extern bt_hc_callbacks_t *bt_hc_cbacks;

/******************************************************************************
**  Local type definitions
******************************************************************************/

/* Low power mode state */
enum {
    LPM_DISABLED = 0,                    /* initial state */
    LPM_ENABLED,
    LPM_ENABLING,
    LPM_DISABLING
};

/* LPM DEVICE state */
enum {
    D0,                                 /* Full Operational mode */
    D0I0,                               /* Not used */
    D0I1,                               /* Not used */
    D0I2,                               /* Some clocks are powered down */
    D0I3,                               /* Most aggresive power save mode */
    D3,                                 /* Fully powered down */
    ANY
};

/* LPM BT WAKE / HOST WAKE / RTS / CTS state */
enum {
    LOW,
    HIGH
};

enum {
    START_TRANSPORT_IDLE_TIMER_HOST_WAKE = 0xF0, /* Host wake is low */
    START_TRANSPORT_IDLE_TIMER_BT_WAKE   = 0x0F, /* bt wake is low */
    START_TRANSPORT_IDLE_TIMER           = 0xFF, /* bt wake and host wake is low */
};

enum {
    NO_TX_ACL_DATA = 0xF0, /* No TX data to send */
    NO_TX_HCI_CMD  = 0x0F, /* No hci cmd to send */
    NO_TX          = 0xFF, /* No TX */
};

typedef struct
{
    uint32_t latency;
} qos_param_t;

typedef struct
{
    uint8_t pkt_count;
    uint8_t pkt_rate;
    uint8_t pkt_rate_threshold;
    uint8_t pkt_rate_threshold_correction;
    timer_t timer_id;
    uint32_t timeout_ms;
    uint8_t timer_created;
} lpm_pkt_rate_params_t;

/* low power mode control block */
typedef struct
{
    uint8_t state;                          /* Low power mode state */
    uint8_t device_state;                   /* LPM DEVICE state */
    uint8_t bt_wake_state;                  /* LPM BT WAKE state */
    uint8_t host_wake_state;                /* LPM HOST WAKE state */
    uint8_t rts_state;                      /* LPM RTS state */
    uint8_t cts_state;                      /* LPM CTS state */
    qos_param_t qos_param[MAX_L2CAP_CHANNELS]; /* qos param per cid */
    uint32_t min_profile_latency;           /* Min Latency among active links */
    uint32_t D0I3_wake_time;                /* Platform dependent */
    /* Flag to indicate bt wake host wake status */
    uint8_t start_transport_idle_timer;
    uint8_t no_tx;
    uint8_t timer_created;
    timer_t timer_id;
    uint32_t timeout_ms;
    uint8_t timer_started;                  /* transport idle timer started */

    /* packet rate monitoring for D0I2 state */
    lpm_pkt_rate_params_t pkt_rate_params;   /* Packet rate motoring params */
} bt_lpm_cb_t;


/******************************************************************************
**  Static variables
******************************************************************************/

static bt_lpm_cb_t bt_lpm_cb;
/* Mutex variables to protect shared variables */
static pthread_mutex_t device_state_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t bt_wake_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t host_wake_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t start_transport_idle_timer_mutex = \
                                            PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t cts_state_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t pkt_count_mutex = PTHREAD_MUTEX_INITIALIZER;

/******************************************************************************
**   LPM Function declaration
******************************************************************************/
static void lpm_periodic_pkt_rate_timeout(union sigval arg);
static void lpm_periodic_pkt_rate_stop_timer(void);
static void lpm_idle_timeout(union sigval arg);
static void lpm_start_transport_idle_timer(void);
static void lpm_stop_transport_idle_timer(void);
static void lpm_periodic_pkt_rate_start_timer(void);
void lpm_periodic_pkt_rate_init_timer(void);
void lpm_increase_pkt_count();
void lpm_init(void);
void lpm_cleanup(void);
void lpm_enable(uint8_t turn_on);
void lpm_tx_done(uint8_t is_tx_done);
void lpm_wake_assert(void);
void lpm_allow_bt_device_sleep(void);
void lpm_wake_deassert(void);
int lpm_set_device_state(uint8_t source_state, uint8_t next_state);
void lpm_set_bt_wake_state(uint8_t state);
void lpm_host_wake_handler(uint8_t state);
/******************************************************************************
**   LPM Static Functions
******************************************************************************/
/*******************************************************************************
**
** Function        lpm_periodic_pkt_rate_timeout
**
** Description     Timeout thread of periodic pkt rate monitoring thread
**                 On the basis of the pkt rate decide whether to go to D0I2/D0
**
** Returns         None
**
*******************************************************************************/
static void lpm_periodic_pkt_rate_timeout(union sigval arg)
{
    //BTLPMDBG("%s", __func__);
    if (bt_lpm_cb.state == LPM_ENABLED)
    {
        /* calculate packet rate */
        bt_lpm_cb.pkt_rate_params.pkt_rate = bt_lpm_cb.pkt_rate_params.pkt_count;
        if(bt_lpm_cb.pkt_rate_params.pkt_rate < \
            bt_lpm_cb.pkt_rate_params.pkt_rate_threshold + \
            bt_lpm_cb.pkt_rate_params.pkt_rate_threshold_correction)
        {
            /* go to D0I2 */
            lpm_set_device_state(D0, D0I2);
        }
        else if(bt_lpm_cb.pkt_rate_params.pkt_rate >= \
            bt_lpm_cb.pkt_rate_params.pkt_rate_threshold - \
            bt_lpm_cb.pkt_rate_params.pkt_rate_threshold_correction)
        {
            /* go to D0 */
            lpm_set_device_state(D0I2, D0);
        }
        /* Make pkt count 0 for next time slot */
        pthread_mutex_lock(&pkt_count_mutex);
        bt_lpm_cb.pkt_rate_params.pkt_count = 0;
        pthread_mutex_unlock(&pkt_count_mutex);

        /* Restart the timer only if device is in D0/D0I2 state */
        pthread_mutex_lock(&device_state_mutex);
        if (bt_lpm_cb.device_state == D0 || bt_lpm_cb.device_state == D0I2)
        {
            pthread_mutex_unlock(&device_state_mutex);
            lpm_periodic_pkt_rate_start_timer();
        }
        else
            pthread_mutex_unlock(&device_state_mutex);
    }
}

/*******************************************************************************
**
** Function        lpm_periodic_pkt_rate_start_timer
**
** Description     Launch periodic pkt rate monitoring timer
**                 Time to time packet rate will be checked. If the packet rate
**                 is below certain threshold then the device state can go to
**                 D0I2 and vice versa.
**
** Returns         None
**
*******************************************************************************/
static void lpm_periodic_pkt_rate_start_timer(void)
{
    int status;
    struct itimerspec ts;
    struct sigevent se;
    //BTLPMDBG("%s", __func__);
    if (bt_lpm_cb.state != LPM_ENABLED)
        return;

    if (bt_lpm_cb.pkt_rate_params.timer_created == FALSE)
    {
        se.sigev_notify = SIGEV_THREAD;
        se.sigev_value.sival_ptr = &bt_lpm_cb.pkt_rate_params.timer_id;
        se.sigev_notify_function = lpm_periodic_pkt_rate_timeout;
        se.sigev_notify_attributes = NULL;

        status = timer_create(CLOCK_MONOTONIC, &se, \
                                    &bt_lpm_cb.pkt_rate_params.timer_id);

        if (status == 0)
            bt_lpm_cb.pkt_rate_params.timer_created = TRUE;
    }

    if (bt_lpm_cb.pkt_rate_params.timer_created == TRUE)
    {
        //BTLPMDBG("%s bt_lpm_cb.pkt_rate_params.timeout_ms: %d", __func__, bt_lpm_cb.pkt_rate_params.timeout_ms);
        ts.it_value.tv_sec = bt_lpm_cb.pkt_rate_params.timeout_ms/1000;
        ts.it_value.tv_nsec = 1000*1000*(bt_lpm_cb.pkt_rate_params.timeout_ms%1000);
        ts.it_interval.tv_sec = 0;
        ts.it_interval.tv_nsec = 0;

        status = timer_settime(bt_lpm_cb.pkt_rate_params.timer_id, 0, &ts, 0);
        if (status == -1)
            ALOGE("[START] Failed to set LPM idle timeout");
    }
}

/*******************************************************************************
**
** Function        lpm_periodic_pkt_rate_init_timer
**
** Description     Launch periodic packet rate monitor timer.
**
** Returns         None
**
*******************************************************************************/
void lpm_periodic_pkt_rate_init_timer(void)
{
    bt_lpm_cb.start_transport_idle_timer = START_TRANSPORT_IDLE_TIMER;
    lpm_periodic_pkt_rate_start_timer();
}

/*******************************************************************************
**
** Function        lpm_periodic_pkt_rate_stop_timer
**
** Description     Launch periodic packet rate monitor timer.
**
** Returns         None
**
*******************************************************************************/
static void lpm_periodic_pkt_rate_stop_timer(void)
{
    int status;
    struct itimerspec ts;
    BTLPMDBG("%s", __func__);

    if (bt_lpm_cb.timer_created == TRUE)
    {
        ts.it_value.tv_sec = 0;
        ts.it_value.tv_nsec = 0;
        ts.it_interval.tv_sec = 0;
        ts.it_interval.tv_nsec = 0;

        status = timer_settime(bt_lpm_cb.pkt_rate_params.timer_id, 0, &ts, 0);
        if (status == -1)
            ALOGE("[STOP] Failed to set LPM idle timeout");
    }
}

/*******************************************************************************
**
** Function        lpm_idle_timeout
**
** Description     Timeout thread of transport idle timer
**                 Take decision based on the present device state what whould
**                 be the next device state.
**
**                 TODO: Implement profile monitoring for D0I3 and pkt rate
**                 algorithm for D0I2.
**
** Returns         None
**
*******************************************************************************/
static void lpm_idle_timeout(union sigval arg)
{
    BTLPMDBG("%s", __func__);

    if (bt_lpm_cb.state == LPM_ENABLED)
    {
        bthc_signal_event(HC_EVENT_LPM_IDLE_TIMEOUT);
    }
}

/*******************************************************************************
**
** Function        lpm_start_transport_idle_timer
**
** Description     Launch transport idle timer. This can be triggered from two
**                 threads: host_wake handle thread, and bt wake handle thread.
**                 This is protected by start_transport_idle_timer_mutex from
**                 the calling place. So no need to protect here.
**
**                 Idle timer is started if there is no data to send and no data
**                 to receive. So, when both bt wake and host wake are low it is
**                 invoked and timer is started.
**
** Returns         None
**
*******************************************************************************/
static void lpm_start_transport_idle_timer(void)
{
    int status;
    struct itimerspec ts;
    struct sigevent se;

    BTLPMDBG("%s", __func__);

    if (bt_lpm_cb.state != LPM_ENABLED || bt_lpm_cb.timer_started == TRUE)
        return;

    if (bt_lpm_cb.timer_created == FALSE)
    {
        se.sigev_notify = SIGEV_THREAD;
        se.sigev_value.sival_ptr = &bt_lpm_cb.timer_id;
        se.sigev_notify_function = lpm_idle_timeout;
        se.sigev_notify_attributes = NULL;

        status = timer_create(CLOCK_MONOTONIC, &se, &bt_lpm_cb.timer_id);

        if (status == 0)
            bt_lpm_cb.timer_created = TRUE;
    }

    if (bt_lpm_cb.timer_created == TRUE)
    {
        ts.it_value.tv_sec = bt_lpm_cb.timeout_ms/1000;
        ts.it_value.tv_nsec = 1000*1000*(bt_lpm_cb.timeout_ms%1000);
        ts.it_interval.tv_sec = 0;
        ts.it_interval.tv_nsec = 0;

        status = timer_settime(bt_lpm_cb.timer_id, 0, &ts, 0);
        if (status == -1)
            ALOGE("[START] Failed to set LPM idle timeout");
        else
            bt_lpm_cb.timer_started = TRUE;
    }
}

/*******************************************************************************
**
** Function        lpm_stop_transport_idle_timer
**
** Description     Launch transport idle timer. This can be called from two
**                 contexts: bt wake high, host wake high. this call is already
**                 guarded by start_transport_idle_timer_mutex from the calling
**                 context. So no need to guard here.
**
**                 Timer is stopped when there is data to send (bt wake is high)
**                 or data to recv (host wake is high).
**
** Returns         None
**
*******************************************************************************/
static void lpm_stop_transport_idle_timer(void)
{
    int status;
    struct itimerspec ts;

    BTLPMDBG("%s", __func__);

    if (bt_lpm_cb.timer_created == TRUE && bt_lpm_cb.timer_started == TRUE )
    {
        ts.it_value.tv_sec = 0;
        ts.it_value.tv_nsec = 0;
        ts.it_interval.tv_sec = 0;
        ts.it_interval.tv_nsec = 0;

        status = timer_settime(bt_lpm_cb.timer_id, 0, &ts, 0);
        if (status == -1)
            ALOGE("[STOP] Failed to set LPM idle timeout");
        else
            bt_lpm_cb.timer_started = FALSE; /* Timer stopped */
    }
}

/*******************************************************************************
**
** Function         lpm_vnd_cback
**
** Description      Callback of vendor specific result for lpm enable/disable
**                  rquest
**
** Returns          None
**
*******************************************************************************/
void lpm_vnd_cback(uint8_t vnd_result)
{
    if (bt_hc_cbacks)
    {
        BTLPMDBG("%s call bte_main lpm_cb to notify that lpm is enabled. device state:%d", __func__, bt_lpm_cb.device_state);
        if (bt_hc_cbacks->lpm_cb)
            bt_hc_cbacks->lpm_cb(1);
    }
}

/*****************************************************************************
**   Low Power Mode Interface Functions
*****************************************************************************/
/*******************************************************************************
**
** Function        lpm_increase_pkt_count
**
** Description     Init LPM
**
** Returns         None
**
*******************************************************************************/
void lpm_increase_pkt_count()
{
    if (bt_lpm_cb.state != LPM_DISABLED)
    {
        pthread_mutex_lock(&pkt_count_mutex);
        bt_lpm_cb.pkt_rate_params.pkt_count++;
        pthread_mutex_unlock(&pkt_count_mutex);
    }
}
/*******************************************************************************
**
** Function        lpm_init
**
** Description     Init LPM
**
** Returns         None
**
*******************************************************************************/
void lpm_init(void)
{
    memset(&bt_lpm_cb, 0, sizeof(bt_lpm_cb_t));
    static bt_vendor_lpm_param_t lpm_param;
    BTLPMDBG("%s", __func__);
    /* Calling vendor-specific part */
    if (bt_vnd_if)
    {
        bt_vnd_if->op(BT_VND_OP_GET_LPM_IDLE_TIMEOUT, &lpm_param);
        bt_lpm_cb.timeout_ms = lpm_param.idle_timeout;
        bt_lpm_cb.pkt_rate_params.timeout_ms =
                    lpm_param.pkt_rate_monitor_period;
        bt_lpm_cb.pkt_rate_params.pkt_rate_threshold =
                    lpm_param.pkt_rate_monitor_threshold;
        bt_lpm_cb.pkt_rate_params.pkt_rate_threshold_correction =
                    lpm_param.pkt_rate_monitor_correction_factor;
        bt_lpm_cb.D0I3_wake_time = lpm_param.wakeup_time;
    }
    else
        bt_lpm_cb.timeout_ms = DEFAULT_LPM_IDLE_TIMEOUT;
}

/*******************************************************************************
**
** Function        lpm_cleanup
**
** Description     Clean up
**
** Returns         None
**
*******************************************************************************/
void lpm_cleanup(void)
{
    BTLPMDBG("%s", __func__);
    if (bt_lpm_cb.timer_created == TRUE)
    {
        timer_delete(bt_lpm_cb.timer_id);
    }
}

/*******************************************************************************
**
** Function        lpm_enable
**
** Description     Enalbe/Disable LPM
**
** Returns         None
**
*******************************************************************************/
void lpm_enable(uint8_t turn_on)
{
    uint8_t state = LOW;
    uint8_t lpm_cmd;
    BTLPMDBG("%s turn_on:%d", __func__, turn_on);

    if (turn_on == BT_VND_LPM_ENABLE)
    {
        lpm_cmd = BT_VND_LPM_ENABLE;
        if(NULL==bt_vnd_if)
        {
            BTLPMDBG("%s bt_vnd_if is NULL",__func__);
            return;
        }
        if (bt_vnd_if->op(BT_VND_OP_LPM_SET_MODE, &lpm_cmd) == -1)
        {
            BTLPMDBG("%s lpm is disabled in conf file", __func__);
            bt_lpm_cb.state = LPM_DISABLED;
            return;
        }
        bt_lpm_cb.state = lpm_cmd;
        bt_lpm_cb.pkt_rate_params.pkt_count = 0;
        bt_lpm_cb.pkt_rate_params.pkt_rate = 0;
        bt_lpm_cb.pkt_rate_params.timer_created = FALSE;
        bt_lpm_cb.cts_state = HIGH;
        bt_lpm_cb.device_state = -1;
        bt_lpm_cb.bt_wake_state = LOW;
        bt_lpm_cb.host_wake_state = LOW;
        bt_lpm_cb.start_transport_idle_timer = START_TRANSPORT_IDLE_TIMER;
        //lpm_periodic_pkt_rate_start_timer();
        lpm_set_device_state(ANY, D0);
        //lpm_host_wake_handler(HIGH);
        lpm_set_bt_wake_state(HIGH);
    }
    else if (turn_on == BT_VND_LPM_DISABLE)
    {
        lpm_periodic_pkt_rate_stop_timer();
        lpm_set_bt_wake_state(LOW);
        if (bt_vnd_if)
            bt_vnd_if->op(BT_VND_OP_LPM_SET_RTS_STATE, &state);
        BTLPMDBG("%s Sending D3", __func__);
        lpm_set_device_state(ANY, D3);
        if (bt_vnd_if)
        {
            lpm_cmd = BT_VND_LPM_DISABLE;
            if (bt_vnd_if->op(BT_VND_OP_LPM_SET_MODE, &lpm_cmd) == -1)
            {
                /* LPM is disabled by configuration file */
                bt_lpm_cb.state = LPM_DISABLED;
                return;
            }
            bt_lpm_cb.state = lpm_cmd;
        }
    }
}

/*******************************************************************************
**
** Function          lpm_tx_done
**
** Description       This function is to inform the lpm module
**                   if data is waiting in the Tx Q or not.
**
**                   IsTxDone: TRUE if All data in the Tx Q are gone
**                             FALSE if any data is still in the Tx Q.
**                   Typicaly this function must be called
**                   before USERIAL Write and in the Tx Done routine
**
** Returns           None
**
*******************************************************************************/
void lpm_tx_done(uint8_t is_tx_done)
{
    /* Nothing to do */
}

/*******************************************************************************
**
** Function        lpm_wake_assert
**
** Description     Called to wake up Bluetooth chip.
**                 Normally this is called when there is data to be sent
**                 over UART.
**                 1. if device state is D0I3 change to D0
**                 2. if CTS is low send bt wake high
**
** Returns         None
**
*******************************************************************************/
void lpm_wake_assert(void)
{
    /* Increase the pkt count */
    lpm_increase_pkt_count();
    if (bt_lpm_cb.state != LPM_DISABLED)
    {
        /* Change device state if required */
        lpm_set_device_state(D0I3, D0);
        /* Check CTS state */
        pthread_mutex_lock(&cts_state_mutex);
        if (bt_lpm_cb.cts_state == LOW)
        {
            BTLPMDBG("%s CTS LOW. Turn bt_wake HIGH" ,__func__);
            pthread_mutex_unlock(&cts_state_mutex);
            /* Set BT WAKE state to HIGH */
            lpm_set_bt_wake_state(HIGH);
        }
        else
        {
            BTLPMDBG("%s CTS is HIGH no need to set BT WAKE." ,__func__);
            pthread_mutex_unlock(&cts_state_mutex);
        }
    }
}

/*******************************************************************************
**
** Function        lpm_allow_bt_device_sleep
**
** Description     This function is called when there is no hci traffic. As in:
**                  1. No ACL data traffics
**                  2. No HCI cmd traffic
**                  3. No space in controller (flow stop)
**                  Action: Will low bt_wake_up line.
**                  cond: NO_TX_ACL_DATA: if no acl data is present
**                        NO_TX_HCI_CMD : if no hci command is prensent
**
** Returns         None
**
*******************************************************************************/
void lpm_allow_bt_device_sleep(void)
{
    BTLPMDBG("%s", __func__);
    if ((bt_lpm_cb.state == LPM_ENABLED))
        lpm_set_bt_wake_state(LOW);
}

/*******************************************************************************
**
** Function         lpm_wake_deassert
**
** Description      This function is called when idle timer is timed out. From
**                  the idle timeout function this function is called.
**                  If the previous state is D0I2 change it to D0I2.
**
** Returns          None
**
*******************************************************************************/
void lpm_wake_deassert(void)
{
    pthread_mutex_lock(&bt_wake_mutex);
    if (bt_lpm_cb.bt_wake_state) {
        pthread_mutex_unlock(&bt_wake_mutex);
        return;
    }
    pthread_mutex_unlock(&bt_wake_mutex);

    pthread_mutex_lock(&host_wake_mutex);
    if (bt_lpm_cb.host_wake_state) {
        pthread_mutex_unlock(&host_wake_mutex);
        return;
    }
    pthread_mutex_unlock(&host_wake_mutex);

    // FIXME: Profile latency requirement is not considered for now.
    //if (bt_lpm_cb.min_profile_latency > bt_lpm_cb.D0I3_wake_time)
    if (lpm_set_device_state(ANY, D0I3) != 0)
    {
        BTLPMDBG("D0I3 is not possible now.");
        /* Restart idle timer now */
        pthread_mutex_lock(&start_transport_idle_timer_mutex);
        if (bt_lpm_cb.start_transport_idle_timer == \
                                        START_TRANSPORT_IDLE_TIMER)
        {
            BTLPMDBG("%s start transport_idle_timer", __func__);
            lpm_start_transport_idle_timer();
        }
        pthread_mutex_unlock(&start_transport_idle_timer_mutex);
    }
    else
    {
        /* In D0I3, Stop the packet rate timer */
        lpm_periodic_pkt_rate_stop_timer();
    }
}

/*******************************************************************************
**
** Function         lpm_set_device_state
**
** Description      Sets device state to the state passed
**
** Returns          None
**
*******************************************************************************/
int lpm_set_device_state(uint8_t source_state, uint8_t next_state)
{
    uint8_t intermediate_state = 0;
    int retval = 0;

    if (bt_lpm_cb.state != LPM_ENABLED || (!bt_vnd_if)) {
        BTLPMDBG("%s LPM is not enabled!", __func__);
        return -1;
    }

    pthread_mutex_lock(&device_state_mutex);

    /* Sanity checks */

    if (bt_lpm_cb.device_state == next_state) {
        retval = -1;
        goto done;
    }

    if (source_state != ANY && source_state != bt_lpm_cb.device_state) {
        retval = -1;
        goto done;
    }

    /* Feasibility checks */

    switch (next_state) {
    case D0:
        break;
    case D0I2:
        if (bt_lpm_cb.device_state != D0) {
            BTLPMDBG("%s Cannot go to D0I2 from %d!", __func__, bt_lpm_cb.device_state);
            retval = -1;
        }
        break;
    case D0I3:
        if (bt_lpm_cb.device_state == D3) {
            BTLPMDBG("%s Cannot go to D0I3 from %d!", __func__, bt_lpm_cb.device_state);
            retval = -1;
        }
        break;
    case D3:
        break;
    default:
        BTLPMDBG("%s Invalid state %d!", __func__, next_state);
        retval = -1;
    }

    /* Special handling for D0 > D0I3 transition */
    if (next_state == D0I3 && bt_lpm_cb.device_state == D0) {
        intermediate_state = 1;
        next_state = D0I2;
    }

again:
    if (retval == -1)
        goto done;

    BTLPMDBG("%s PREV STATE:%d", __func__, bt_lpm_cb.device_state);
    if ((retval = bt_vnd_if->op(BT_VND_OP_LPM_SET_DEVICE_STATE, &next_state)) == 0) {
        bt_lpm_cb.device_state = next_state;
        BTLPMDBG("%s NEXT STATE:%d", __func__, bt_lpm_cb.device_state);
    }
    else
        BTLPMDBG("%s State transition into %d failed!", __func__, next_state);

    if (intermediate_state) {
        intermediate_state = 0;
        next_state = D0I3;
        goto again;
    }

done:
    pthread_mutex_unlock(&device_state_mutex);
    return retval;
}

/*******************************************************************************
**
** Function         lpm_set_bt_wake_state
**
** Description      handles host wake signal.
**                  1. notifies vendor lib about the bt wake state change
**                  2. if required start transport idle timer
**
** Returns          None
**
*******************************************************************************/
void lpm_set_bt_wake_state(uint8_t state)
{
    pthread_mutex_lock(&bt_wake_mutex);
    if ((bt_lpm_cb.state == LPM_ENABLED))
    {
        if (bt_lpm_cb.bt_wake_state != state)
        {
            /* Set BT WKAE state and store CTS state */
            pthread_mutex_lock(&cts_state_mutex);
            //BTLPMDBG("%s Calling vendor to set state:%d", __func__, state);
            bt_lpm_cb.cts_state = \
                        bt_vnd_if->op(BT_VND_OP_LPM_SET_BT_WAKE_STATE, &state);
            if (bt_lpm_cb.cts_state != state)
            {
                /* This should never happen. If happens see BTIF driver. */
                ALOGE("[ERROR]: SET BT WAKE UP NOT POSSIBLE.");
                pthread_mutex_unlock(&cts_state_mutex);
                pthread_mutex_unlock(&bt_wake_mutex);
                return;

            }
            bt_lpm_cb.bt_wake_state = state;
            pthread_mutex_unlock(&cts_state_mutex);
        }
        pthread_mutex_lock(&start_transport_idle_timer_mutex);
        if (state == LOW)
        {
            bt_lpm_cb.start_transport_idle_timer |= \
                            START_TRANSPORT_IDLE_TIMER_BT_WAKE;
            /* Decide if transport_idle timer has to be started */
            if (bt_lpm_cb.start_transport_idle_timer == \
                                        START_TRANSPORT_IDLE_TIMER)
            {
                BTLPMDBG("%s start transport_idle_timer", __func__);
                lpm_start_transport_idle_timer();
            }
        }
        else
        {
            BTLPMDBG("%s stop transport_idle_timer", __func__);
            bt_lpm_cb.start_transport_idle_timer &= \
                                    ~START_TRANSPORT_IDLE_TIMER_BT_WAKE;
            /* Data to send. Stop transport idle timer */
            lpm_stop_transport_idle_timer();
        }
        pthread_mutex_unlock(&start_transport_idle_timer_mutex);
    }
    pthread_mutex_unlock(&bt_wake_mutex);
}
/*******************************************************************************
**
** Function         lpm_host_wake_handler
**
** Description      handles host wake signal.
**                  1. Stores the host wake state.
**                  2. Starts transport idle timer if required.
**                  3. send out RTS.
**
** Returns          None
**
*******************************************************************************/
void lpm_host_wake_handler(uint8_t state)
{
    pthread_mutex_lock(&host_wake_mutex);
    if (bt_lpm_cb.host_wake_state == state)
    {
        pthread_mutex_unlock(&host_wake_mutex);
        return; /* Redundent notify. Should never happen */
    }

    if ((bt_lpm_cb.state == LPM_ENABLED))
    {
        bt_lpm_cb.host_wake_state = state;
        pthread_mutex_lock(&start_transport_idle_timer_mutex);
        if (state == LOW)
        {
            BTLPMDBG("%s got host_wakeup LOW", __func__);
            /* Host wake low. check bt wake and if low start idle timer */
            bt_lpm_cb.start_transport_idle_timer |= \
                            START_TRANSPORT_IDLE_TIMER_HOST_WAKE;
            /* Decide if transport_idle timer has to be started */
            if (bt_lpm_cb.start_transport_idle_timer == \
                                        START_TRANSPORT_IDLE_TIMER)
            {
                lpm_start_transport_idle_timer();
            }
        }
        else
        {
            BTLPMDBG("%s got host_wakeup HIGH", __func__);
            bt_lpm_cb.start_transport_idle_timer &= \
                                    ~START_TRANSPORT_IDLE_TIMER_HOST_WAKE;
            /* Data to receive. Stop transport idle timer */
            lpm_stop_transport_idle_timer();
        }
        pthread_mutex_unlock(&start_transport_idle_timer_mutex);
        /* Change device state to D0I3 -> D0 */
        if (state == HIGH) {
            if (!lpm_set_device_state(D0I3, D0)) {
                /* Start the packet rate timer */
                lpm_periodic_pkt_rate_start_timer();
            }
        }
        /* Send RTS to ack host wake receive */
        if (bt_vnd_if)
        {
            bt_vnd_if->op(BT_VND_OP_LPM_SET_RTS_STATE, &state);
        }
    }
    pthread_mutex_unlock(&host_wake_mutex);
}

