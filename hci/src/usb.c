/******************************************************************************
 *
 *  Copyright (C) 2009-2012 Broadcom Corporation
 *  Portions of file: Copyright (C) 2013, Intel Corporation
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
 *  Filename:      usb.c
 *
 *  Description:   Contains open/read/write/close functions on usb
 *
 ******************************************************************************/

#define LOG_TAG "bt_usb"

#include <utils/Log.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include "bt_hci_bdroid.h"
#include "usb.h"
#include "utils.h"
#include "bt_vendor_lib.h"
#include <sys/prctl.h>
#include "libusb/libusb.h"

/******************************************************************************
**  Constants & Macros
******************************************************************************/

#ifndef USB_DBG
#define USB_DBG FALSE
#endif

#define USBERR ALOGE

#if (USB_DBG == TRUE)
#define USBDBG ALOGD
#else
#define USBDBG
#endif

/*
 * Bit masks : To check the transfer status
 */
#define XMITTED                 1
#define RX_DEAD                 2
#define RX_FAILED               4
#define XMIT_FAILED             8

/*
 * Field index values
 */
#define EV_LEN_FIELD        1
#define BLK_LEN_LO          2
#define BLK_LEN_HI          3
#define SCO_LEN_FIELD       2

#define BT_CTRL_EP      0x0
#define BT_INT_EP       0x81
#define BT_BULK_IN      0x82
#define BT_BULK_OUT     0x02
#define BT_ISO_IN       0x83
#define BT_ISO_OUT      0x03


#define BT_HCI_MAX_FRAME_SIZE      1028
#define ALTERNATE_SETTING 2
#define USB_SCO_INTERFACE 1
#define BT_MAX_ISO_FRAMES   3
#define SCO_PACKET_SIZE 48
#define BT_MAX_SCO_CONN 1
#define H4_TYPE_COMMAND         1
#define H4_TYPE_ACL_DATA        2
#define H4_TYPE_SCO_DATA        3
#define H4_TYPE_EVENT           4

#define MEMALLOC_WAIT 1000 //in milli sec
#define MEMALLOC_RETRY_COUNT 10
#define TRANS_SUMBIT_COUNT 30
#define TRANS_SUBMIT_WAIT 200 //in milli sec
#define INVALID_INDEX -1
#define NO_RX_SUBMITS 3
/*
 * USB types, the second of three bRequestType fields
 */
#define USB_TYPE_REQ                 32

/* Preamble length for HCI Commands:
**      2-bytes for opcode and 1 byte for length
*/
#define HCI_CMD_PREAMBLE_SIZE   3

/* Preamble length for HCI Events:
**      1-byte for opcode and 1 byte for length
*/
#define HCI_EVT_PREAMBLE_SIZE   2

/* Preamble length for SCO Data:
**      2-byte for Handle and 1 byte for length
*/
#define HCI_SCO_PREAMBLE_SIZE   3

/* Preamble length for ACL Data:
**      2-byte for Handle and 2 byte for length
*/
#define HCI_ACL_PREAMBLE_SIZE   4
#define RX_NEW_PKT              1
#define RECEIVING_PKT           2

#define CONTAINER_RX_HDR(ptr) \
      (RX_HDR *)((char *)(ptr) - offsetof(RX_HDR, data))

#define CONTAINER_ISO_HDR(ptr) \
      (ISO_HDR *)((char *)(ptr) - offsetof(ISO_HDR, data))

#define CONTAINER_CMD_HDR(ptr) \
      (CMD_HDR *)((char *)(ptr) - offsetof(CMD_HDR, data))

/******************************************************************************
**  Local type definitions
******************************************************************************/
/*
The mutex is protecting send_rx_event and rxed_xfer.

rxed_xfer     : Accounting the packet received at recv_xfer_cb() and processed
                at usb_read().
send_rx_event : usb_read() signals recv_xfer_cb() to signal  the
                Host/Controller lib thread about new packet arrival.

usb_read() belongs to Host/Controller lib thread.
recv_xfer_cb() belongs to USB read thread
*/

typedef struct
{
    libusb_device_handle      *handle;
    pthread_t                 read_thread;
    pthread_mutex_t           mutex;
    pthread_cond_t            cond;
    int                       rxed_xfer;
    uint8_t                   send_rx_event;
    BUFFER_Q                  rx_eventq;
    BUFFER_Q                  rx_bulkq;
    BUFFER_Q                  rx_isoq;
    int16_t                   rx_pkt_len;
    uint8_t                   rx_status;
    int                       iso_frame_ndx;
    struct libusb_transfer    *failed_tx_xfer;
} tUSB_CB;

/******************************************************************************
**  Static variables
******************************************************************************/
/* The list will grow and will be updated from btusb.c in kernel */
typedef enum
{
    ISO_STOPPED,
    ISO_STARTED
}tISO_STATE;

static struct bt_usb_device btusb_table[] =
{
    /* Generic Bluetooth USB device */
    { BT_USB_DEVICE_INFO(0xe0, 0x01, 0x01) },
    { }     /* Terminating entry */
};

typedef struct
{
    uint16_t          event;
    uint16_t          len;
    uint16_t          offset;
    unsigned char     data[0];
} RX_HDR;

struct iso_frames
{
    int               actual_length;
    int               length;
};

typedef struct
{
    uint16_t           event;
    uint16_t           len;
    uint16_t           offset;
    struct iso_frames  frames[BT_MAX_ISO_FRAMES];
    unsigned char      data[0];
} ISO_HDR;

typedef struct
{
    uint8_t                     event;
    struct libusb_control_setup setup;
    unsigned char               data[0];
} CMD_HDR;

static tUSB_CB usb;
static int usb_xfer_status, usb_running;
static int intr_pkt_size, iso_pkt_size, bulk_pkt_size;
static int intr_pkt_size_wh, iso_pkt_size_wh, bulk_pkt_size_wh;
static struct libusb_transfer *data_rx_xfer, *event_rx_xfer, *xmit_transfer, *iso_rx_xfer[NO_RX_SUBMITS];
static int xmited_len;
RX_HDR *p_rx_hdr = NULL;
static tISO_STATE iso_state=ISO_STOPPED;
static ISO_HDR *cur_iso_pkt[BT_MAX_SCO_CONN];
static int cur_iso_pkt_idx[BT_MAX_SCO_CONN];
static uint16_t sco_handle_db[BT_MAX_SCO_CONN];
static int sco_handle_idx = 0;
static int prev_sco_db_index = -1;
static int cur_sco_db_index = 0;
static int cancelled_packets = 0;
/******************************************************************************
**  Static functions
******************************************************************************/
static int check_sco_handle_validity(uint16_t sco_handle);
static int add_frame_to_cur_packet(uint8_t *buffer, int cur_pkt_idx);
static void init_sco_db();
static void cancel_transfer(void);
static void submit_transfer(void);
static int delete_sco_conn(uint16_t sco_handle);
static int add_sco_conn(uint16_t sco_handle);
static void close_sco_db();
static void flush_prev_packet(int cur_pkt_idx);

static int is_usb_match_idtable (struct bt_usb_device *id, struct libusb_device_descriptor *desc)
{
    int ret = TRUE;

    ret = ((id->bDevClass != libusb_le16_to_cpu(desc->bDeviceClass)) ? FALSE :
           (id->bDevSubClass != libusb_le16_to_cpu(desc->bDeviceSubClass)) ? FALSE :
           (id->bDevProtocol != libusb_le16_to_cpu(desc->bDeviceProtocol)) ? FALSE : TRUE);

    return ret;
}

static int check_bt_usb_endpoints (struct bt_usb_device *id, struct libusb_config_descriptor *cfg_desc)
{
    const struct libusb_interface_descriptor *idesc;
    const struct libusb_endpoint_descriptor *endpoint;
    int i, num_altsetting;

    endpoint =  cfg_desc->interface[0].altsetting[0].endpoint;
    for(i = 0; i < cfg_desc->interface[0].altsetting[0].bNumEndpoints; i++)
    {
        if(!(endpoint[i].bEndpointAddress == BT_CTRL_EP || \
                endpoint[i].bEndpointAddress == BT_INT_EP || \
                endpoint[i].bEndpointAddress == BT_BULK_IN || \
                endpoint[i].bEndpointAddress == BT_BULK_OUT))
            return FALSE;
    }

/*
    we are using 8khz 16 bits samples for sco, so bluetooth recommended the alternate setting 2 for the same
*/
    num_altsetting =  cfg_desc->interface[1].num_altsetting;
    endpoint =  cfg_desc->interface[1].altsetting[ALTERNATE_SETTING].endpoint;
    for(i = 0; i < cfg_desc->interface[1].altsetting[ALTERNATE_SETTING]. \
            bNumEndpoints; i++)
    {
        if(!(endpoint[i].bEndpointAddress == BT_ISO_IN || \
                endpoint[i].bEndpointAddress == BT_ISO_OUT))
            return FALSE;
    }
    for(i = 0; i < cfg_desc->interface[1]. \
            altsetting[ALTERNATE_SETTING].bNumEndpoints; i++)
    {
        if(endpoint[i].bEndpointAddress == BT_ISO_IN)
        {
            iso_pkt_size =  libusb_le16_to_cpu(endpoint[i].wMaxPacketSize);
            USBDBG("iso pkt size is %d", iso_pkt_size);
            iso_pkt_size_wh = iso_pkt_size * BT_MAX_ISO_FRAMES + \
                              sizeof(ISO_HDR);
            USBDBG("iso pkt size wh %d", iso_pkt_size_wh);
        }
    }
    return TRUE;
}

static int is_btusb_device (struct libusb_device *dev)
{
    struct bt_usb_device *id;
    struct libusb_device_descriptor desc;
    struct libusb_config_descriptor *cfg_desc;
    int    r, match, num_altsetting = 0;

    r = libusb_get_device_descriptor(dev, &desc);
    if (r < 0)
        return FALSE;

    match = 0;

    for (id = btusb_table; id->bDevClass; id++)
    {
        if (is_usb_match_idtable (id, &desc) == TRUE)
        {
            match = 1;
            break;
        }
    }

    if (!match)
    {
        return FALSE;
    }

    r = libusb_get_config_descriptor(dev, 0, &cfg_desc);
    if (r < 0)
    {
        USBERR("libusb_get_config_descriptor  %x:%x failed ....%d\n", \
               desc.idVendor, desc.idProduct, r);
        return FALSE;
    }

    r = check_bt_usb_endpoints(id, cfg_desc);
    libusb_free_config_descriptor(cfg_desc);

    return r;
}

/*******************************************************************************
**
** Function        libusb_open_bt_device
**
** Description     Scan the system USB devices. If match is found on
**                 btusb_table ensure that  it is a bluetooth device by
**                 checking Interface endpoint addresses.
**
** Returns         NULL: termination
**                 !NULL : pointer to the libusb_device_handle
**
*******************************************************************************/
static libusb_device_handle *libusb_open_bt_device()
{
    struct libusb_device **devs;
    struct libusb_device *found = NULL;
    struct libusb_device *dev;
    struct libusb_device_handle *handle = NULL;
    int    r, i;

    if (libusb_get_device_list(NULL, &devs) < 0)
    {
        return NULL;
    }
    for (i = 0; (dev = devs[i]) != NULL; i++)
    {
        if (is_btusb_device (dev) == TRUE)
            break;
    }
    if (dev)
    {
        r = libusb_open(dev, &handle);
        if (r < 0)
        {
            USBERR("found USB BT device failed to open .....\n");
            return NULL;
        }
    }
    else
    {
        USBERR("No matching USB BT device found .....\n");
        return NULL;
    }

    libusb_free_device_list(devs, 1);
    r = libusb_claim_interface(handle, 0);
    if (r < 0)
    {
        USBERR("usb_claim_interface 0 error %d\n", r);
        return NULL;
    }

    intr_pkt_size = libusb_get_max_packet_size(dev, BT_INT_EP);
    USBDBG("Interrupt pkt size is %d", intr_pkt_size);
    intr_pkt_size_wh =  intr_pkt_size + sizeof(RX_HDR);
    init_sco_db();
    return handle;
}

static void usb_rx_signal_event()
{
    pthread_mutex_lock(&usb.mutex);
    usb.rxed_xfer++;
    pthread_cond_signal(&usb.cond);
    if (usb.send_rx_event == TRUE)
    {
        bthc_signal_event(HC_EVENT_RX);
        usb.send_rx_event = FALSE;
    }

    pthread_mutex_unlock(&usb.mutex);
}

static void recv_xfer_cb(struct libusb_transfer *transfer)
{
    RX_HDR *p_rx = NULL;
    int r, skip = 0;
    int iso_actual_length=0;
    enum libusb_transfer_status status;
    int xx;
    uint8_t *buffer = NULL;
    uint16_t sco_handle = 0;
    int sco_pkt_length = 0;

    status = transfer->status;
    switch (status)
    {
        case LIBUSB_TRANSFER_CANCELLED:
            USBDBG("Libusb Transfer Cancelled");
            if (transfer->endpoint == BT_ISO_IN)
            {
                USBDBG("Freeing transfer");
                free(transfer->buffer);
                libusb_free_transfer(transfer);
                cancelled_packets++;
                if (cancelled_packets == NO_RX_SUBMITS)
                {
                    cancelled_packets = 0;
                    r=libusb_set_interface_alt_setting(usb.handle, USB_SCO_INTERFACE, 0);
                    if (r != LIBUSB_SUCCESS)
                    {
                        USBERR("%s : Unable to set the alternate to %d. Error %d", __func__, 0, r);
                    }
                    r = libusb_release_interface(usb.handle, USB_SCO_INTERFACE);
                    if (r != LIBUSB_SUCCESS)
                    {
                        USBERR("%s : Unable to release the %d interface", __func__, USB_SCO_INTERFACE);
                    }
                }
                return;
            }
            break;
        case LIBUSB_TRANSFER_COMPLETED:
            USBDBG("Libusb Transfer Completed Successfully");
            switch (transfer->endpoint)
            {
                struct iso_frames *frames;
                case BT_INT_EP:
                    if (transfer->actual_length == 0)
                    {
                        USBDBG("*****Rxed zero length packet from usb ....");
                        skip = 1;
                        break;
                    }
                    p_rx = CONTAINER_RX_HDR(transfer->buffer);
                    p_rx->event = H4_TYPE_EVENT;
                    p_rx->len = (uint16_t)transfer->actual_length;
                    utils_enqueue(&(usb.rx_eventq), p_rx);
                    p_rx =  (RX_HDR *) bt_hc_cbacks->alloc(intr_pkt_size_wh);
                    transfer->buffer = p_rx->data;
                    transfer->length = intr_pkt_size;
                    break;

                case BT_BULK_IN:
                    if (transfer->actual_length == 0)
                    {
                        USBERR("*******Rxed zero length packet from usb ....");
                        skip = 1;
                        break;
                    }
                    p_rx = CONTAINER_RX_HDR(transfer->buffer);
                    p_rx->event = H4_TYPE_ACL_DATA;
                    p_rx->len = (uint16_t)transfer->actual_length;
                    utils_enqueue(&(usb.rx_bulkq), p_rx);
                    p_rx =  (RX_HDR *) bt_hc_cbacks->alloc(bulk_pkt_size_wh);
                    transfer->buffer = p_rx->data;
                    transfer->length = bulk_pkt_size;
                    break;

                case BT_ISO_IN:
                    iso_actual_length = 0;
                    for (xx = 0; xx<transfer->num_iso_packets; xx++)
                    {
                        iso_actual_length += transfer->iso_packet_desc[xx].actual_length;
                    }
                    skip = 1;
                    if (iso_actual_length != 51)
                    {
                        USBERR("*******Rxed Non-proper length packet from usb ....");
                        USBDBG("Length of packet received = %d", iso_actual_length);
                        break;
                    }
                    USBDBG("Packet Received : Actual length = %d", iso_actual_length);
                    buffer = transfer->buffer;
                    for (xx = 0; xx < BT_MAX_ISO_FRAMES; xx++)
                    {
                        sco_handle = (buffer[1]<<(8)) + buffer[0];
                        USBDBG("Sco Handle of frame %d is %d", xx, sco_handle);
                        sco_pkt_length = buffer[2];
                        USBDBG("Sco Packet Length = %d", sco_pkt_length);
                        cur_sco_db_index = check_sco_handle_validity(sco_handle);
                        if (cur_sco_db_index < 0 )
                        {
                            if (prev_sco_db_index == INVALID_INDEX)
                            {
                                buffer = buffer + iso_pkt_size;
                                continue;
                            }
                            if (add_frame_to_cur_packet(buffer, prev_sco_db_index))
                            {
                                utils_enqueue(&(usb.rx_isoq), cur_iso_pkt[prev_sco_db_index]);
                                USBDBG("Enqued iso packet with correct event");
                                cur_iso_pkt[prev_sco_db_index] = (ISO_HDR *) bt_hc_cbacks->alloc(iso_pkt_size_wh);
                                flush_prev_packet(prev_sco_db_index);
                                prev_sco_db_index = INVALID_INDEX;
                                skip = 0;
                            }
                        }
                        else
                        {
                            if (sco_pkt_length == SCO_PACKET_SIZE)
                            {
                                flush_prev_packet(cur_sco_db_index);
                                prev_sco_db_index = cur_sco_db_index;
                                if (add_frame_to_cur_packet(buffer, cur_sco_db_index))
                                {
                                    utils_enqueue(&(usb.rx_isoq), cur_iso_pkt[cur_sco_db_index]);
                                    USBDBG("Enqued iso packet with correct event");
                                    cur_iso_pkt[cur_sco_db_index] = (ISO_HDR *) bt_hc_cbacks->alloc(iso_pkt_size_wh);
                                    skip = 0;
                                }
                            }
                            else
                            {
                                USBERR("Sco Packet size not proper. Size is %d", sco_pkt_length);
                            }
                        }
                        buffer = buffer + iso_pkt_size;
                    }
                    break;
            default:
                USBERR("Unexpeted endpoint rx %d\n", transfer->endpoint);
                break;
            }
            if (!skip)
                usb_rx_signal_event();
            break;
        case LIBUSB_TRANSFER_ERROR:
            USBERR("Libusb Transfer: IO Error, restarting BT");
            kill(getpid(), SIGKILL);
            break;
        case LIBUSB_TRANSFER_TIMED_OUT:
            USBERR("Libusb Transfer: Timed Out");
            break;
        case LIBUSB_TRANSFER_STALL:
            USBERR("Libusb Transfer: Stalled");
            break;
        case LIBUSB_TRANSFER_NO_DEVICE:
            USBERR("Libusb Transfer: Device Disconnected");
            break;
        case LIBUSB_TRANSFER_OVERFLOW:
            USBERR("Libusb Transfer: Overflow");
            break;
        default :
            USBERR("Libusb Transfer: Unknown Error, restarting BT");
            kill(getpid(), SIGKILL);
            break;
    }
    r = libusb_submit_transfer(transfer);
    if (r < 0)
    {
        if (transfer->endpoint == BT_ISO_IN)
        {
           free(transfer->buffer);
        }
        else
        {
            p_rx = CONTAINER_RX_HDR(transfer->buffer);
        }
        bt_hc_cbacks->dealloc((TRANSAC)p_rx, (char *)(p_rx + 1));
        transfer->buffer = NULL;
        USBERR("libusb_submit_transfer : %d : %d : failed", \
               transfer->endpoint, transfer->status);
        usb_xfer_status |= RX_FAILED;
    }
}

void handle_usb_events ()
{
    RX_HDR  *rx_buf;
    unsigned char *iso_buf = NULL;
    int  r, xx, yy, iso_xfer;
    struct libusb_transfer *transfer;
    struct timeval timeout = { 1, 0 };

    usb_xfer_status &= ~RX_DEAD;
    while (!(usb_xfer_status & RX_DEAD))
    {
        // This polling introduces two problems:
        //  1) /1s device wakeups when BT is on
        //  2) ~0.5s response to user's shutdown request
        libusb_handle_events_timeout(0, &timeout);
        transfer = NULL;
        iso_xfer = 0;
        if (usb_xfer_status & RX_FAILED)
        {
            if (data_rx_xfer->buffer == NULL)
            {
                transfer = data_rx_xfer;
                rx_buf = (RX_HDR *) bt_hc_cbacks->alloc(bulk_pkt_size_wh);
                if (rx_buf == NULL)
                {
                    USBERR("%s : Allocation failed", __FUNCTION__);
                    transfer = NULL;
                }
                else
                {
                    transfer->buffer = rx_buf->data;
                    transfer->length = bulk_pkt_size;
                }
            }
            else if (event_rx_xfer->buffer == NULL)
            {
                transfer = event_rx_xfer;
                rx_buf = (RX_HDR *) bt_hc_cbacks->alloc(intr_pkt_size_wh);
                if (rx_buf == NULL)
                {
                    USBERR("%s : Allocation failed", __FUNCTION__);
                    transfer = NULL;
                }
                else
                {
                    transfer->buffer = rx_buf->data;
                    transfer->length = intr_pkt_size;
                }
            }
            else
            {
                for (xx = 0; xx < NO_RX_SUBMITS; xx++)
                {
                    if (iso_rx_xfer[xx]->buffer == NULL)
                    {
                        transfer = iso_rx_xfer[xx];
                        iso_buf = (unsigned char*) malloc(iso_pkt_size*BT_MAX_ISO_FRAMES);
                        if (iso_buf == NULL)
                        {
                            USBERR("%s : Allocation failed", __FUNCTION__);
                            transfer = NULL;
                        }
                        else
                        {
                            transfer->buffer = iso_buf;
                            transfer->length = BT_MAX_ISO_FRAMES * iso_pkt_size;
                            for(yy = 0; yy < transfer->num_iso_packets; yy++)
                            {
                                transfer->iso_packet_desc[yy].length = iso_pkt_size;
                            }
                            iso_xfer = 1;
                        }
                    }

                }
            }
            if (transfer != NULL)
            {
                usb_xfer_status &= ~(RX_FAILED);
                r = libusb_submit_transfer(transfer);
                if (r < 0)
                {
                    USBERR("libusb_submit_transfer : data_rx_xfer failed");
                    if (iso_xfer)
                    {
                        free(iso_buf);
                    }
                    else
                    {
                        bt_hc_cbacks->dealloc((TRANSAC) rx_buf, \
                                              (char *)(rx_buf + 1));
                    }
                    transfer->buffer = NULL;
                }
            }
        }
        else if (usb_xfer_status & XMIT_FAILED)
        {
            transfer = usb.failed_tx_xfer;
            USBDBG("Retransmitting xmit packet %d", \
                   *(transfer->buffer - 1));
            xmited_len = transfer->length;
            usb_xfer_status &= ~(XMIT_FAILED);
            if (libusb_submit_transfer(transfer) < 0)
            {
                USBERR("libusb_submit_transfer : %d : failed", \
                       *(transfer->buffer - 1));
            }
        }
    }
    usb_running = 0;
}

/*******************************************************************************
**
** Function        usb_read_thread
**
** Description
**
** Returns         void *
**
*******************************************************************************/
static void *usb_read_thread(void *arg)
{
    RX_HDR  *rx_buf;

    int size, size_wh, r, i, iso_xfer;
    struct libusb_transfer *transfer;
    unsigned char *buf;

    USBDBG("Entering usb_read_thread()");
    prctl(PR_SET_NAME, (unsigned long)"usb_read", 0, 0, 0);


    rx_buf = (RX_HDR *) bt_hc_cbacks->alloc(bulk_pkt_size_wh);
    buf =  rx_buf->data;
    libusb_fill_bulk_transfer(data_rx_xfer, usb.handle, BT_BULK_IN, \
                              buf, bulk_pkt_size, recv_xfer_cb, NULL, 0);
    r = libusb_submit_transfer(data_rx_xfer);
    if (r < 0)
    {
        USBERR("libusb_submit_transfer : data_rx_xfer : failed");
        goto out;
    }

    rx_buf = (RX_HDR *) bt_hc_cbacks->alloc(intr_pkt_size_wh);
    buf = rx_buf->data;
    libusb_fill_interrupt_transfer(event_rx_xfer, usb.handle, BT_INT_EP, \
                                   buf, intr_pkt_size, recv_xfer_cb, NULL, 0);
    r = libusb_submit_transfer(event_rx_xfer);
    if (r < 0)
    {
        USBERR("libusb_submit_transfer : event_rx_xfer : failed");
        goto out;
    }
    usb_running = 1;
    handle_usb_events();
out:
    USBDBG("Leaving usb_read_thread()");
    if (data_rx_xfer != NULL)
    {
        rx_buf = CONTAINER_RX_HDR(data_rx_xfer->buffer);
        bt_hc_cbacks->dealloc((TRANSAC) rx_buf, (char *)(rx_buf+1));
        libusb_free_transfer(data_rx_xfer);
    }
    if (event_rx_xfer != NULL)
    {
        rx_buf = CONTAINER_RX_HDR(event_rx_xfer->buffer);
        bt_hc_cbacks->dealloc((TRANSAC) rx_buf, (char *)(rx_buf+1));
        libusb_free_transfer(event_rx_xfer);
    }

    pthread_exit(NULL);

    return NULL;
}


/*****************************************************************************
**   USB API Functions
*****************************************************************************/

/*******************************************************************************
**
** Function        usb_init
**
** Description     Initializes the serial driver for usb
**
** Returns         TRUE/FALSE
**
*******************************************************************************/
uint8_t usb_init(void)
{
    USBDBG("usb_init");
    int xx;
    memset(&usb, 0, sizeof(tUSB_CB));
    usb.handle = NULL;
    utils_queue_init(&(usb.rx_eventq));
    utils_queue_init(&(usb.rx_bulkq));
    utils_queue_init(&(usb.rx_isoq));
    pthread_mutex_init(&usb.mutex, NULL);
    pthread_cond_init(&usb.cond, NULL);
    data_rx_xfer = event_rx_xfer = NULL;
    memset(iso_rx_xfer, 0, (sizeof(iso_rx_xfer[0]) * NO_RX_SUBMITS));
    usb.send_rx_event = TRUE;
    usb.rx_status = RX_NEW_PKT;

    return TRUE;
}


/*******************************************************************************
**
** Function        usb_open
**
** Description     Open Bluetooth device with the port ID
**
** Returns         TRUE/FALSE
**
*******************************************************************************/
uint8_t usb_open(uint8_t port)
{

    USBDBG("usb_open(port:%d)", port);
    int r, xx;
    if (usb_running)
    {
        /* Userial is open; close it first */
        usb_close();
        utils_delay(50);
    }
    if (libusb_init(NULL) < 0)
    {
        USBERR("libusb_init : failed");
        return FALSE;
    }

    usb.handle = libusb_open_bt_device();
    bulk_pkt_size_wh = BT_HCI_MAX_FRAME_SIZE + sizeof(RX_HDR);
    bulk_pkt_size = BT_HCI_MAX_FRAME_SIZE;
    if (usb.handle == NULL)
    {
        USBERR("usb_open: HCI USB failed to open");
        goto out;
    }
    data_rx_xfer = libusb_alloc_transfer(0);
    if (!data_rx_xfer)
    {
        USBERR("Failed alloc data_rx_xfer");
        goto out;
    }

    event_rx_xfer  = libusb_alloc_transfer(0);
    if (!event_rx_xfer)
    {
        USBERR("Failed alloc event_rx_xfer");
        goto out;
    }

    USBDBG("usb_read_thread is created ....");
    if (pthread_create(&(usb.read_thread), NULL, \
                       usb_read_thread, NULL) != 0 )
    {
        USBERR("pthread_create failed!");
        goto out;
    }

    return TRUE;
out :
    if (usb.handle != NULL)
    {
        if (data_rx_xfer != NULL)
            libusb_free_transfer(data_rx_xfer);
        if (event_rx_xfer != NULL)
            libusb_free_transfer(event_rx_xfer);
        for( xx = 0; xx < NO_RX_SUBMITS; xx++)
            libusb_free_transfer(iso_rx_xfer[xx]);
        libusb_release_interface(usb.handle, 1);
        libusb_release_interface(usb.handle, 0);
        libusb_close(usb.handle);
        libusb_exit(NULL);
    }
    return FALSE;
}


/*******************************************************************************
**
** Function        usb_read
**
** Description     Read data from the usb port
**
** Returns         Number of bytes actually read from the usb port and
**                 copied into p_data.  This may be less than len.
**
*******************************************************************************/
uint16_t  usb_read(uint16_t msg_id, uint8_t *p_buffer, uint16_t len)
{
    uint16_t total_len = 0;
    uint16_t copy_len = 0;
    uint8_t *p_data = NULL, iso_idx;
    int iso_frame_len = 0;
    int different_xfer = 0;
    struct iso_frames *frames;
    int pkt_rxing = 0;
    int rem_len = 0;
    ISO_HDR *p_iso_hdr;
    int i;


    if (!usb_running)
        return 0;
    while (total_len < len)
    {
        if (p_rx_hdr == NULL)
        {

            pthread_mutex_lock(&usb.mutex);
            if (usb.rxed_xfer < 0)
            {
                USBERR("Rx thread and usb_read out of sync %d", \
                       usb.rxed_xfer);
                usb.rxed_xfer = 0;
            }
            if (usb.rxed_xfer == 0 && usb.rx_status == RX_NEW_PKT)
            {
                usb.send_rx_event = TRUE;
                pthread_mutex_unlock(&usb.mutex);
                USBDBG("usb_read nothing to rx....");
                return 0;

            }
            while (usb.rxed_xfer == 0)
            {
                pthread_cond_wait(&usb.cond, &usb.mutex);
            }
            usb.rxed_xfer--;
            pthread_mutex_unlock(&usb.mutex);

            if (usb.rx_status == RX_NEW_PKT)
            {

                p_rx_hdr = (RX_HDR *)utils_dequeue(&(usb.rx_eventq));
                if (p_rx_hdr == NULL)
                {
                    p_rx_hdr = (RX_HDR *)utils_dequeue(&(usb.rx_isoq));
                }
                if (p_rx_hdr == NULL)
                {
                    p_rx_hdr = (RX_HDR *)utils_dequeue(&(usb.rx_bulkq));
                }
                if (p_rx_hdr == NULL)
                {
                    USBERR("rxed_xfer is %d but no packet found", usb.rxed_xfer);
                    return 0;
                }
                switch (p_rx_hdr->event)
                {
                case H4_TYPE_EVENT:
                    p_data = p_rx_hdr->data;
                    p_rx_hdr->offset = 0;
                    usb.rx_pkt_len = p_data[EV_LEN_FIELD] + \
                                     HCI_EVT_PREAMBLE_SIZE;
                    usb.rx_status = RECEIVING_PKT;
                    *p_buffer = p_rx_hdr->event;
                    total_len += 1;
                    p_buffer++;
                    break;


                case H4_TYPE_SCO_DATA:
                    p_iso_hdr = (ISO_HDR *)p_rx_hdr;
                    p_iso_hdr->offset = 0;
                    usb.rx_pkt_len = p_iso_hdr->len;
                    *p_buffer = p_rx_hdr->event;
                    total_len += 1;
                    p_buffer++;
                    usb.rx_status = RECEIVING_PKT;
                    usb.iso_frame_ndx = 0;
                    break;


                case H4_TYPE_ACL_DATA:
                    p_data = p_rx_hdr->data;
                    p_rx_hdr->offset = 0;
                    usb.rx_pkt_len = ((uint16_t)p_data[BLK_LEN_LO] | \
                                      (uint16_t)p_data[BLK_LEN_HI] << 8) + \
                                     HCI_ACL_PREAMBLE_SIZE;
                    usb.rx_status = RECEIVING_PKT;
                    *p_buffer = p_rx_hdr->event;
                    total_len += 1;
                    p_buffer++;
                    break;
                }
                USBDBG("Received packet from usb of len %d of type %x", \
                       p_rx_hdr->len, p_rx_hdr->event);
            }
            else   // rx_status == RECIVING_PKT
            {
                switch (pkt_rxing)
                {
                case H4_TYPE_EVENT:
                    p_rx_hdr = (RX_HDR *)utils_dequeue(&(usb.rx_eventq));
                    break;

                case H4_TYPE_SCO_DATA:
                    p_rx_hdr = (RX_HDR *)utils_dequeue(&(usb.rx_isoq));
                    break;

                case H4_TYPE_ACL_DATA:
                    p_rx_hdr = (RX_HDR *)utils_dequeue(&(usb.rx_bulkq));
                    break;
                }
                if (p_rx_hdr == NULL)
                {
                    USBDBG("Rxed packet from different end_point.");
                    different_xfer++;
                }
                else
                {
                    p_rx_hdr->offset = 0;
                    USBDBG("Received packet from usb of len %d of type %x",
                           p_rx_hdr->len, p_rx_hdr->event);
                }
            }
        }
        else //if (p_rx_hdr != NULL)
        {
            if (p_rx_hdr->event  == H4_TYPE_SCO_DATA)
            {
                p_iso_hdr = (ISO_HDR *)p_rx_hdr;
                frames = p_iso_hdr->frames;
                p_data = p_iso_hdr->data + p_iso_hdr->offset;
                frames += usb.iso_frame_ndx;
                rem_len = usb.rx_pkt_len;
                if (usb.rx_pkt_len < (len-total_len))
                {
                    copy_len = usb.rx_pkt_len;
                }
                else
                {
                    copy_len = len - total_len;
                }
                rem_len = rem_len - copy_len;
                p_iso_hdr->offset += copy_len;
            }
            else
            {
                p_data = p_rx_hdr->data + p_rx_hdr->offset;
                pkt_rxing = p_rx_hdr->event;

                if ((p_rx_hdr->len) <= (len - total_len))
                    copy_len = p_rx_hdr->len;
                else
                    copy_len = (len - total_len);

                p_rx_hdr->offset += copy_len;
                p_rx_hdr->len -= copy_len;
                rem_len = p_rx_hdr->len;
            }

            memcpy((p_buffer + total_len), p_data, copy_len);
            total_len += copy_len;

            if (rem_len == 0)
            {
                bt_hc_cbacks->dealloc((TRANSAC) p_rx_hdr, (char *)(p_rx_hdr+1));
                p_rx_hdr = NULL;
            }
            usb.rx_pkt_len -= copy_len;
            if (usb.rx_pkt_len == 0)
            {
                usb.rx_status = RX_NEW_PKT;
                break;
            }
            if (usb.rx_pkt_len < 0)
            {
                USBERR("pkt len expected %d rxed len of %d", len, total_len);
                usb.rx_status = RX_NEW_PKT;
                break;
            }
        }
    }
    if (different_xfer)
    {
        pthread_mutex_lock(&usb.mutex);
        usb.rxed_xfer += different_xfer;
        pthread_mutex_unlock(&usb.mutex);
    }

    return total_len;
}
/*******************************************************************************
**
** Function        xmit_xfer_cb
**
** Description     Callback function after xmission
**
** Returns         None
**
**
*******************************************************************************/
static void xmit_xfer_cb(struct libusb_transfer *transfer)
{
    enum libusb_transfer_status status = transfer->status;
    static int xmit_acked;
    if (transfer->type == LIBUSB_TRANSFER_TYPE_ISOCHRONOUS)
    {
        if (transfer->status != LIBUSB_TRANSFER_COMPLETED)
        {
            USBERR("xfer did not succeeded .....%d", transfer->status);
        }
        if (transfer->buffer != NULL)
            free(transfer->buffer);
        libusb_free_transfer(transfer);
        return;
    }
    else
    {
         if (transfer->status != LIBUSB_TRANSFER_COMPLETED)
        {
            USBERR("xfer did not succeeded .....%d", transfer->status);
            usb_xfer_status |= XMIT_FAILED;
            usb.failed_tx_xfer = transfer;
            xmited_len = 0;
        }
        else
        {
            xmited_len = transfer->actual_length+1;
            libusb_free_transfer(transfer);
            usb_xfer_status  |= XMITTED;
            USBDBG("Xfer Succeded : count %d", ++xmit_acked);
        }
    }
}
/*******************************************************************************
**
** Function        usb_write
**
** Description     Write data to the usb port
**
** Returns         Number of bytes actually written to the usb port. This
**                 may be less than len.
**
*******************************************************************************/
uint16_t usb_write(uint16_t msg_id, uint8_t *p_data, uint16_t len)
{
    struct timeval tv = {60, 0};
    char buffer[512], pkt_type;
    uint8_t *sco_data = NULL;
    int x, i, r;
    long time;
    int count = 0;
    CMD_HDR *cmd_hdr;
    static int xmit_count;

    static int sco_count = 0;
    int retry_submit_count = 0;
    pkt_type = *p_data;
    if (pkt_type == H4_TYPE_SCO_DATA)
    {
        if (!(xmit_transfer = libusb_alloc_transfer(BT_MAX_ISO_FRAMES)))
        {
            USBERR( "libusb_alloc_tranfer() failed");
            return 0;
        }
    }
    else
    {
        if (!(xmit_transfer = libusb_alloc_transfer(0)))
        {
            USBERR( "libusb_alloc_tranfer() failed");
            return 0;
        }
    }
    x = (len > (sizeof(buffer)-1)/2)? ((sizeof(buffer)-1)/2) : len;
    switch(pkt_type)
    {
    case H4_TYPE_COMMAND:
        /* Make use of BT_HDR space to populate setup */
        cmd_hdr = CONTAINER_CMD_HDR(p_data + 1);
        cmd_hdr->setup.bmRequestType = USB_TYPE_REQ;
        cmd_hdr->setup.wLength = len - 1;
        cmd_hdr->setup.wIndex = 0;
        cmd_hdr->setup.wValue = 0;
        cmd_hdr->setup.bRequest = 0;
        cmd_hdr->event = H4_TYPE_COMMAND;
        libusb_fill_control_transfer(xmit_transfer, usb.handle,
                                     (uint8_t *)&cmd_hdr->setup, xmit_xfer_cb, NULL, 0);
        break;

    case H4_TYPE_ACL_DATA:
        libusb_fill_bulk_transfer(xmit_transfer, usb.handle,
                                  BT_BULK_OUT, (p_data+1), (len-1), xmit_xfer_cb, NULL, 0);
        break;

    case H4_TYPE_SCO_DATA:
       retry:
       sco_data = NULL;
       sco_data = (uint8_t*)malloc((len - 1) * sizeof(uint8_t));
       while (sco_data == NULL)
       {
           usleep(MEMALLOC_WAIT);
            sco_data = (uint8_t*)malloc((len - 1) * sizeof(uint8_t));
            count++;
            if (count > MEMALLOC_RETRY_COUNT)
            {
                USBERR("Mem alloc failed for sco packet tx");
                return 0;
            }
       }
        memcpy(sco_data, p_data+1, len-1);
        libusb_fill_iso_transfer(xmit_transfer, usb.handle, \
                                 BT_ISO_OUT, sco_data, (len-1), BT_MAX_ISO_FRAMES, \
                                 xmit_xfer_cb, NULL, 0);
        libusb_set_iso_packet_lengths(xmit_transfer, iso_pkt_size);
        sco_count++;
        break;

    default:
        USBERR("Unknown packet type to transmit %x", *p_data);
        return 0;
    }
    if (pkt_type == H4_TYPE_SCO_DATA)
    {
        if (iso_state == ISO_STOPPED)
        {
            free(xmit_transfer->buffer);
            libusb_free_transfer(xmit_transfer);
            return 0;
        }
    }

    usb_xfer_status &= ~(XMITTED);
    while ((r = libusb_submit_transfer(xmit_transfer)) < 0)
    {

        if (retry_submit_count > TRANS_SUMBIT_COUNT)
        {
            USBERR("libusb_submit_transfer failed with error %d", r);
            return 0;
        }
        retry_submit_count++;
        usleep(TRANS_SUBMIT_WAIT);
    }
    xmited_len = len;

    if (pkt_type == H4_TYPE_SCO_DATA)
    {
        return xmited_len;
    }

    while (!(usb_xfer_status & XMITTED))
        libusb_handle_events_timeout(0, &tv);

    return (xmited_len);
}

/*******************************************************************************
**
** Function        usb_close
**
** Description     Close the serial port
**
** Returns         None
**
*******************************************************************************/
void usb_close(void)
{
    int result;
    TRANSAC p_buf;
    USBDBG("usb_close \n");
    usb_xfer_status |= RX_DEAD;

    if ((result=pthread_join(usb.read_thread, NULL)) < 0)
        USBERR( "pthread_join() FAILED result:%d \n", result);

    if (usb.handle)
    {
        libusb_release_interface(usb.handle, 1);
        libusb_release_interface(usb.handle, 0);
        libusb_close(usb.handle);
    }
    usb.handle = NULL;
    libusb_exit(NULL);
    if (bt_hc_cbacks)
    {
        while ((p_buf = utils_dequeue (&(usb.rx_eventq))) != NULL)
        {
            bt_hc_cbacks->dealloc(p_buf, (char *) ((RX_HDR *)p_buf+1));
        }
        while ((p_buf = utils_dequeue (&(usb.rx_isoq))) != NULL)
        {
            bt_hc_cbacks->dealloc(p_buf, (char *) ((RX_HDR *)p_buf+1));
        }
        while ((p_buf = utils_dequeue (&(usb.rx_bulkq))) != NULL)
        {
            bt_hc_cbacks->dealloc(p_buf, (char *) ((RX_HDR *)p_buf+1));
        }
    }
    close_sco_db();
}

/*******************************************************************************
**
** Function        usb_ioctl
**
** Description     ioctl inteface
**
** Returns         None
**
*******************************************************************************/
void usb_ioctl(usb_ioctl_op_t op, void *p_data)
{
    return;
}

void usb_sco_trigger(int state, uint16_t sco_handle)
{
    USBDBG("%s", __func__);
    USBDBG("Sco handle = %d", sco_handle);
    if (state == 0)
    {
        if (delete_sco_conn(sco_handle) < 0)
        {
            USBERR("Sco handle not found");
        }
    }
    else
    {
        USBDBG("Setting up SCO (ISO_STARTING");
        if (add_sco_conn(sco_handle) < 0)
        {
            USBERR("Maximum sco connection reached");
        }
    }
}

static int check_sco_handle_validity(uint16_t sco_handle)
{
    int xx = 0;
    for (xx = 0; xx < sco_handle_idx; xx++)
    {
        if (sco_handle == sco_handle_db[xx])
        {
            USBDBG("Valid Sco Handle found at index = %d", xx);
            return xx;
        }
    }
    return -1;
}

static int add_frame_to_cur_packet(uint8_t *buffer, int cur_pkt_idx)
{
    int xx;
    if (cur_pkt_idx >= sco_handle_idx)
    {
        return 0;
    }
    int index = cur_iso_pkt_idx[cur_pkt_idx];
    if (index < 0 || index >= (iso_pkt_size*BT_MAX_ISO_FRAMES))
    {
        return 0;
    }
    if (index == 0)
    {
        cur_iso_pkt[cur_pkt_idx]->event = H4_TYPE_SCO_DATA;
        cur_iso_pkt[cur_pkt_idx]->len = 0;

    }
    for (xx = 0; xx < iso_pkt_size; xx++)
    {
        cur_iso_pkt[cur_pkt_idx]->data[index++] = buffer[xx];
    }
    cur_iso_pkt_idx[cur_pkt_idx] = index;
    cur_iso_pkt[cur_pkt_idx]->len += iso_pkt_size;
    if (index == iso_pkt_size*BT_MAX_ISO_FRAMES)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

static void flush_prev_packet(int cur_pkt_idx)
{
    if (cur_pkt_idx > sco_handle_idx)
    {
        USBERR("%s : wrong index %d", __func__, cur_pkt_idx);
        return;
    }
    cur_iso_pkt_idx[cur_pkt_idx] = 0;
}

static void init_sco_db()
{
    int xx;
    for (xx = 0; xx < BT_MAX_SCO_CONN; xx++)
    {
        cur_iso_pkt[xx] = (ISO_HDR *) bt_hc_cbacks->alloc(iso_pkt_size_wh);
        cur_iso_pkt_idx[xx] = 0;
        sco_handle_db[xx] = -1;
    }
    sco_handle_idx = 0;
    USBDBG("Sco initialised");
}
static void close_sco_db()
{
    int xx;
   for (xx = 0; xx < BT_MAX_SCO_CONN; xx++)
    {
        bt_hc_cbacks->dealloc((TRANSAC)cur_iso_pkt[xx], (char*)cur_iso_pkt[xx]+1);
        cur_iso_pkt_idx[xx] = 0;
        sco_handle_db[xx] = -1;
    }
}
static int add_sco_conn(uint16_t sco_handle)
{

    if(sco_handle_idx >= BT_MAX_SCO_CONN)
    {
        return -1;
    }
    else
    {
        sco_handle_db[sco_handle_idx] = sco_handle;
        sco_handle_idx++;
        USBDBG("Added sco handle %d : Sco_handle_idx = %d", sco_handle, sco_handle_idx);
        if (sco_handle_idx == 1)
        {
            submit_transfer();
            iso_state = ISO_STARTED;
        }
        return 0;
    }
}

static int delete_sco_conn(uint16_t sco_handle)
{
    int xx;
    int yy;
    for (xx = 0; xx < sco_handle_idx; xx++)
    {
        if (sco_handle == sco_handle_db[xx])
        {
            sco_handle_idx--;
            sco_handle_db[xx] = sco_handle_db[sco_handle_idx];
            for (yy = 0; yy < cur_iso_pkt_idx[sco_handle_idx]; yy++)
            {
                cur_iso_pkt[xx]->data[yy] = cur_iso_pkt[sco_handle_idx]->data[yy];
            }
           if (sco_handle_idx == 0)
            {
                cancel_transfer();
                iso_state = ISO_STOPPED;
            }
            return 0;
        }
    }
    return -1;
}

static void submit_transfer(void)
{
    int r = 0, xx;
    unsigned char *buf;
    r = libusb_claim_interface(usb.handle, USB_SCO_INTERFACE);
    if (r != LIBUSB_SUCCESS)
    {
        USBERR("%s : Unable to claim interface 1. Errror %d", __func__, r);
    }
    r = libusb_set_interface_alt_setting(usb.handle, USB_SCO_INTERFACE, ALTERNATE_SETTING);
    if (r != LIBUSB_SUCCESS)
    {
        USBERR("%s : Unable to set the alternate to %d. Error %d", __func__, ALTERNATE_SETTING, r);
    }
    for (xx = 0; xx < NO_RX_SUBMITS; xx++)
    {
        iso_rx_xfer[xx] = libusb_alloc_transfer(BT_MAX_ISO_FRAMES);
        if (!iso_rx_xfer[xx])
        {
            USBERR("Failed to alloc iso_rx_xfer[%d]", xx);
            continue;
        }
        buf = (unsigned char*) malloc(iso_pkt_size*BT_MAX_ISO_FRAMES);
        if (buf == NULL)
        {
            USBERR("Failed to allocate memory for recv transfer for iso_rx_xfer[%d]", xx);
            continue;
        }
        libusb_fill_iso_transfer(iso_rx_xfer[xx], usb.handle, BT_ISO_IN, buf, \
                             iso_pkt_size * BT_MAX_ISO_FRAMES, BT_MAX_ISO_FRAMES, recv_xfer_cb, \
                             NULL, 0);
        libusb_set_iso_packet_lengths (iso_rx_xfer[xx], iso_pkt_size);
        r = libusb_submit_transfer(iso_rx_xfer[xx]);
        if (r < 0)
        {
            USBERR("libusb_submit_transfer : iso_rx_xfer[%d] : failed with error %d", xx, r);
        }
    }
    USBDBG("All packets submitted");
}
static void cancel_transfer(void)
{
    int r, xx;
    USBDBG("Cancel Transfer");
    for (xx =0 ; xx < NO_RX_SUBMITS; xx++)
    {
        r = libusb_cancel_transfer(iso_rx_xfer[xx]);
        if (r < 0)
        {
            USBERR("libusb_cancel_transfer : iso_rx_xfer[%d] : failed with error %d", xx, r);
        }
    }
}
