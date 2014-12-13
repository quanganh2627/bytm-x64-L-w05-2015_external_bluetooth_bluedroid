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
 *  Filename:      audio_hsp_hw.c (derived from audio_a2dp_hw.c)
 *
 *  Description:   Implements hal for bluedroid hsp audio devices
 *
 *****************************************************************************/

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/poll.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <cutils/str_parms.h>
#include <cutils/sockets.h>
#include <hardware/audio.h>
#include <audio_utils/resampler.h>
#include <hardware/hardware.h>
#include "audio_hsp_hw.h"

#define LOG_TAG "audio_hsp_hw"

#include <cutils/log.h>

/*****************************************************************************
**  Constants & Macros
******************************************************************************/

#define CTRL_CHAN_RETRY_COUNT 3
#define USEC_PER_SEC 1000000L
#define SOCKET_POLL_TIMEOUT_MS 500
#define CTRL_CHANNEL_RETRY_INTERVAL_US 250000
#define CASE_RETURN_STR(const) case const: return #const;

#define HSP_OUTPUT_STREAM_FRAMES 2560
#define HSP_INPUT_STREAM_FRAMES 5292
#define HSP_ADEV_INPUT_BUFFER_SIZE 4096 /* for adev input buf callback */

#ifdef HSP_HAL_DEBUG
#define FNLOG()             ALOGV("%s", __FUNCTION__);
#define DEBUG(fmt, ...)     ALOGV("%s: " fmt,__FUNCTION__, ## __VA_ARGS__)
#define INFO(fmt, ...)      ALOGI("%s: " fmt,__FUNCTION__, ## __VA_ARGS__)
#define ASSERTC(cond, msg, val) if (!(cond)) {ERROR("### ASSERT : %s line %d %s (%d) ###", __FILE__, __LINE__, msg, val);}
/* log helpers with stream direction */
#define FNLOG_IO(x)               ALOGV("[ %c ] %s", x, __FUNCTION__);
#define DEBUG_IO(fmt, x, ...)     ALOGV("[ %c ] %s: " fmt, x, __FUNCTION__, ## __VA_ARGS__)
#define INFO_IO(fmt, x, ...)      ALOGI("[ %c ] %s: " fmt, x, __FUNCTION__, ## __VA_ARGS__)
#else
#define FNLOG()             do {} while(0)
#define DEBUG(fmt, ...)     do {} while(0)
#define INFO(fmt, ...)      do {} while(0)
#define FNLOG_IO(x)               do {} while(0)
#define DEBUG_IO(x, fmt, ...)     do {} while(0)
#define INFO_IO(x, fmt, ...)      do {} while(0)
#define ASSERTC(cond, msg, val) do {} while(0)
#endif

#define ERROR(fmt, ...)           ALOGE("%s: " fmt,__FUNCTION__, ## __VA_ARGS__)
#define ERROR_IO(fmt, x, ...)     ALOGE("[ %c ] %s: " fmt, x, __FUNCTION__, ## __VA_ARGS__)

/*****************************************************************************
**  Local type definitions
******************************************************************************/
typedef enum {
    HSP_INPUT_STREAM = 'I',
    HSP_OUTPUT_STREAM = 'O'
} hsp_io_t;

typedef union hsp_audio_stream {
    struct audio_stream_out out;
    struct audio_stream_in in;
} hsp_audio_stream_t;

typedef enum {
    AUDIO_HSP_STATE_STARTING,
    AUDIO_HSP_STATE_STARTED,
    AUDIO_HSP_STATE_STOPPING,
    AUDIO_HSP_STATE_STOPPED,
    AUDIO_HSP_STATE_SUSPENDED, /* need explicit set param call to resume (suspend=false) */
    AUDIO_HSP_STATE_STANDBY    /* allows write to autoresume */
} hsp_state_t;

struct hsp_config {
    uint32_t af_frame_num;         /* frame num for af to allocate stream buffers */
    uint32_t af_rate;              /* rate to audio flinger */
    uint32_t af_channels;          /* channels to audio flinger */
    uint32_t bt_channels;          /* channels supported by BT stack */
    uint32_t bt_rate;              /* rate supported by BT stack */
    int format;
};

struct hsp_private {
    pthread_mutex_t         lock;
    int                     ctrl_fd;
    int                     data_fd;
    size_t                  socket_buf_sz;
    hsp_state_t             state;
};

struct hsp_stream {
    hsp_audio_stream_t stream;
    hsp_io_t io;  /* direction of a stream from audio flinger side */
    struct hsp_config      cfg;
    struct resampler_itfe *resampler;
    int16_t *resample_buf;
    uint32_t resample_frame_num;         /* frame num to allocate resample buffer */
    struct hsp_private private;
};

struct hsp_audio_device {
    struct audio_hw_device device;
    struct hsp_stream *output;
    struct hsp_stream *input;
    bool mic_mute;
};

/*****************************************************************************
**  Static variables
******************************************************************************/

/*****************************************************************************
**  Static functions
******************************************************************************/

/*****************************************************************************
**  Externs
******************************************************************************/

/*****************************************************************************
**  Functions
******************************************************************************/

/*****************************************************************************
**   Miscellaneous helper functions
******************************************************************************/

/*
 * return the minimum frame numbers from resampling between BT stack's rate
 * and audio flinger's. For output stream, 'output' shall be true, otherwise
 * false for input streams at audio flinger side.
 */
static inline size_t get_resample_frame_num(uint32_t bt_rate, uint32_t af_rate, size_t frame_num, bool output)
{
    size_t resample_frames_num = frame_num * bt_rate / af_rate + output;

    DEBUG("resampler: af_rate [%d] frame_num [%d] bt_rate [%d] resample frames [%d]",
            af_rate, frame_num, bt_rate, resample_frames_num);
    return resample_frames_num;
}


/* helper function to convert a stereo PCM 16 bit stream to a mono
 * channel stream.
 */
static int pcm_16_stereo_to_mono (int16_t *buf, size_t frame_num)
{
    size_t i;
    int32_t tmp;

    if (!buf || !frame_num)
    {
        ERROR("invalid parameters: buffer = 0x%p frame_num = %d",
                buf, frame_num);
        return -EINVAL;
    }

    for (i = 0; i < frame_num; i++) {
        tmp = buf[2 * i] + buf[2 * i + 1];
        buf[i] = (int16_t)(tmp >> 1);
    }
    return 0;
}

static const char* dump_hsp_ctrl_event(char event)
{
    switch(event)
    {
        CASE_RETURN_STR(HSP_CTRL_CMD_NONE)
        CASE_RETURN_STR(HSP_CTRL_CMD_CHECK_READY)
        CASE_RETURN_STR(HSP_CTRL_CMD_START)
        CASE_RETURN_STR(HSP_CTRL_CMD_STOP)
        CASE_RETURN_STR(HSP_CTRL_CMD_SUSPEND)
        default:
            return "UNKNOWN MSG ID";
    }
}


/*****************************************************************************
**
**   bluedroid stack adaptation
**
*****************************************************************************/

static int skt_connect(struct hsp_private *private, const char *path)
{
    int ret;
    int skt_fd;
    struct sockaddr_un remote;
    int len;

    INFO("connect to %s (sz %d)", path, private->socket_buf_sz);

    skt_fd = socket(AF_LOCAL, SOCK_STREAM, 0);

    if(socket_local_client_connect(skt_fd, path,
            ANDROID_SOCKET_NAMESPACE_ABSTRACT, SOCK_STREAM) < 0)
    {
        ERROR("failed to connect (%s)", strerror(errno));
        close(skt_fd);
        return -1;
    }

    len = private->socket_buf_sz;

    DEBUG("reset socket buf size to [%d]", len);
    ret = setsockopt(skt_fd, SOL_SOCKET, SO_SNDBUF, (char*)&len, (int)sizeof(len));

    /* only issue warning if failed */
    if (ret < 0)
        ERROR("failed to set snd_buf size (%s)", strerror(errno));

    ret = setsockopt(skt_fd, SOL_SOCKET, SO_RCVBUF, (char*)&len, (int)sizeof(len));

    /* only issue warning if failed */
    if (ret < 0)
        ERROR("failed to set rcv_buf size (%s)", strerror(errno));

    INFO("connected to stack fd = %d", skt_fd);

    return skt_fd;
}

static ssize_t skt_write(int fd, const void *p, size_t len)
{
    ssize_t sent;
    struct pollfd pfd;

    FNLOG();

    pfd.fd = fd;
    pfd.events = POLLOUT|POLLHUP|POLLNVAL;;

    /* poll for sending*/
    if (poll(&pfd, 1, SOCKET_POLL_TIMEOUT_MS) == 0)
    {
        DEBUG("%s: time out %d", __FUNCTION__, fd);
        return 0;
    }
    if (pfd.revents & (POLLHUP|POLLNVAL|POLLRDHUP|POLLERR))
    {
        ERROR("%s:remote error fd %d, events 0x%x", __FUNCTION__, fd, pfd.revents);
        return -1;
    }

    if ((sent = send(fd, p, len, MSG_NOSIGNAL)) < 0)
        ERROR("send failed (%s)", strerror(errno));

    return sent;
}

static ssize_t skt_read(int fd, char *p, size_t len)
{
    ssize_t ret;
    struct pollfd pfd;

    FNLOG();

    pfd.fd = fd;
    pfd.events = POLLIN|POLLHUP|POLLNVAL;

    /* poll for reading */
    if (poll(&pfd, 1, SOCKET_POLL_TIMEOUT_MS) == 0)
    {
        ERROR("%s: time out %d", __FUNCTION__, fd);
        return 0;
    }

    if (pfd.revents & (POLLHUP|POLLNVAL))
    {
        ERROR("%s:remote error fd %d, events 0x%x", __FUNCTION__, fd, pfd.revents);
        return 0;
    }
    if ((ret = read(fd, p, len)) < 0)
        ERROR("read failed with (%s)", strerror(errno));

    return ret;
}

static void skt_disconnect(int *fd)
{
    INFO("fd %d", *fd);

    if (*fd != AUDIO_SKT_DISCONNECTED)
    {
        shutdown(*fd, SHUT_RDWR);
        close(*fd);
        *fd = AUDIO_SKT_DISCONNECTED;
    }
}


static void hsp_stream_private_init(struct hsp_private *private)
{
    pthread_mutexattr_t lock_attr;

    FNLOG();

    pthread_mutexattr_init(&lock_attr);
    pthread_mutex_init(&private->lock, &lock_attr);

    private->ctrl_fd = AUDIO_SKT_DISCONNECTED;
    private->data_fd = AUDIO_SKT_DISCONNECTED;
    private->state = AUDIO_HSP_STATE_STOPPED;
    /* manages max capacity of socket pipe */
    private->socket_buf_sz = HSP_SOCKET_BUFFER_SZ;

}

/*****************************************************************************
**
**  AUDIO CONTROL PATH
**
*****************************************************************************/

static int hsp_command(struct hsp_private *private, char cmd)
{
    char ack;

    DEBUG("HSP COMMAND %s", dump_hsp_ctrl_event(cmd));

    /* send command */
    if (send(private->ctrl_fd, &cmd, 1, MSG_NOSIGNAL) == -1)
    {
        ERROR("cmd failed (%s)", strerror(errno));
        skt_disconnect(&private->ctrl_fd);
        return -1;
    }

    /* wait for ack byte */
    if (recv(private->ctrl_fd, &ack, 1, MSG_NOSIGNAL) < 0)
    {
        ERROR("ack failed (%s)", strerror(errno));
        skt_disconnect(&private->ctrl_fd);
        return -1;
    }

    DEBUG("HSP COMMAND %s DONE STATUS %d", dump_hsp_ctrl_event(cmd), ack);

    if (ack != HSP_CTRL_ACK_SUCCESS)
        return -1;

    return 0;
}

/*****************************************************************************
**
** AUDIO DATA PATH
**
*****************************************************************************/

/* Caller should hold lock before calling this function */
static int start_audio_datapath(struct hsp_private *private, const char *path)
{
    int oldstate = private->state;

    INFO("state %d", private->state);

    if (private->ctrl_fd == AUDIO_SKT_DISCONNECTED)
        return -1;

    private->state = AUDIO_HSP_STATE_STARTING;

    if (hsp_command(private, HSP_CTRL_CMD_START) < 0)
    {
        ERROR("audiopath start failed");

        private->state = oldstate;
        return -1;
    }

    /* connect socket if not yet connected */
    if (private->data_fd == AUDIO_SKT_DISCONNECTED)
    {
        private->data_fd = skt_connect(private, path);

        if (private->data_fd < 0)
        {
            private->state = oldstate;
            return -1;
        }

        private->state = AUDIO_HSP_STATE_STARTED;
    }

    return 0;
}

static int stop_audio_datapath(struct hsp_private *private)
{
    int oldstate = private->state;

    INFO("state %d", private->state);

    if (private->ctrl_fd == AUDIO_SKT_DISCONNECTED)
         return -1;

    /* prevent any stray output writes from autostarting the stream
       while stopping audiopath */
    private->state = AUDIO_HSP_STATE_STOPPING;

    if (hsp_command(private, HSP_CTRL_CMD_STOP) < 0)
    {
        ERROR("audiopath stop failed");
        private->state = oldstate;
        return -1;
    }

    private->state = AUDIO_HSP_STATE_STOPPED;

    /* disconnect audio path */
    skt_disconnect(&private->data_fd);

    return 0;
}

static int suspend_audio_datapath(struct hsp_private *private, bool standby)
{
    INFO("state %d", private->state);

    if (private->ctrl_fd == AUDIO_SKT_DISCONNECTED)
         return -1;

    if (private->state == AUDIO_HSP_STATE_STOPPING)
        return -1;

    if (hsp_command(private, HSP_CTRL_CMD_SUSPEND) < 0)
        return -1;

    if (standby)
        private->state = AUDIO_HSP_STATE_STANDBY;
    else
        private->state = AUDIO_HSP_STATE_SUSPENDED;

    /* disconnect audio path */
    skt_disconnect(&private->data_fd);

    return 0;
}

static int check_hsp_ready(struct hsp_private *private)
{
    INFO("state %d", private->state);

    if (hsp_command(private, HSP_CTRL_CMD_CHECK_READY) < 0)
    {
        ERROR("check hsp ready failed");
        return -1;
    }
    return 0;
}

/*****************************************************************************
**
**  Unified audio callbacks for both of output and input streams
**
*****************************************************************************/
static uint32_t get_sample_rate(const struct audio_stream *stream)
{
    struct hsp_stream *hsp_stream = (struct hsp_stream *)stream;

    DEBUG_IO("rate %d", hsp_stream->io, hsp_stream->cfg.af_rate);

    return hsp_stream->cfg.af_rate;
}

static int set_sample_rate(struct audio_stream *stream, uint32_t rate)
{
    struct hsp_stream *hsp_stream = (struct hsp_stream *)stream;

    DEBUG_IO("rate : %d", hsp_stream->io, rate);

    /* Application Note: resampler and its buffer need to be re-allocated
     * when rate is allowed to change */
    if (rate != AUDIO_STREAM_DEFAULT_RATE)
    {
        ERROR_IO("only rate %d supported", hsp_stream->io, AUDIO_STREAM_DEFAULT_RATE);
        return -1;
    }

    hsp_stream->cfg.af_rate = rate;

    return 0;
}


static size_t get_buffer_size(const struct audio_stream *stream)
{
    struct hsp_stream *hsp_stream = (struct hsp_stream *)stream;
    struct hsp_config *cfg = &hsp_stream->cfg;
    size_t size = audio_stream_frame_size(stream) * cfg->af_frame_num;

    DEBUG_IO("buffer_size: %d", hsp_stream->io, size);

    return size;
}

static uint32_t get_channels(const struct audio_stream *stream)
{
    struct hsp_stream *hsp_stream = (struct hsp_stream *)stream;

    DEBUG_IO("channels 0x%x", hsp_stream->io, hsp_stream->cfg.af_channels);

    return hsp_stream->cfg.af_channels;
}

static audio_format_t get_format(const struct audio_stream *stream)
{
    struct hsp_stream *hsp_stream = (struct hsp_stream *)stream;

    DEBUG_IO("format 0x%x", hsp_stream->io, hsp_stream->cfg.format);
    return hsp_stream->cfg.format;
}

static int set_format(struct audio_stream *stream, audio_format_t format)
{
    struct hsp_stream *hsp_stream = (struct hsp_stream *)stream;

    DEBUG_IO("setting format not yet supported (0x%x)", hsp_stream->io, format);
    return -ENOSYS;
}

static char * get_parameters(const struct audio_stream *stream, const char *keys)
{
    struct hsp_stream *hsp_stream = (struct hsp_stream *)stream;

    FNLOG_IO(hsp_stream->io);

    /* add populating param here */

    return strdup("");
}

static int add_audio_effect(const struct audio_stream *stream, effect_handle_t effect)
{
    struct hsp_stream *hsp_stream = (struct hsp_stream *)stream;

    FNLOG_IO(hsp_stream->io);
    return 0;
}

static int remove_audio_effect(const struct audio_stream *stream, effect_handle_t effect)
{
    struct hsp_stream *hsp_stream = (struct hsp_stream *)stream;

    FNLOG_IO(hsp_stream->io);
    return 0;
}

/*****************************************************************************
**
**  audio output callbacks
**
*****************************************************************************/

static ssize_t out_write(struct audio_stream_out *stream, const void* buffer,
                         size_t bytes)
{
    struct hsp_stream *out = (struct hsp_stream *)stream;
    struct hsp_private *private = &out->private;
    ssize_t sent = -1;

    DEBUG("write %d bytes (fd %d)", bytes, private->data_fd);

    pthread_mutex_lock(&private->lock);

    if (private->state == AUDIO_HSP_STATE_SUSPENDED)
    {
        DEBUG("stream suspended");
        pthread_mutex_unlock(&private->lock);
        return -1;
    }

    /* only allow autostarting if we are in stopped or standby */
    if ((private->state == AUDIO_HSP_STATE_STOPPED) ||
        (private->state == AUDIO_HSP_STATE_STANDBY))
    {
        if (start_audio_datapath(private, HSP_OUT_DATA_PATH) < 0)
        {
            pthread_mutex_unlock(&private->lock);
            return -1;
        }
    }
    else if (private->state != AUDIO_HSP_STATE_STARTED)
    {
        ERROR("invalid state: %d", private->state);
        pthread_mutex_unlock(&private->lock);
        return -1;
    }

    pthread_mutex_unlock(&private->lock);

    /* do raw write when format is not PCM 16 bit */
    if (stream->common.get_format(&stream->common) != AUDIO_FORMAT_PCM_16_BIT)
        return skt_write(private->data_fd, buffer, bytes);

    /* check if we need to do conversion to mono and resampling when
     * the format is PCM 16bit. Otherwise, write raw data from audio flinger.
     */

    int16_t *send_buf = (int16_t *) buffer;
    size_t frame_num = bytes / audio_stream_frame_size(&stream->common);
    size_t output_frame_num = frame_num;
    int channel_num = popcount(stream->common.get_channels(&stream->common));
    int bt_channel_num = popcount(out->cfg.bt_channels);
    ssize_t wrote = 0;
    ssize_t total = 0;
    int ret;

    /* stereo to mono */
    if (channel_num == 2 && bt_channel_num == 1)
    {
        if (pcm_16_stereo_to_mono(send_buf, frame_num))
        {
            ERROR("failed to convert stereo to mono");
            goto out_done;
        }
    }
    else if (bt_channel_num != channel_num)
    {
        ERROR("Not surported channels %d to %d", channel_num, bt_channel_num);
        goto out_done;
    }

    if (out->resampler)
    {
        /* limit resampler's output within what resample buf can hold */
        output_frame_num = out->resample_frame_num;

        ret = out->resampler->resample_from_input(out->resampler, send_buf,
                &frame_num, out->resample_buf, &output_frame_num);

        if (ret)
        {
            ERROR("Failed to resample frames: %d input %d output (%s)",
                    frame_num, output_frame_num, strerror(ret));
            goto out_done;
        }

        send_buf = out->resample_buf;
    } /* resampling done */

    total = output_frame_num * bt_channel_num * sizeof(int16_t);

    /* we could have changed the size of data due to mono conversion and resampling
     * so we must commit to write all data, return whole all 'bytes' to audio flinger.
     */

    sent = 0;

    while (sent < total)
    {
        wrote = skt_write(private->data_fd, (int8_t *) send_buf + sent, total - sent);
        if (wrote <= 0)
        {
            sent = -1;
            goto out_done;
        }
        else
            sent += wrote;
    }
    sent = bytes;

out_done:
    DEBUG("return [%d] bytes", sent);
    return sent;
}

static int out_get_render_position(const struct audio_stream_out *stream,
                                   uint32_t *dsp_frames)
{
    struct hsp_stream *hsp_stream = (struct hsp_stream *)stream;

    FNLOG_IO(hsp_stream->io);
    return -EINVAL;
}

static int out_set_volume(struct audio_stream_out *stream, float left,
                          float right)
{
    FNLOG();

    /* volume controlled in audioflinger mixer (digital) */

    return -ENOSYS;
}

static int out_standby(struct audio_stream *stream)
{
    struct hsp_stream *out = (struct hsp_stream *)stream;
    struct hsp_private *private = &out->private;

    int retVal = 0;

    FNLOG();

    pthread_mutex_lock(&private->lock);

    if (private->state == AUDIO_HSP_STATE_STARTED)
        retVal =  suspend_audio_datapath(private, true);
    else
        retVal = 0;
    pthread_mutex_unlock (&private->lock);

    return retVal;
}

static int out_dump(const struct audio_stream *stream, int fd)
{
    struct hsp_stream *out = (struct hsp_stream *)stream;

    FNLOG();
    return 0;
}

static int out_set_parameters(struct audio_stream *stream, const char *kvpairs)
{
    struct hsp_stream *out = (struct hsp_stream *)stream;
    struct hsp_private *private = &out->private;
    struct str_parms *parms;
    char keyval[16];
    int retval = 0;

    FNLOG_IO(out->io);

    pthread_mutex_lock(&private->lock);

    INFO("state %d", private->state);

    parms = str_parms_create_str(kvpairs);

    if(parms != NULL)
    {
        /* dump params */
        str_parms_dump(parms);

        retval = str_parms_get_str(parms, "closing", keyval, sizeof(keyval));

        if (retval >= 0)
        {
            if (strcmp(keyval, "true") == 0)
            {
                DEBUG("stream closing, disallow any writes");
                private->state = AUDIO_HSP_STATE_STOPPING;

            }
        }

        /* use A2dp instead of Hsp */
        retval = str_parms_get_str(parms, "A2dpSuspended", keyval, sizeof(keyval));

        if (retval >= 0)
        {
            if (strcmp(keyval, "true") == 0)
            {
                if (private->state == AUDIO_HSP_STATE_STARTED)
                    retval = suspend_audio_datapath(private, false);
            }
            else
            {
                /* Do not start the streaming automatically. If the phone was streaming
                 * prior to being suspended, the next out_write shall trigger the
                 * AVDTP start procedure */
                if (private->state == AUDIO_HSP_STATE_SUSPENDED)
                    private->state = AUDIO_HSP_STATE_STANDBY;
                /* Irrespective of the state, return 0 */
                retval = 0;
            }
        }

        str_parms_destroy(parms);
    }

    pthread_mutex_unlock(&private->lock);
    return retval;
}

static uint32_t out_get_latency(const struct audio_stream_out *stream)
{
    int latency_us;
    struct hsp_stream *out = (struct hsp_stream *)stream;
    struct hsp_private *private = &out->private;

    FNLOG();

    /* same as a2dp. */
    latency_us = ((private->socket_buf_sz * 1000 ) /
                    audio_stream_frame_size(&out->stream.out.common) /
                    out->cfg.af_rate) * 1000;


    return (latency_us / 1000) + 200;
}

/*****************************************************************************
**
**  audio input callbacks
**
*****************************************************************************/

static int in_standby(struct audio_stream *stream)
{
    FNLOG();
    return 0;
}

static int in_dump(const struct audio_stream *stream, int fd)
{
    FNLOG();
    return 0;
}

static int in_set_parameters(struct audio_stream *stream, const char *kvpairs)
{
    FNLOG();
    return 0;
}

static int in_set_gain(struct audio_stream_in *stream, float gain)
{
    FNLOG();
    return 0;
}

static ssize_t in_read(struct audio_stream_in *stream, void* buffer,
                       size_t bytes)
{
    struct hsp_stream *in = (struct hsp_stream *) stream;
    struct hsp_private *private = &in->private;
    ssize_t ret = -1;

    DEBUG("buffer size %d bytes (fd %d)", bytes, private->data_fd);

    pthread_mutex_lock(&private->lock);

    if (private->state == AUDIO_HSP_STATE_SUSPENDED)
    {
        pthread_mutex_unlock(&private->lock);
        DEBUG("stream suspended");
        return -1;
    }

    /* only allow autostarting if we are in stopped or standby */
    if ((private->state == AUDIO_HSP_STATE_STOPPED)
            || (private->state == AUDIO_HSP_STATE_STANDBY))
    {
        if (start_audio_datapath(private, HSP_IN_DATA_PATH) < 0)
        {
            ERROR("Failed to start in data path");
            pthread_mutex_unlock(&private->lock);
            return -1;
        }
    }

    pthread_mutex_unlock(&private->lock);

    if (stream->common.get_channels(&stream->common)
            != in->cfg.bt_channels)
    {
        ERROR("unsupported: different channels between BT stack and stream");
        goto in_done;
    }
    else if (in->cfg.af_rate == in->cfg.bt_rate)
    {    /* raw read, resampling not needed */
        ret = skt_read(private->data_fd, (char *) buffer, bytes);
        goto in_done;
    }
    else if (stream->common.get_format(&stream->common)
            != AUDIO_FORMAT_PCM_16_BIT)
    {
        ERROR("unsupported: non-PCM 16 bit with different rates");
        goto in_done;
    }

    /* now we are sure for PCM 16 BIT with different rates */
    size_t resample_size;
    size_t max_resample_size;
    size_t frame_size = audio_stream_frame_size(&stream->common);
    size_t frame_num = bytes / frame_size;
    size_t input_frame_num;
    int bt_channel_num = popcount(in->cfg.bt_channels);
    size_t sample_rate = stream->common.get_sample_rate(&stream->common);

    if (!in->resample_buf || !in->resampler)
    {
        ERROR("cannot find resampler");
        goto in_done;
    }

    input_frame_num = get_resample_frame_num(in->cfg.bt_rate, sample_rate,
            frame_num, 0);

    if (!input_frame_num)
    { /* input buffer is too small to resample */
        ERROR("data is too small to resample, discard it");
        goto in_done;
    }

    /* we can only read frames from BT as much as frames of resample buffer */
    if (input_frame_num > in->resample_frame_num)
    {
        DEBUG("resampler: resize read frames from %d to %d !", input_frame_num, in->resample_frame_num);
        input_frame_num = in->resample_frame_num;
    }
    resample_size = sizeof(int16_t) * bt_channel_num * input_frame_num;

    ret = skt_read(private->data_fd, (char *)in->resample_buf, resample_size);

    DEBUG("resampler: read [%ld] bytes from BT stack. buf size [%d]", ret, resample_size);

    if (ret > 0)
    {
        /* note: we expect BT stack provide whole frame(s) every time */
        if ((size_t) ret < frame_size)
        {
            ERROR("got input %ld byte but not enough to resample, drop", ret);
            ret = -1;
            goto in_done;
        }

        size_t read_frames = ret / frame_size;

        DEBUG("resampler: input [%d] frames, maximum output [%d] frames",
                read_frames, frame_num);

        ret = in->resampler->resample_from_input(in->resampler, in->resample_buf,
                &read_frames, (int16_t *) buffer, &frame_num);

        if (ret)
        {
            ERROR("Failed to resample frames: %d input %d output (%s)",
                    frame_num, input_frame_num, strerror(ret));
            ret = -1;
            goto in_done;
        }

        DEBUG("resampler: remain [%d] frames, output [%d] frames", read_frames,
                frame_num);

        ret = frame_num * frame_size;
    }

in_done:
    DEBUG("return [%ld] bytes", ret);
    return ret;
}

static uint32_t in_get_input_frames_lost(struct audio_stream_in *stream)
{
    FNLOG();
    return 0;
}

/*****************************************************************************
**
**  adev callbacks
**
*****************************************************************************/

static int adev_open_output_stream(struct audio_hw_device *dev,
                                   audio_io_handle_t handle,
                                   audio_devices_t devices,
                                   audio_output_flags_t flags,
                                   struct audio_config *config,
                                   struct audio_stream_out **stream_out)

{
    struct hsp_audio_device *hsp_dev = (struct hsp_audio_device *)dev;
    struct hsp_stream *out;
    struct hsp_private *private;
    int ret = 0;
    int i;

    INFO("opening output");

    out = (struct hsp_stream *)calloc(1, sizeof(struct hsp_stream));

    if (!out)
        return -ENOMEM;

    out->stream.out.common.get_sample_rate = get_sample_rate;
    out->stream.out.common.set_sample_rate = set_sample_rate;
    out->stream.out.common.get_buffer_size = get_buffer_size;
    out->stream.out.common.get_channels = get_channels;
    out->stream.out.common.get_format = get_format;
    out->stream.out.common.set_format = set_format;
    out->stream.out.common.standby = out_standby;
    out->stream.out.common.dump = out_dump;
    out->stream.out.common.set_parameters = out_set_parameters;
    out->stream.out.common.get_parameters = get_parameters;
    out->stream.out.common.add_audio_effect = add_audio_effect;
    out->stream.out.common.remove_audio_effect = remove_audio_effect;
    out->stream.out.get_latency = out_get_latency;
    out->stream.out.set_volume = out_set_volume;
    out->stream.out.write = out_write;
    out->stream.out.get_render_position = out_get_render_position;
    out->cfg.af_channels = AUDIO_CHANNEL_OUT_STEREO;
    out->cfg.format = AUDIO_STREAM_DEFAULT_FORMAT;
    out->cfg.af_rate = AUDIO_STREAM_DEFAULT_RATE;
    out->cfg.bt_channels = AUDIO_CHANNEL_OUT_MONO;
    out->cfg.bt_rate = BT_STREAM_OUT_RATE;
    out->cfg.af_frame_num = HSP_OUTPUT_STREAM_FRAMES;
    out->io = HSP_OUTPUT_STREAM;

    /* create resampler as needed, based on what BT stack supports*/
    if (out->cfg.af_rate != out->cfg.bt_rate && out->cfg.format == AUDIO_FORMAT_PCM_16_BIT)
    {
        int  bt_channel_num = popcount(out->cfg.bt_channels);
        size_t frame_size = audio_stream_frame_size(&out->stream.out.common);
        size_t resample_size;

        ret = create_resampler(out->cfg.af_rate,
                               out->cfg.bt_rate,
                               bt_channel_num,  /* if af rate is different, do conversion before resampling */
                               RESAMPLER_QUALITY_DEFAULT,
                               NULL,
                               &out->resampler);
        if (ret)
        {
            ERROR("Failed to create resampler (%s)", strerror(ret));
            goto err_open;
        }

        DEBUG("Created resampler: input rate [%d] output rate [%d] channels [%d]",
                out->cfg.af_rate, out->cfg.bt_rate, bt_channel_num);

        out->resample_frame_num = get_resample_frame_num(out->cfg.bt_rate,
                out->cfg.af_rate, out->cfg.af_frame_num, 1);

        if (!out->resample_frame_num)
        {
            ERROR("frame num is too small to resample, discard it");
            goto err_open;
        }

        resample_size = sizeof(int16_t) * bt_channel_num * out->resample_frame_num;

        out->resample_buf = malloc(resample_size);

        if (!out->resample_buf)
        {
            ERROR("failed to allocate resample buffer for %d frames",
                    out->resample_frame_num);
            goto err_open;
        }

        DEBUG("resampler: frame num [%d] buf size [%d] bytes",
                out->resample_frame_num, resample_size);
    }

    /* initialize hsp specifics */
    private = &out->private;

    hsp_stream_private_init(private);

   /* set output config values */
   if (config)
   {
      config->format = get_format(&out->stream.out.common);
      config->sample_rate = get_sample_rate(&out->stream.out.common);
      config->channel_mask = get_channels(&out->stream.out.common);
   }
    *stream_out = &out->stream.out;
    hsp_dev->output = out;

    /* retry logic to catch any timing variations on control channel */
    for (i = 0; i < CTRL_CHAN_RETRY_COUNT; i++)
    {
        /* connect control channel if not already connected */
        if ((private->ctrl_fd = skt_connect(private, HSP_OUT_CTRL_PATH)) > 0)
        {
            /* success, now check if stack is ready */
            if (check_hsp_ready(private) == 0)
                break;

            ERROR("error : hsp not ready, wait 250 ms and retry");
            usleep(CTRL_CHANNEL_RETRY_INTERVAL_US);
            skt_disconnect(&private->ctrl_fd);
        }

        /* ctrl channel not ready, wait a bit */
        usleep(CTRL_CHANNEL_RETRY_INTERVAL_US);
    }

    if (private->ctrl_fd == AUDIO_SKT_DISCONNECTED)
    {
        ERROR("ctrl socket failed to connect (%s)", strerror(errno));
        ret = -1;
        goto err_open;
    }

    DEBUG("success");
    return 0;

err_open:
    if (out->resampler)
        release_resampler(out->resampler);

    free(out->resample_buf);
    free(out);
    hsp_dev->output = NULL;
    *stream_out = NULL;

    ERROR("failed");
    return ret;
}

static void adev_close_output_stream(struct audio_hw_device *dev,
                                     struct audio_stream_out *stream)
{
    struct hsp_audio_device *hsp_dev = (struct hsp_audio_device *)dev;
    struct hsp_stream *out = (struct hsp_stream *)stream;
    struct hsp_private *private = &out->private;

    INFO("closing output (state %d)", private->state);

    pthread_mutex_lock(&private->lock);
    if ((private->state == AUDIO_HSP_STATE_STARTED) || (private->state == AUDIO_HSP_STATE_STOPPING))
        stop_audio_datapath(private);

    skt_disconnect(&private->ctrl_fd);

    release_resampler(out->resampler);
    free(out->resample_buf);
    pthread_mutex_unlock(&private->lock);

    free(out);
    hsp_dev->output = NULL;
}

static int adev_set_parameters(struct audio_hw_device *dev, const char *kvpairs)
{
    FNLOG();

    return 0;
}

static char * adev_get_parameters(const struct audio_hw_device *dev,
                                  const char *keys)
{
    struct str_parms *parms;

    FNLOG();

    parms = str_parms_create_str(keys);

    if(parms != NULL)
    {
        str_parms_dump(parms);

        str_parms_destroy(parms);
    }

    return strdup("");
}

static int adev_init_check(const struct audio_hw_device *dev)
{
    struct hsp_audio_device *hsp_dev = (struct hsp_audio_device*)dev;

    FNLOG();

    return 0;
}

static int adev_set_voice_volume(struct audio_hw_device *dev, float volume)
{
    FNLOG();

    return -ENOSYS;
}

static int adev_set_master_volume(struct audio_hw_device *dev, float volume)
{
    FNLOG();

    return -ENOSYS;
}

static int adev_set_mode(struct audio_hw_device *dev, int mode)
{
    FNLOG();

    return 0;
}

static int adev_set_mic_mute(struct audio_hw_device *dev, bool state)
{
    struct hsp_audio_device *hsp_dev = (struct hsp_audio_device *)dev;

    DEBUG("state: %d", state);
    hsp_dev->mic_mute = state;

    /* TODO: check the mute state and handle it in in_read() */
    return 0;
}

static int adev_get_mic_mute(const struct audio_hw_device *dev, bool *state)
{
    struct hsp_audio_device *hsp_dev = (struct hsp_audio_device *)dev;


    *state = hsp_dev->mic_mute;

    DEBUG("state: %d", *state);

    return 0;
}

static size_t adev_get_input_buffer_size(const struct audio_hw_device *dev,
                                         const struct audio_config *config)
{
    FNLOG();

    return HSP_ADEV_INPUT_BUFFER_SIZE;
}

static int adev_open_input_stream(struct audio_hw_device *dev,
                                  audio_io_handle_t handle,
                                  audio_devices_t devices,
                                  struct audio_config *config,
                                  struct audio_stream_in **stream_in)
{
    struct hsp_audio_device *hsp_dev = (struct hsp_audio_device *)dev;
    struct hsp_stream *in;
    struct hsp_private *private;
    int i;
    int ret;

    DEBUG("requested rate %d", config->sample_rate);

    in = (struct hsp_stream *)calloc(1, sizeof(struct hsp_stream));

    if (!in)
        return -ENOMEM;

    in->stream.in.common.get_sample_rate = get_sample_rate;
    in->stream.in.common.set_sample_rate = set_sample_rate;
    in->stream.in.common.get_buffer_size = get_buffer_size;
    in->stream.in.common.get_channels = get_channels;
    in->stream.in.common.get_format = get_format;
    in->stream.in.common.set_format = set_format;
    in->stream.in.common.standby = in_standby;
    in->stream.in.common.dump = in_dump;
    in->stream.in.common.set_parameters = in_set_parameters;
    in->stream.in.common.get_parameters = get_parameters;
    in->stream.in.common.add_audio_effect = add_audio_effect;
    in->stream.in.common.remove_audio_effect = remove_audio_effect;
    in->stream.in.set_gain = in_set_gain;
    in->stream.in.read = in_read;
    in->stream.in.get_input_frames_lost = in_get_input_frames_lost;
    in->io = HSP_INPUT_STREAM;

    *stream_in = &in->stream.in;

    in->cfg.af_channels = AUDIO_CHANNEL_IN_MONO;
    in->cfg.format = AUDIO_STREAM_DEFAULT_FORMAT;
    in->cfg.af_rate = AUDIO_STREAM_DEFAULT_RATE;
    in->cfg.bt_channels = AUDIO_CHANNEL_IN_MONO;
    in->cfg.bt_rate = BT_STREAM_IN_RATE;
    in->cfg.af_frame_num = HSP_INPUT_STREAM_FRAMES;

    /* create resampler as needed, based on what BT stack supports*/
    if (in->cfg.af_rate != in->cfg.bt_rate && in->cfg.format == AUDIO_FORMAT_PCM_16_BIT)
    {
        int  bt_channel_num = popcount(in->cfg.bt_channels);
        size_t frame_size = audio_stream_frame_size(&in->stream.in.common);
        size_t resample_size;

        ret = create_resampler(in->cfg.bt_rate,
                               in->cfg.af_rate,
                               bt_channel_num,
                               RESAMPLER_QUALITY_DEFAULT,
                               NULL,
                               &in->resampler);
        if (ret)
        {
            ERROR("Failed to create resampler (%s)", strerror(ret));
            goto err_open;
        }

        DEBUG("Created resampler: input rate [%d] output rate [%d] channels [%d]",
                in->cfg.bt_rate, in->cfg.af_rate, bt_channel_num);

        in->resample_frame_num = get_resample_frame_num(in->cfg.bt_rate, in->cfg.af_rate,
                in->cfg.af_frame_num, 0);

        resample_size = sizeof(int16_t) * bt_channel_num * in->resample_frame_num;

        in->resample_buf = malloc(resample_size);

        if (!in->resample_buf)
        {
            ERROR("failed to allocate resample buffer for %d frames",
                    in->resample_frame_num);
            goto err_open;
        }

        DEBUG("resampler: frame num [%d] buf size [%d] bytes",
                in->resample_frame_num, resample_size);
    }

    /* initialize hsp specifics */
    private = &in->private;

    hsp_stream_private_init(private);

   /* set input config values */
   if (config)
   {
      config->format = get_format(&in->stream.in.common);
      config->sample_rate = get_sample_rate(&in->stream.in.common);
      config->channel_mask = get_channels(&in->stream.in.common);
   }

    hsp_dev->input = in;

    /* retry logic to catch any timing variations on control channel */
    for (i = 0; i < CTRL_CHAN_RETRY_COUNT; i++)
    {
        /* connect control channel if not already connected */
        if ((private->ctrl_fd = skt_connect(private, HSP_IN_CTRL_PATH)) > 0)
        {
            /* success, now check if stack is ready */
            if (check_hsp_ready(private) == 0)
                break;

            ERROR("error : hsp not ready, wait 250 ms and retry");
            usleep(CTRL_CHANNEL_RETRY_INTERVAL_US);
            skt_disconnect(&private->ctrl_fd);
        }

        /* ctrl channel not ready, wait a bit */
        usleep(CTRL_CHANNEL_RETRY_INTERVAL_US);
    }

    if (private->ctrl_fd == AUDIO_SKT_DISCONNECTED)
    {
        ERROR("ctrl socket failed to connect (%s)", strerror(errno));
        ret = -1;
        goto err_open;
    }

    DEBUG("success");
    return 0;

err_open:


if (in->resampler)
    release_resampler(in->resampler);

    free(in->resample_buf);

    free(in);
    hsp_dev->input = NULL;
    *stream_in = NULL;
    return ret;
}

static void adev_close_input_stream(struct audio_hw_device *dev,
                                   struct audio_stream_in *stream)
{
    struct hsp_stream *in = (struct hsp_stream *)stream;
    struct hsp_private *private = &in->private;
    struct hsp_audio_device *hsp_dev = (struct hsp_audio_device *)dev;

    FNLOG();

    pthread_mutex_lock(&private->lock);

    INFO("closing input (state %d)", private->state);

    if ((private->state == AUDIO_HSP_STATE_STARTED) || (private->state == AUDIO_HSP_STATE_STOPPING))
        stop_audio_datapath(private);

    skt_disconnect(&private->ctrl_fd);

    release_resampler(in->resampler);
    free(in->resample_buf);
    pthread_mutex_unlock(&private->lock);
    free(in);
    hsp_dev->input = NULL;

    DEBUG("done");
    return;
}

static int adev_dump(const audio_hw_device_t *device, int fd)
{
    FNLOG();

    return 0;
}

static int adev_close(hw_device_t *device)
{
    FNLOG();

    free(device);
    return 0;
}

static int adev_open(const hw_module_t* module, const char* name,
                     hw_device_t** device)
{
    struct hsp_audio_device *adev;
    int ret;

    INFO(" adev_open in Hsp_hw module ");
    FNLOG();

    if (strcmp(name, AUDIO_HARDWARE_INTERFACE) != 0)
    {
        ERROR("interface %s not matching [%s]", name, AUDIO_HARDWARE_INTERFACE);
        return -EINVAL;
    }

    adev = calloc(1, sizeof(struct hsp_audio_device));

    if (!adev)
        return -ENOMEM;

    adev->device.common.tag = HARDWARE_DEVICE_TAG;
    adev->device.common.version = AUDIO_DEVICE_API_VERSION_CURRENT;
    adev->device.common.module = (struct hw_module_t *) module;
    adev->device.common.close = adev_close;

    adev->device.init_check = adev_init_check;
    adev->device.set_voice_volume = adev_set_voice_volume;
    adev->device.set_master_volume = adev_set_master_volume;
    adev->device.set_mode = adev_set_mode;
    adev->device.set_mic_mute = adev_set_mic_mute;
    adev->device.get_mic_mute = adev_get_mic_mute;
    adev->device.set_parameters = adev_set_parameters;
    adev->device.get_parameters = adev_get_parameters;
    adev->device.get_input_buffer_size = adev_get_input_buffer_size;
    adev->device.open_output_stream = adev_open_output_stream;
    adev->device.close_output_stream = adev_close_output_stream;
    adev->device.open_input_stream = adev_open_input_stream;
    adev->device.close_input_stream = adev_close_input_stream;
    adev->device.dump = adev_dump;

    adev->output = NULL;
    adev->input = NULL;

    *device = &adev->device.common;

    return 0;
}

static struct hw_module_methods_t hal_module_methods = {
    .open = adev_open,
};

struct audio_module HAL_MODULE_INFO_SYM = {
    .common = {
        .tag = HARDWARE_MODULE_TAG,
        .version_major = 1,
        .version_minor = 0,
        .id = AUDIO_HARDWARE_MODULE_ID,
        .name = "HSP Audio HW HAL",
        .author = "The Android Open Source Project",
        .methods = &hal_module_methods,
    },
};
