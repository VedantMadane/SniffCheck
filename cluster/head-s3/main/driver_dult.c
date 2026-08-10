#include "driver_dult.h"

#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "host/ble_gatt.h"
#include "host/ble_uuid.h"

static const char *TAG = "sc-dult";

static const ble_uuid128_t DULT_SVC = BLE_UUID128_INIT(
    0x85,0x2a,0x9f,0x57,0xc5,0x2a,0xed,0x88,0x26,0xc2,0xf4,0x12,0x01,0x00,0x19,0x15);

static const ble_uuid128_t DULT_CHR = BLE_UUID128_INIT(
    0x0e,0x68,0x21,0x74,0x37,0x48,0x61,0xbf,0x92,0xfb,0x68,0x1d,0x01,0x00,0x0c,0x8e);

static const ble_uuid16_t  FMN_SVC = BLE_UUID16_INIT(0xFD44);

static const ble_uuid128_t FMN_CHR = BLE_UUID128_INIT(
    0x7a,0x42,0x04,0x03,0x73,0x2f,0xd4,0xbe,0xef,0x49,0x3b,0x94,0x03,0x00,0x86,0x4f);

static const ble_uuid128_t AIRTAG_SVC = BLE_UUID128_INIT(
    0x6c,0xd6,0xf8,0x28,0x97,0x8d,0xaa,0x86,0x51,0x49,0x1c,0x7d,0x00,0x90,0xfc,0x7d);

static const uint8_t DULT_START[] = { 0x00, 0x03 };
static const uint8_t DULT_STOP[]  = { 0x01, 0x03 };
static const uint8_t FMN_START[]  = { 0x01, 0x00, 0x03 };
static const uint8_t FMN_STOP[]   = { 0x01, 0x01, 0x03 };

#define HCI_REMOTE_USER_TERM  0x13

typedef struct {
    act_target_t tgt;
    act_cmd_t    cmd;
    act_proto_t  proto;
    uint16_t     conn_handle;
    uint16_t     svc_start, svc_end;
    bool         found_svc;
    volatile bool done;
    volatile act_result_t res;
    SemaphoreHandle_t sem;
} dult_ctx_t;

static dult_ctx_t s_c;
static volatile bool s_busy;

static const ble_uuid_t *svc_uuid(act_proto_t p)
{
    switch (p) {
    case ACT_PROTO_DULT:   return &DULT_SVC.u;
    case ACT_PROTO_FINDMY: return &FMN_SVC.u;
    case ACT_PROTO_AIRTAG: return &AIRTAG_SVC.u;
    default:               return NULL;
    }
}
static const ble_uuid_t *chr_uuid(act_proto_t p)
{
    switch (p) {
    case ACT_PROTO_DULT:   return &DULT_CHR.u;
    case ACT_PROTO_FINDMY: return &FMN_CHR.u;
    default:               return NULL;
    }
}
static const uint8_t *opcode(act_proto_t p, act_cmd_t cmd, uint16_t *len)
{
    switch (p) {
    case ACT_PROTO_DULT:
        *len = 2; return cmd == ACT_CMD_SOUND_STOP ? DULT_STOP : DULT_START;
    case ACT_PROTO_FINDMY:
        *len = 3; return cmd == ACT_CMD_SOUND_STOP ? FMN_STOP : FMN_START;
    default:
        *len = 0; return NULL;
    }
}

static void finish(dult_ctx_t *c, act_result_t r)
{
    if (c->done) return;
    if (c->res == ACT_RESULT_NONE) c->res = r;
    c->done = true;
    xSemaphoreGive(c->sem);
}

static int write_cb(uint16_t ch, const struct ble_gatt_error *err,
                    struct ble_gatt_attr *attr, void *arg)
{
    (void)ch; (void)attr;
    dult_ctx_t *c = arg;
    c->res = (err && err->status == 0) ? ACT_RESULT_SUCCEEDED : ACT_RESULT_TRANSPORT_ERROR;
    ble_gap_terminate(c->conn_handle, HCI_REMOTE_USER_TERM);
    finish(c, c->res);
    return 0;
}

static int chr_cb(uint16_t ch, const struct ble_gatt_error *err,
                  const struct ble_gatt_chr *chr, void *arg)
{
    dult_ctx_t *c = arg;
    if (err && err->status == 0 && chr) {
        uint16_t len; const uint8_t *op = opcode(c->proto, c->cmd, &len);
        if (!op) { finish(c, ACT_RESULT_UNSUPPORTED); ble_gap_terminate(c->conn_handle, HCI_REMOTE_USER_TERM); return 0; }
        if (ble_gattc_write_flat(c->conn_handle, chr->val_handle, op, len, write_cb, c) != 0) {
            finish(c, ACT_RESULT_TRANSPORT_ERROR);
            ble_gap_terminate(c->conn_handle, HCI_REMOTE_USER_TERM);
        }
        return 0;
    }
    if (err && err->status == BLE_HS_EDONE) {
        finish(c, ACT_RESULT_UNSUPPORTED);
        ble_gap_terminate(c->conn_handle, HCI_REMOTE_USER_TERM);
    }
    return 0;
}

static int svc_cb(uint16_t ch, const struct ble_gatt_error *err,
                  const struct ble_gatt_svc *svc, void *arg)
{
    dult_ctx_t *c = arg;
    if (err && err->status == 0 && svc) {
        c->svc_start = svc->start_handle;
        c->svc_end   = svc->end_handle;
        c->found_svc = true;
        return 0;
    }
    if (err && err->status == BLE_HS_EDONE) {
        if (!c->found_svc) {
            finish(c, ACT_RESULT_UNSUPPORTED);
            ble_gap_terminate(c->conn_handle, HCI_REMOTE_USER_TERM);
        } else {
            ble_gattc_disc_chrs_by_uuid(c->conn_handle, c->svc_start, c->svc_end,
                                        chr_uuid(c->proto), chr_cb, c);
        }
        return 0;
    }
    finish(c, ACT_RESULT_TRANSPORT_ERROR);
    ble_gap_terminate(c->conn_handle, HCI_REMOTE_USER_TERM);
    return 0;
}

static int gap_cb(struct ble_gap_event *ev, void *arg)
{
    dult_ctx_t *c = arg;
    switch (ev->type) {
    case BLE_GAP_EVENT_CONNECT:
        if (ev->connect.status == 0) {
            c->conn_handle = ev->connect.conn_handle;
            const ble_uuid_t *svc = svc_uuid(c->proto);
            if (!svc) { finish(c, ACT_RESULT_UNSUPPORTED); ble_gap_terminate(c->conn_handle, HCI_REMOTE_USER_TERM); break; }
            if (ble_gattc_disc_svc_by_uuid(c->conn_handle, svc, svc_cb, c) != 0) {
                finish(c, ACT_RESULT_TRANSPORT_ERROR);
                ble_gap_terminate(c->conn_handle, HCI_REMOTE_USER_TERM);
            }
        } else {
            finish(c, ACT_RESULT_TRANSPORT_ERROR);
        }
        break;
    case BLE_GAP_EVENT_DISCONNECT:
        finish(c, ACT_RESULT_TRANSPORT_ERROR);
        break;

    case BLE_GAP_EVENT_ENC_CHANGE:
    case BLE_GAP_EVENT_PASSKEY_ACTION:
        c->res = ACT_RESULT_REJECTED;
        ble_gap_terminate(c->conn_handle, HCI_REMOTE_USER_TERM);
        finish(c, ACT_RESULT_REJECTED);
        break;
    case BLE_GAP_EVENT_REPEAT_PAIRING:
        return BLE_GAP_REPEAT_PAIRING_IGNORE;
    default:
        break;
    }
    return 0;
}

static act_result_t dult_run(const act_target_t *t, act_cmd_t cmd, uint32_t deadline_ms)
{
    if (s_busy) return ACT_RESULT_TRANSPORT_ERROR;

    act_proto_t proto = (t->proto_hint == ACT_PROTO_AUTO) ? ACT_PROTO_DULT
                                                          : (act_proto_t)t->proto_hint;
    if (proto == ACT_PROTO_AIRTAG) {
        ESP_LOGW(TAG, "AirTag proprietary sound payload not sourced — unsupported");
        return ACT_RESULT_UNSUPPORTED;
    }

    memset(&s_c, 0, sizeof s_c);
    s_c.tgt = *t;
    s_c.cmd = cmd;
    s_c.proto = proto;
    s_c.res = ACT_RESULT_NONE;
    if (!s_c.sem) s_c.sem = xSemaphoreCreateBinary();
    if (!s_c.sem) return ACT_RESULT_TRANSPORT_ERROR;
    xSemaphoreTake(s_c.sem, 0);

    ble_addr_t peer;
    peer.type = t->addr_type;
    for (int i = 0; i < 6; i++) peer.val[i] = t->mac[5 - i];

    uint8_t own_type;
    if (ble_hs_id_infer_auto(0, &own_type) != 0) return ACT_RESULT_TRANSPORT_ERROR;

    s_busy = true;
    ble_gap_disc_cancel();
    int rc = ble_gap_connect(own_type, &peer, (int32_t)deadline_ms, NULL, gap_cb, &s_c);
    if (rc != 0) {
        ESP_LOGW(TAG, "ble_gap_connect: %d", rc);
        s_busy = false;
        return ACT_RESULT_TRANSPORT_ERROR;
    }

    if (xSemaphoreTake(s_c.sem, pdMS_TO_TICKS(deadline_ms + 750)) != pdTRUE) {
        ble_gap_terminate(s_c.conn_handle, HCI_REMOTE_USER_TERM);
        s_c.res = ACT_RESULT_TIMED_OUT;
    }
    s_busy = false;
    return s_c.res == ACT_RESULT_NONE ? ACT_RESULT_TRANSPORT_ERROR : s_c.res;
}

const act_driver_t driver_dult = {
    .id  = "dult",
    .run = dult_run,
};
