#pragma once

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    ACT_AUTH_TRACKER_SAFETY = 0,
    ACT_AUTH_OWNER_ENROLLED = 1,
} act_auth_t;

typedef enum {
    ACT_PROTO_AUTO   = 0,
    ACT_PROTO_DULT   = 1,
    ACT_PROTO_FINDMY = 2,
    ACT_PROTO_AIRTAG = 3,
} act_proto_t;

typedef enum {
    ACT_CMD_SOUND_START = 0,
    ACT_CMD_SOUND_STOP  = 1,
} act_cmd_t;

typedef enum {
    ACT_RESULT_NONE = 0,
    ACT_RESULT_SUCCEEDED,
    ACT_RESULT_REJECTED,
    ACT_RESULT_UNSUPPORTED,
    ACT_RESULT_TIMED_OUT,
    ACT_RESULT_TRANSPORT_ERROR,
    ACT_RESULT_CANCELLED,
} act_result_t;

typedef struct {
    uint8_t  mac[6];
    uint8_t  addr_type;
    uint8_t  proto_hint;
    char     name[32];
    uint32_t captured_seq;
} act_target_t;

typedef struct {
    const char *id;
    act_result_t (*run)(const act_target_t *t, act_cmd_t cmd, uint32_t deadline_ms);
} act_driver_t;

void action_sched_init(void);
void action_sched_register(const act_driver_t *drv);

void action_sched_set_radio_hooks(void (*pause)(void), void (*resume)(void));

bool action_sched_submit(const act_target_t *t, act_cmd_t cmd);

void action_sched_cancel(void);

void action_sched_service(bool armed);

bool action_sched_busy(void);

int  action_sched_status_json(char *buf, int cap);
