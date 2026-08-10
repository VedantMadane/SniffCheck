#pragma once

#include <stdbool.h>
#include "cluster_proto.h"

void head_ui_init(void);

void head_ui_push_frame(const cl_uiframe_t *f);

void head_ui_fill_event(cl_uievent_t *out);

bool head_ui_linked(void);
