#pragma once

#include "cluster_proto.h"

void cl_ui_draw(const cl_uiframe_t *f);

int cl_ui_draw_diff(const cl_uiframe_t *now, const cl_uiframe_t *prev, int have_prev);

void cl_ui_frame_reset(cl_uiframe_t *f, uint8_t screen, const char *title,
                       const char *hint);
void cl_ui_frame_item(cl_uiframe_t *f, const char *text);
void cl_ui_frame_extra(cl_uiframe_t *f, const char *text, int ok);
