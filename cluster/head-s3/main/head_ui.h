#pragma once

#include <stdbool.h>
#include "cluster_proto.h"

#define HEAD_UI_PAGES 3

typedef void (*head_ui_page_fn)(int page, cl_uiframe_t *f);

void head_ui_init(head_ui_page_fn compose);

void head_ui_mark_dirty(void);
