/*
 * Do not modify this file. Changes will be overwritten.
 *
 * Generated automatically from /home/matheus/5g/wdissector/libs/wireshark/tools/make-plugin-reg.py.
 */

#include "config.h"

#include <gmodule.h>

/* plugins are DLLs */
#define WS_BUILD_DLL
#include "ws_symbol_export.h"

#include "epan/proto.h"

WS_DLL_PUBLIC void proto_register_btbrlmp(void);
WS_DLL_PUBLIC void proto_register_h4bcm(void);
WS_DLL_PUBLIC void proto_reg_handoff_btbrlmp(void);
WS_DLL_PUBLIC void proto_reg_handoff_h4bcm(void);

WS_DLL_PUBLIC const gchar plugin_version[] = PLUGIN_VERSION;
WS_DLL_PUBLIC const int plugin_want_major = VERSION_MAJOR;
WS_DLL_PUBLIC const int plugin_want_minor = VERSION_MINOR;

WS_DLL_PUBLIC void plugin_register(void);

void plugin_register(void)
{
    static proto_plugin plug_btbrlmp;

    plug_btbrlmp.register_protoinfo = proto_register_btbrlmp;
    plug_btbrlmp.register_handoff = proto_reg_handoff_btbrlmp;
    proto_register_plugin(&plug_btbrlmp);
    static proto_plugin plug_h4bcm;

    plug_h4bcm.register_protoinfo = proto_register_h4bcm;
    plug_h4bcm.register_handoff = proto_reg_handoff_h4bcm;
    proto_register_plugin(&plug_h4bcm);
}
