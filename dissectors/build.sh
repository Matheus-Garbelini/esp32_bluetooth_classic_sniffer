#!/usr/bin/env bash

PLUGIN_VERSION=2.0.0
WIRESHARK_INCLUDES=$(pkg-config wireshark --cflags-only-I)

mkdir -p build

clang-11 -DG_DISABLE_DEPRECATED -DG_DISABLE_SINGLE_INCLUDES -DHAVE_PLUGINS -DPLUGIN_VERSION=\"$PLUGIN_VERSION\" \
-Dh4bcm_EXPORTS $WIRESHARK_INCLUDES -I. -fvisibility=hidden  -Qunused-arguments \
-Wall -Wextra -Wendif-labels -Wpointer-arith -Wformat-security -fwrapv -fno-strict-overflow -Wvla -Waddress \
-Wattributes -Wdiv-by-zero -Wignored-qualifiers -Wpragmas -Wno-overlength-strings -Wno-long-long -Wheader-guard \
-Wcomma -Wshorten-64-to-32 -Wframe-larger-than=32768 -Wc++-compat -Wunused-const-variable -Wshadow -Wold-style-definition \
-Wstrict-prototypes -Werror=implicit -Wno-pointer-sign -std=gnu99 -fno-stack-protector -fpic -Wall -Wno-braced-scalar-init \
-Wno-unused-variable -Wno-reorder -O2 -g -DNDEBUG -fPIC -fcolor-diagnostics -w -std=gnu11 -Werror \
-o build/packet-h4bcm.c.o -c packet-h4bcm.c

clang-11 -DG_DISABLE_DEPRECATED -DG_DISABLE_SINGLE_INCLUDES -DHAVE_PLUGINS -DPLUGIN_VERSION=\"$PLUGIN_VERSION\" \
-Dh4bcm_EXPORTS $WIRESHARK_INCLUDES -I. -fvisibility=hidden  -Qunused-arguments \
-Wall -Wextra -Wendif-labels -Wpointer-arith -Wformat-security -fwrapv -fno-strict-overflow -Wvla -Waddress \
-Wattributes -Wdiv-by-zero -Wignored-qualifiers -Wpragmas -Wno-overlength-strings -Wno-long-long -Wheader-guard \
-Wcomma -Wshorten-64-to-32 -Wframe-larger-than=32768 -Wc++-compat -Wunused-const-variable -Wshadow -Wold-style-definition \
-Wstrict-prototypes -Werror=implicit -Wno-pointer-sign -std=gnu99 -fno-stack-protector -fpic -Wall -Wno-braced-scalar-init \
-Wno-unused-variable -Wno-reorder -O2 -g -DNDEBUG -fPIC -fcolor-diagnostics -w -std=gnu11 -Werror \
-o build/packet-btbrlmp.c.o -c packet-btbrlmp.c

clang-11 -DG_DISABLE_DEPRECATED -DG_DISABLE_SINGLE_INCLUDES -DHAVE_PLUGINS -DPLUGIN_VERSION=\"$PLUGIN_VERSION\" \
-Dh4bcm_EXPORTS $WIRESHARK_INCLUDES -I. -fvisibility=hidden  -Qunused-arguments \
-Wall -Wextra -Wendif-labels -Wpointer-arith -Wformat-security -fwrapv -fno-strict-overflow -Wvla -Waddress \
-Wattributes -Wdiv-by-zero -Wignored-qualifiers -Wpragmas -Wno-overlength-strings -Wno-long-long -Wheader-guard \
-Wcomma -Wshorten-64-to-32 -Wframe-larger-than=32768 -Wc++-compat -Wunused-const-variable -Wshadow -Wold-style-definition \
-Wstrict-prototypes -Werror=implicit -Wno-pointer-sign -std=gnu99 -fno-stack-protector -fpic -Wall -Wno-braced-scalar-init \
-Wno-unused-variable -Wno-reorder -O2 -g -DNDEBUG -fPIC -fcolor-diagnostics -w -std=gnu11 -Werror \
-o build/plugin.c.o -c plugin.c


gcc --std=gnu11 -fPIC -w -O3 -shared -o h4bcm.so build/packet-btbrlmp.c.o build/packet-h4bcm.c.o build/plugin.c.o -lwireshark -lwiretap -lwsutil

# sudo cp h4bcm.so /usr/local/lib/wireshark/plugins/3.4/epan/ 
