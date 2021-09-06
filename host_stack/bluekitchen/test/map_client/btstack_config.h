//
// btstack_config.h for libusb port
//

#ifndef BTSTACK_CONFIG_H
#define BTSTACK_CONFIG_H

// Port related features
#define HAVE_BTSTACK_STDIN
#define HAVE_MALLOC
#define HAVE_POSIX_FILE_IO
#define HAVE_POSIX_TIME

// BTstack features that can be enabled
#define ENABLE_ATT_DELAYED_RESPONSE
#define ENABLE_BLE
#define ENABLE_CLASSIC
#define ENABLE_HFP_WIDE_BAND_SPEECH
#define ENABLE_LE_CENTRAL
#define ENABLE_LE_DATA_CHANNELS
#define ENABLE_LE_DATA_LENGTH_EXTENSION
#define ENABLE_LE_PERIPHERAL
#define ENABLE_LE_SECURE_CONNECTIONS
#define ENABLE_LOG_ERROR
#define ENABLE_LOG_INFO
#define ENABLE_MICRO_ECC_FOR_LE_SECURE_CONNECTIONS
#define ENABLE_PRINTF_HEXDUMP
#define ENABLE_SCO_OVER_HCI
#define ENABLE_SDP_DES_DUMP

#define ENABLE_L2CAP_ENHANCED_RETRANSMISSION_MODE

// BTstack configuration. buffers, sizes, ...
#define HCI_ACL_PAYLOAD_SIZE (1691 + 4)
#define HCI_INCOMING_PRE_BUFFER_SIZE 14 // sizeof BNEP header, avoid memcpy
#define NVM_NUM_DEVICE_DB_ENTRIES      20
#define NVM_NUM_LINK_KEYS 20

#endif
