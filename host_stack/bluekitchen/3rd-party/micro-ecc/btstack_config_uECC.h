// Configuration of micro-ecc for use with BTstack
//
// We only need/use SECP256R1 for LE Secure Connections


#ifndef BTSATCK_CONFIG_UECC_H__
#define BTSATCK_CONFIG_UECC_H__

#define uECC_CURVE uECC_secp256r1
#define uECC_NO_DEFAULT_RNG

// optimization: size vs. speed: uECC_asm_none - uECC_asm_small - uECC_asm_fast
#ifndef uECC_ASM
#define uECC_ASM uECC_asm_none
#endif

// don't use special square functions
#ifndef uECC_SQUARE_FUNC
#define uECC_SQUARE_FUNC 0
#endif

#endif
