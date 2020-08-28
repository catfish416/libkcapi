#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "kcapi.h"


static int bin_char(u_int8_t hex)
{
	if (48 <= hex && 57 >= hex)
		return (hex - 48);
	if (65 <= hex && 70 >= hex)
		return (hex - 55);
	if (97 <= hex && 102 >= hex)
		return (hex - 87);
	return 0;
}

static void hex2bin(const char *hex, u_int32_t hexlen,
		    u_int8_t *bin, u_int32_t binlen)
{
	u_int32_t i = 0;
	u_int32_t chars = (binlen > (hexlen / 2)) ? (hexlen / 2) : binlen;

	for (i = 0; i < chars; i++) {
		bin[i] = bin_char(hex[(i*2)]) << 4;
		bin[i] |= bin_char(hex[((i*2)+1)]);
	}
}

static char hex_char_map_l[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				 '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
static char hex_char_map_u[] = { '0', '1', '2', '3', '4', '5', '6', '7',
				 '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
static char hex_char(u_int32_t bin, int u)
{
	if (bin < sizeof(hex_char_map_l))
		return (u) ? hex_char_map_u[bin] : hex_char_map_l[bin];
	return 'X';
}

static void bin2hex(const u_int8_t *bin, u_int32_t binlen,
		    char *hex, u_int32_t hexlen, int u)
{
	u_int32_t i = 0;
	u_int32_t chars = (binlen > (hexlen / 2)) ? (hexlen / 2) : binlen;

	for (i = 0; i < chars; i++) {
		hex[(i*2)] = hex_char((bin[i] >> 4), u);
		hex[((i*2)+1)] = hex_char((bin[i] & 0x0f), u);
	}
}

static void bin2print(const u_int8_t *bin, u_int32_t binlen)
{
	char *hex;
	u_int32_t hexlen = binlen * 2 + 1;

	hex = calloc(1, hexlen);
	if (!hex)
		return;
	bin2hex(bin, binlen, hex, hexlen - 1 , 0);
	fprintf(stdout, "%s", hex);
	printf("\n");
	free(hex);
}

#define KEY_LEN     32
#define KEYBIN_LEN		(KEY_LEN/2)
#define INPUT_LEN   32
#define INPUTBIN_LEN 	(INPUT_LEN/2)
#define OUTPUT_LEN  32
#define OUTPUTBIN_LEN 	(OUTPUT_LEN/2)

void test_cmac_aes128()
{
	u_int8_t key_bin[KEYBIN_LEN];
	u_int8_t input_bin[INPUTBIN_LEN];
    u_int8_t output_bin[OUTPUTBIN_LEN];

	memset(key_bin, 0, KEYBIN_LEN);
	memset(input_bin, 0xFF, INPUTBIN_LEN);
	memset(output_bin, 0, OUTPUTBIN_LEN);

	int rc = kcapi_md_cmac_aes128(key_bin, KEYBIN_LEN, input_bin, INPUTBIN_LEN, output_bin, OUTPUTBIN_LEN);

	printf("key: \n");
	bin2print(key_bin, KEYBIN_LEN);
	printf("input: \n");
	bin2print(input_bin, INPUTBIN_LEN);
	printf("output: \n");
	bin2print(output_bin, rc);
}

#define RNG_OUT_LEN 	128
#define BITS_PER_BYTE 	8

void test_rng_128()
{
	uint8_t out[RNG_OUT_LEN/BITS_PER_BYTE];
	int32_t ret;

	memset(out, 0, sizeof(out));
	printf("BYTES: %d\n", sizeof(out));

	ret = kcapi_rng_get_bytes(out, sizeof(out));
	if (ret != sizeof(out)) {
		printf("Random number generation error");
		return;
	}

	bin2print(out, sizeof(out));
	printf("Random number generation success!\n");

	return;
}

int main()
{
//	test_cmac_aes128();

	test_rng_128();

	return 0;
}
