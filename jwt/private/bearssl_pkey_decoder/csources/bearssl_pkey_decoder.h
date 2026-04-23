#include <bearssl_x509.h>

/**
 * \brief Public key decoder context.
 *
 * The public key decoder recognises RSA and EC private keys, either in
 * their raw, DER-encoded format, or wrapped in an unencrypted PKCS#8
 * archive (again DER-encoded).
 *
 * Structure contents are opaque and shall not be accessed directly.
 */
typedef struct {
#ifndef BR_DOXYGEN_IGNORE
	/* Structure for returning the private key. */
	union {
		br_rsa_public_key rsa;
		br_ec_public_key ec;
	} key;

	/* CPU for the T0 virtual machine. */
	struct {
		uint32_t *dp;
		uint32_t *rp;
		const unsigned char *ip;
	} cpu;
	uint32_t dp_stack[32];
	uint32_t rp_stack[32];
	int err;

	/* Private key data chunk. */
	const unsigned char *hbuf;
	size_t hlen;

	/* The pad serves as destination for various operations. */
	unsigned char pad[256];

	/* Decoded key type; 0 until decoding is complete. */
	unsigned char key_type;

	/* Buffer for the private key elements. It shall be large enough
	   to accommodate all elements for a RSA-4096 private key (roughly
	   five 2048-bit integers, possibly a bit more). */
	unsigned char key_data[3 * BR_X509_BUFSIZE_SIG];
#endif
} br_pkey_decoder_context;


/**
 * \brief Initialise a public key decoder context.
 *
 * \param ctx   key decoder context to initialise.
 */
void br_pkey_decoder_init(br_pkey_decoder_context *ctx);

/**
 * \brief Push some data bytes into a public key decoder context.
 *
 * If `len` is non-zero, then that many data bytes, starting at address
 * `data`, are pushed into the decoder.
 *
 * \param ctx    key decoder context.
 * \param data   private key data chunk.
 * \param len    private key data chunk length (in bytes).
 */
void br_pkey_decoder_push(br_pkey_decoder_context *ctx,
	const void *data, size_t len);

/**
 * \brief Get the decoding status for a public key.
 *
 * Decoding status is 0 on success, or a non-zero error code. If the
 * decoding is unfinished when this function is called, then the
 * status code `BR_ERR_X509_TRUNCATED` is returned.
 *
 * \param ctx   key decoder context.
 * \return  0 on successful decoding, or a non-zero error code.
 */
static inline int
br_pkey_decoder_last_error(const br_pkey_decoder_context *ctx)
{
	if (ctx->err != 0) {
		return ctx->err;
	}
	if (ctx->key_type == 0) {
		return BR_ERR_X509_TRUNCATED;
	}
	return 0;
}

/**
 * \brief Get the decoded public key type.
 *
 * Public key type is `BR_KEYTYPE_RSA` or `BR_KEYTYPE_EC`. If decoding is
 * not finished or failed, then 0 is returned.
 *
 * \param ctx   key decoder context.
 * \return  decoded private key type, or 0.
 */
static inline int
br_pkey_decoder_key_type(const br_pkey_decoder_context *ctx)
{
	if (ctx->err == 0) {
		return ctx->key_type;
	} else {
		return 0;
	}
}

/**
 * \brief Get the decoded RSA public key.
 *
 * This function returns `NULL` if the decoding failed, or is not
 * finished, or the key is not RSA. The returned pointer references
 * structures within the context that can become invalid if the context
 * is reused or released.
 *
 * \param ctx   key decoder context.
 * \return  decoded RSA public key, or `NULL`.
 */
static inline const br_rsa_public_key *
br_pkey_decoder_get_rsa(const br_pkey_decoder_context *ctx)
{
	if (ctx->err == 0 && ctx->key_type == BR_KEYTYPE_RSA) {
		return &ctx->key.rsa;
	} else {
		return NULL;
	}
}

/**
 * \brief Get the decoded EC private key.
 *
 * This function returns `NULL` if the decoding failed, or is not
 * finished, or the key is not EC. The returned pointer references
 * structures within the context that can become invalid if the context
 * is reused or released.
 *
 * \param ctx   key decoder context.
 * \return  decoded EC private key, or `NULL`.
 */
static inline const br_ec_public_key *
br_pkey_decoder_get_ec(const br_pkey_decoder_context *ctx)
{
	if (ctx->err == 0 && ctx->key_type == BR_KEYTYPE_EC) {
		return &ctx->key.ec;
	} else {
		return NULL;
	}
}
