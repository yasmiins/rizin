#ifndef RZ_SEARCH_H
#define RZ_SEARCH_H

#include <rz_types.h>
#include <rz_util.h>
#include <rz_list.h>
#include <rz_io.h>

#ifdef __cplusplus
extern "C" {
#endif

RZ_LIB_VERSION_HEADER(rz_search);

typedef enum {
	RZ_SEARCH_ESIL,
	RZ_SEARCH_KEYWORD,
	RZ_SEARCH_REGEXP,
	RZ_SEARCH_PATTERN,
	RZ_SEARCH_STRING,
	RZ_SEARCH_XREFS,
	RZ_SEARCH_AES,
	RZ_SEARCH_PRIV_KEY,
	RZ_SEARCH_DELTAKEY,
	RZ_SEARCH_MAGIC,
	RZ_SEARCH_LAST
} RzSearchMode;

#define RZ_SEARCH_DISTANCE_MAX 10

#define RZ_SEARCH_KEYWORD_TYPE_BINARY 'i'
#define RZ_SEARCH_KEYWORD_TYPE_STRING 's'

typedef struct rz_search_keyword_t {
	ut8 *bin_keyword;
	ut8 *bin_binmask;
	ut32 keyword_length;
	ut32 binmask_length;
	void *data;
	int count;
	int kwidx;
	int icase; // ignore case
	int type;
	ut64 last; // last hit hint
} RzSearchKeyword;

typedef struct rz_search_hit_t {
	RzSearchKeyword *kw;
	ut64 addr;
} RzSearchHit;

typedef int (*RzSearchCallback)(RzSearchKeyword *kw, void *user, ut64 where);

struct rz_search_t;

typedef struct rz_search_params_t {
	RzList *boundaries;
	const char *cmd_hit; ///< cmd.hit
	RzInterval itv;
	ut32 pattern_size;
	RzSearchMode mode;

	bool aes_search;
	bool privkey_search;
	bool inverse;
	bool backwards;

	int search_align; ///< search.align
	bool search_contiguous; ///< search.contiguous
	int search_distance; ///< search.distance
	bool search_flags; ///< search.flags
	ut64 search_from; ///< search.from
	ut64 search_to; ///< search.to
	ut64 search_maxhits; ///< search.maxhits
	ut32 search_maxlength; ///< search.maxlength: max length of strings for RZ_SEARCH_STRING
	ut32 search_minlength; ///< search.minlength: min length of strings for RZ_SEARCH_STRING
	bool search_overlap; ///< search.overlap: whether two matches can overlap
	const char *search_prefix; ///< search.prefix
	bool search_show; ///< search.show

	RzList *kws; // TODO: Use rz_search_kw_new ()
	int n_kws; // hit${n_kws}_${count}
	RzIOBind iob;
	int (*update)(struct rz_search_t *s, ut64 from, const ut8 *buf, int len);
} RzSearchParams;

typedef struct rz_search_t {
	void *data; // data used by search algorithm
	void *user; // user data passed to callback
	RzSearchCallback callback;
	ut64 nhits;
	RzList /*<RzSearchHit>*/ *hits;
	RzSearchParams *params;
} RzSearch;

#ifdef RZ_API

#define RZ_SEARCH_AES_BOX_SIZE 31

RZ_API RzSearchParams *rz_search_params_new(RzSearchMode mode);
RZ_API void rz_search_params_free(RzSearchParams *params);
RZ_API RzSearch *rz_search_new(RZ_OWN RZ_NONNULL RzSearchParams *params);
RZ_API int rz_search_params_set_mode(RzSearchParams *params, RzSearchMode mode);
RZ_API RzSearch *rz_search_free(RzSearch *s);

/* keyword management */
RZ_API RzList /*<RzSearchHit *>*/ *rz_search_find(RzSearch *s, ut64 addr, const ut8 *buf, int len);
RZ_API int rz_search_update(RzSearch *s, ut64 from, const ut8 *buf, long len);
RZ_API int rz_search_update_i(RzSearch *s, ut64 from, const ut8 *buf, long len);

RZ_API void rz_search_keyword_free(RzSearchKeyword *kw);
RZ_API RzSearchKeyword *rz_search_keyword_new(const ut8 *kw, int kwlen, const ut8 *bm, int bmlen, const char *data);
RZ_API RzSearchKeyword *rz_search_keyword_new_str(const char *kw, const char *bm, const char *data, int icase);
RZ_API RzSearchKeyword *rz_search_keyword_new_wide(const char *kw, const char *bm, const char *data, int icase);
RZ_API RzSearchKeyword *rz_search_keyword_new_hex(const char *kwstr, const char *bmstr, const char *data);
RZ_API RzSearchKeyword *rz_search_keyword_new_hexmask(const char *kwstr, const char *data);
RZ_API RzSearchKeyword *rz_search_keyword_new_regexp(const char *str, const char *data);

RZ_API int rz_search_params_kw_add(RzSearchParams *params, RzSearchKeyword *kw);
RZ_API void rz_search_reset(RzSearch *s, int mode);
RZ_API void rz_search_kw_reset(RzSearch *s);
RZ_API void rz_search_params_string_prepare_backward(RzSearchParams *s);

// TODO: is this an internal API?
RZ_API int rz_search_mybinparse_update(RzSearch *s, ut64 from, const ut8 *buf, int len);
RZ_API int rz_search_aes_update(RzSearch *s, ut64 from, const ut8 *buf, int len);
RZ_API int rz_search_privkey_update(RzSearch *s, ut64 from, const ut8 *buf, int len);
RZ_API int rz_search_magic_update(RzSearch *_s, ut64 from, const ut8 *buf, int len);
RZ_API int rz_search_deltakey_update(RzSearch *s, ut64 from, const ut8 *buf, int len);
RZ_API int rz_search_strings_update(RzSearch *s, ut64 from, const ut8 *buf, int len);
RZ_API int rz_search_regexp_update(RzSearch *s, ut64 from, const ut8 *buf, int len);
// Returns 2 if search.maxhits is reached, 0 on error, otherwise 1
RZ_API int rz_search_hit_new(RzSearch *s, RzSearchKeyword *kw, ut64 addr);
RZ_API void rz_search_params_set_distance(RzSearchParams *params, int dist);
RZ_API int rz_search_strings(RzSearch *s, ut32 min, ut32 max);
RZ_API int rz_search_set_string_limits(RzSearch *s, ut32 min, ut32 max); // dup again?
// RZ_API int rz_search_set_callback(RzSearch *s, int (*callback)(struct rz_search_kw_t *, void *, ut64), void *user);
RZ_API void rz_search_set_callback(RzSearch *s, RzSearchCallback(callback), void *user);
RZ_API int rz_search_begin(RzSearch *s);

/* pattern search */
RZ_API void rz_search_pattern_size(RzSearch *s, int size);
RZ_API int rz_search_pattern(RzSearch *s, ut64 from, ut64 to);

#ifdef __cplusplus
}
#endif

#endif
#endif
