/* apbpatch
 *
 * Copyright (c) 2021 black-sliver
 *
 * bsdiff portion based on bspatch.c by Colin Percival
 * see README.md and LICENSE for more information
 */

#define JSMN_STATIC
#define JSMN_PARENT_LINKS
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <stdbool.h>
#include <lzma.h>
#include <yaml.h>
#include <bzlib.h>
#include <md5.h>
#include <miniz.h>
#include <jsmn.h>
#include "b64.h"

#ifdef __EMSCRIPTEN__
#include <emscripten.h>
#else
#define EMSCRIPTEN_KEEPALIVE static
#endif


#define APPNAME "apbpatch"
#define VERSION "0.3.5"


static bool
xz_init(lzma_stream *strm)
{
	lzma_ret ret = lzma_stream_decoder(
			strm, UINT64_MAX, LZMA_CONCATENATED);

	// Return successfully if the initialization went fine.
	if (ret == LZMA_OK)
		return true;

	const char *msg;
	switch (ret) {
	case LZMA_MEM_ERROR:
		msg = "Memory allocation failed";
		break;

	case LZMA_OPTIONS_ERROR:
		msg = "Unsupported decompressor flags";
		break;

	default:
		msg = "Unknown error, possibly a bug";
		break;
	}

	fprintf(stderr, "Error initializing the decoder: %s (error code %u)\n",
			msg, ret);
	return false;
}

static bool
xz_decompress(lzma_stream *strm, const char *inname, FILE *infile, uint8_t **out, size_t *outsize)
{
	lzma_action action = LZMA_RUN;

	uint8_t inbuf[BUFSIZ];
	uint8_t outbuf[BUFSIZ];

	strm->next_in = NULL;
	strm->avail_in = 0;
	strm->next_out = outbuf;
	strm->avail_out = sizeof(outbuf);

	while (true) {
		if (strm->avail_in == 0 && !feof(infile)) {
			strm->next_in = inbuf;
			strm->avail_in = fread(inbuf, 1, sizeof(inbuf),
					infile);

			if (ferror(infile)) {
				fprintf(stderr, "%s: Read error: %s\n",
						inname, strerror(errno));
				return false;
			}

			if (feof(infile))
				action = LZMA_FINISH;
		}

		lzma_ret ret = lzma_code(strm, action);

		if (strm->avail_out == 0 || ret == LZMA_STREAM_END) {
			size_t write_size = sizeof(outbuf) - strm->avail_out;
            
            size_t pos = *outsize;
            *outsize = pos + write_size;
            *out = (uint8_t*)realloc(*out, *outsize);
			if (!*out) {
				fprintf(stderr, "Write error: %s\n",
						strerror(errno));
				return false;
			}
			memcpy((*out) + pos, outbuf, write_size);

			strm->next_out = outbuf;
			strm->avail_out = sizeof(outbuf);
		}

		if (ret != LZMA_OK) {
			if (ret == LZMA_STREAM_END)
				return true;

			const char *msg;
			switch (ret) {
			case LZMA_MEM_ERROR:
				msg = "Memory allocation failed";
				break;

			case LZMA_FORMAT_ERROR:
				// .xz magic bytes weren't found.
				msg = "The input is not in the .xz format";
				break;

			case LZMA_OPTIONS_ERROR:
				msg = "Unsupported compression options";
				break;

			case LZMA_DATA_ERROR:
				msg = "Compressed file is corrupt";
				break;

			case LZMA_BUF_ERROR:
				msg = "Compressed file is truncated or "
						"otherwise corrupt";
				break;

			default:
				// This is most likely LZMA_PROG_ERROR.
				msg = "Unknown error";
				break;
			}

			fprintf(stderr, "%s: Decoder error: "
					"%s (error code %u)\n",
					inname, msg, ret);
			return false;
		}
	}
}

static bool json_is(const char *json, jsmntok_t *tok, const char *s) {
    if (tok->type == JSMN_STRING && (int)strlen(s) == tok->end - tok->start &&
            strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
        return true;
    }
    return false;
}

static char* json_strdup(const char *json, jsmntok_t *tok) {
    if (tok->type != JSMN_STRING) {
        return NULL;
    }
    return strndup(json + tok->start, tok->end - tok->start);
}

static long json_long(const char *json, jsmntok_t *tok, bool* ok) {
    if (tok->type != JSMN_PRIMITIVE || json[tok->start] == 't' || json[tok->start] == 'f' || json[tok->start] == 'n') {
        if (ok) *ok = false;
        return 0;
    }
    if (ok) *ok = true;
    return strtol(json + tok->start, NULL, 10);
}

static bool read_patch_v3(FILE *fpatch, uint8_t **ppatch_data, size_t *ppatch_data_len,
                          char **pgame, char **pchecksum, char **pfileext)
{
    lzma_stream lzma = LZMA_STREAM_INIT;
    int res = 0;
    char *yaml = NULL;
    size_t yaml_size = 0;
    yaml_parser_t parser;
    yaml_token_t  token;
    int level=0;
    yaml_token_type_t last_token = YAML_NO_TOKEN;
    char *last_key = NULL;
    char *tag_suffix = NULL;
    uint8_t *patch_data = NULL;
    size_t patch_data_len = 0;

    if (pfileext) *pfileext = NULL;
    if (pchecksum) *pchecksum = NULL;
    if (pgame) *pgame = NULL;
    if (ppatch_data) *ppatch_data = NULL;
    if (ppatch_data_len) *ppatch_data_len = 0;

    /* read and decompress apbp */
    yaml = NULL;
    yaml_size = 0;
    if (!xz_init(&lzma)) goto lzma_init_error;
    if (!xz_decompress(&lzma, "apbp", fpatch, (uint8_t**)(&yaml), &yaml_size)) goto lzma_decompress_error;
    if (!yaml) goto yaml_malloc_error;
    yaml = (char*)realloc(yaml, yaml_size+1);
    if (!yaml) goto yaml_malloc_error;
    yaml[yaml_size] = 0; // nul terminate

    /* parse yaml. NOTE: we don't care about most of it, so this may look dirty */
    if(!yaml_parser_initialize(&parser)) {
        fprintf(stderr, "Failed to initialize yaml parser!\n");
        goto yaml_init_error;
    }
    yaml_parser_set_input_string(&parser, (uint8_t*)yaml, yaml_size);
    do {
        if (!yaml_parser_scan(&parser, &token)) {
            fprintf(stderr, "Invalid yaml!\n");
            goto yaml_parse_error;
        }
        switch(token.type)
        {
        case YAML_BLOCK_MAPPING_START_TOKEN:
        case YAML_FLOW_MAPPING_START_TOKEN:
            level++;
            break;
        case YAML_BLOCK_END_TOKEN:
        case YAML_FLOW_MAPPING_END_TOKEN:
            level--;
            break;
        case YAML_SCALAR_TOKEN:
            if (last_token == YAML_KEY_TOKEN) {
                free(last_key);
                last_key = strdup((const char*)token.data.scalar.value);
            }
            else if (last_token == YAML_VALUE_TOKEN) {
                if (level==1 && last_key && strcmp(last_key, "patch")==0 && tag_suffix && strcmp(tag_suffix, "binary")==0) {
                    const char *val = (const char*)token.data.scalar.value;
                    patch_data_len = b64_decoded_size(val);
                    patch_data = (uint8_t*)malloc(patch_data_len);
                    if (!b64_decode(val, patch_data, patch_data_len)) {
                        fprintf(stderr, "Error decoding b64 patch data!\n");
                        patch_data_len = 0;
                    }
                }
                else if (level==1 && last_key && strcmp(last_key, "game")==0 && !tag_suffix) {
                    if (pgame) *pgame = strdup((const char*)token.data.scalar.value);
                }
                else if (level==1 && last_key && strcmp(last_key, "base_checksum")==0 && !tag_suffix) {
                    if (pchecksum) *pchecksum = strdup((const char*)token.data.scalar.value);
                }
                free(tag_suffix);
                tag_suffix = NULL;
            }
            break;
        case YAML_TAG_TOKEN:
            free(tag_suffix);
            tag_suffix = strdup((const char*)token.data.tag.suffix);
            token.type = last_token; /* ignore tag for flow*/
            break;
        default:
            break;
        }
        last_token = token.type;
        yaml_token_delete(&token);
    } while(last_token != YAML_STREAM_END_TOKEN);
    yaml_parser_delete(&parser);
    free(tag_suffix);
    free(last_key);
    free(yaml);

    if (!patch_data || !patch_data_len) {
        fprintf(stderr, "No patch data in apbp!\n");
        free(patch_data);
        if (pgame) free(*pgame);
        return false;
    }

    if (pfileext) *pfileext = strdup(".sfc"); /* v3 is snes-only */
    if (ppatch_data) *ppatch_data = patch_data;
    else free(patch_data);
    if (ppatch_data_len) *ppatch_data_len = patch_data_len;

    return true;

yaml_parse_error:
    yaml_parser_delete(&parser);
    free(patch_data);
    if (pgame) free(*pgame);
    free(tag_suffix);
    free(last_key);
yaml_init_error:
    free(yaml);
    return false;
lzma_decompress_error:
    free(yaml);
lzma_init_error:
yaml_malloc_error:
fopen_error:
    return false;
}

static bool read_patch_v4(FILE *fpatch, uint8_t **ppatch_data, size_t *ppatch_data_len,
                          char **pgame, char **pchecksum, char **pfileext)
{
    int i, r;
    mz_bool status;
    mz_zip_archive zip_archive;
    char *json = NULL;
    size_t json_size = 0;
    jsmn_parser j;
    jsmntok_t t[128]; // arbitrary json token limit
    int t_count = sizeof(t) / sizeof(t[0]);

    if (pfileext) *pfileext = NULL;
    if (pchecksum) *pchecksum = NULL;
    if (pgame) *pgame = NULL;
    if (ppatch_data) *ppatch_data = NULL;
    if (ppatch_data_len) *ppatch_data_len = 0;

    mz_zip_zero_struct(&zip_archive);
    status = mz_zip_reader_init_cfile(&zip_archive, fpatch, 0, 0);
    if (!status) {
        fprintf(stderr, "Error reading zip: %s!\n", mz_zip_get_error_string(mz_zip_peek_last_error(&zip_archive)));
        return false;
    }

    json = (char*)mz_zip_reader_extract_file_to_heap(&zip_archive, "archipelago.json", &json_size, 0);
    if (!json) {
        fprintf(stderr, "Could not read archipelago.json from zip: %s!\n",
                mz_zip_get_error_string(mz_zip_peek_last_error(&zip_archive)));
        goto data_error;
    }

    jsmn_init(&j);
    r = jsmn_parse(&j, json, json_size, t, t_count);
    if (r == JSMN_ERROR_NOMEM) {
        fprintf(stderr, "archipelago.json longer than expected!\n");
        goto data_error;
    } else if (r<0 || t[0].type != JSMN_OBJECT) {
        fprintf(stderr, "Could not parse archipelago.json (%d)!\n", r);
        goto data_error;
    }

    for (i = 1; i < r; i++) {
        /* iterate over root object */
        if (json_is(json, &t[i], "game") && pgame) {
            *pgame = json_strdup(json, &t[i+1]);
            if (!*pgame) {
                fprintf(stderr, "\"game\" not a string!\n");
                goto data_error;
            }
        } else if (json_is(json, &t[i], "base_checksum") && pchecksum) {
            *pchecksum = json_strdup(json, &t[i+1]);
            if (!*pchecksum) {
                fprintf(stderr, "\"base_checksum\" not a string!\n");
                goto data_error;
            }
        } else if (json_is(json, &t[i], "compatible_version")) {
            long compatible_version = json_long(json, &t[i+1], NULL);
            /* version 4 and 5 are fully compatible from our PoV */
            if (compatible_version < 4 || compatible_version > 5) {
                fprintf(stderr, "Incompatible apbp version %ld\n", compatible_version);
                goto data_error;
            }
        } else if (json_is(json, &t[i], "result_file_ending") && pfileext) {
            *pfileext = json_strdup(json, &t[i+1]);
            if (!*pfileext) {
                fprintf(stderr, "\"result_file_ending\" not a string!\n");
                goto data_error;
            }
        }
        /* skip to the next key in root */
        while (i < r - 1 && t[i+1].parent != 0) i++;
    }

    if (ppatch_data && ppatch_data_len) {
        *ppatch_data = (uint8_t*)mz_zip_reader_extract_file_to_heap(&zip_archive, "delta.bsdiff4", ppatch_data_len, 0);
        if (!*ppatch_data) {
            fprintf(stderr, "Could not read delta.bsdiff4 from zip: %s!\n",
                    mz_zip_get_error_string(mz_zip_peek_last_error(&zip_archive)));
            goto data_error;
        }
    }

    free(json);
    mz_zip_reader_end(&zip_archive);
    return true;

data_error:
    free(json);
    mz_zip_reader_end(&zip_archive);
    if (pgame) free(*pgame);
    if (pchecksum) free(*pchecksum);
    if (pfileext) free(*pfileext);
    return false;
}

static bool read_patch(const char *patchfile, uint8_t **ppatch_data, size_t *ppatch_data_len,
                       char **pgame, char **pchecksum, char **pfileext)
{
    bool res = false;
    /* open patch file and read header/magic sequence */
    FILE *fpatch = fopen(patchfile, "rb");
    uint8_t magic[6];
    if (!fpatch) {
        fprintf(stderr, "Could not open patchfile!\n");
        goto fopen_error;
    }
    if (fread(magic, 1, sizeof(magic), fpatch) != sizeof(magic)) {
        fprintf(stderr, "Could not read patchfile!\n");
        goto fread_error;
    }
    rewind(fpatch);

    /* if the patch file is a zip file, it's v4 or newer */
    if (memcmp(magic, "PK", 2) == 0) {
        res = read_patch_v4(fpatch, ppatch_data, ppatch_data_len, pgame, pchecksum, pfileext);
    }
    /* if the patch file is a xz stream, it's v3 or older */
    else if (memcmp(magic, "\xFD\x37\x7A\x58\x5A\x00", 6) == 0) {
        res = read_patch_v3(fpatch, ppatch_data, ppatch_data_len, pgame, pchecksum, pfileext);
    }
    /* otherwise the format is unknown/incompatible */
    else {
        fprintf(stderr, "Not a patch file or unknown version!\n");
    }

fread_error:
    fclose(fpatch);
fopen_error:
    return res;
}

static off_t offtin(uint8_t *buf)
{
	off_t y;

	y=buf[7]&0x7F;
	y=y*256;y+=buf[6];
	y=y*256;y+=buf[5];
	y=y*256;y+=buf[4];
	y=y*256;y+=buf[3];
	y=y*256;y+=buf[2];
	y=y*256;y+=buf[1];
	y=y*256;y+=buf[0];

	if(buf[7]&0x80) y=-y;

	return y;
}

EMSCRIPTEN_KEEPALIVE
bool patch(const char* oldfile, const char* newfile, const char* patchfile)
{
    FILE *fold, *fnew, *fctrl, *fdata, *fextra;
    BZFILE *bz2ctrl, *bz2data, *bz2extra;
    int errctrl, errdata, errextra;

    uint8_t *patch_data = NULL;
    size_t patch_data_len = 0;
    char *game = NULL;
    char *checksum = NULL;

    MD5_CTX mdContext;
    size_t i;

    off_t oldpos,newpos;
    ssize_t oldsize,newsize;
    uint8_t *olddata, *newdata;
    ssize_t bzctrllen, bzdatalen;
    off_t ctrl[3];

    /* argument checking */
    if (strcmp(oldfile, newfile) == 0) {
        fprintf(stderr, "oldfile and newfile identical\n");
        return 1;
    }
    if (strcmp(patchfile, newfile) == 0) {
        fprintf(stderr, "patchfile and newfile identical\n");
        return 1;
    }
    fold = fopen(oldfile, "rb");
    if (!fold) {
        fprintf(stderr, "Could not open oldfile!\n");
        return 1;
    }

    /* read bsdiff from apbp */
    if (!read_patch(patchfile, &patch_data, &patch_data_len, &game, &checksum, NULL)) {
        goto read_err;
    }
    /* check bsdiff header */
    if (patch_data_len < 32 || memcmp(patch_data, "BSDIFF40", 8) != 0) {
        fprintf(stderr, "Invalid or corrupt patch!\n");
        goto read_err;
    }
    /* TODO: check oldfile against game*/

    /* read lengths from bsdiff header */
    bzctrllen=offtin(patch_data+8);
    bzdatalen=offtin(patch_data+16);
    newsize=offtin(patch_data+24);
    if((bzctrllen<0) || (bzdatalen<0) || (newsize<0)) {
        fprintf(stderr, "Corrupt patch!\n");
        goto read_err;
    }

    /* map and open bz2 streams */
    fctrl = fmemopen(patch_data, patch_data_len, "rb");
    if (!fctrl) goto read_err;
    if (fseeko(fctrl, 32, SEEK_SET)) {
        fprintf(stderr, "Corrupt patch: seek %s: %d\n", "ctrl", errno);
        goto map_ctrl_err;
    }
    if ((bz2ctrl = BZ2_bzReadOpen(&errctrl, fctrl, 0, 0, NULL, 0)) == NULL) {
        fprintf(stderr, "Corrupt patch: bz2 open %s: %d\n", "ctrl", errctrl);
        goto map_ctrl_err;
    }

    fdata = fmemopen(patch_data, patch_data_len, "rb");
    if (!fdata) goto map_ctrl_err;
    if (fseeko(fdata, 32 + bzctrllen, SEEK_SET)) {
        fprintf(stderr, "Corrupt patch: seek %s: %d\n", "data", errno);
        goto map_data_err;
    }
    if ((bz2data = BZ2_bzReadOpen(&errdata, fdata, 0, 0, NULL, 0)) == NULL) {
        fprintf(stderr, "Corrupt patch: bz2 open %s: %d\n", "data", errctrl);
        goto map_data_err;
    }

    fextra = fmemopen(patch_data, patch_data_len, "rb");
    if (!fextra) goto map_data_err;
    if (fseeko(fextra, 32 + bzctrllen + bzdatalen, SEEK_SET)) {
        fprintf(stderr, "Corrupt patch: seek %s: %d\n", "extra", errno);
        goto map_extra_err;
    }
    if ((bz2extra = BZ2_bzReadOpen(&errextra, fextra, 0, 0, NULL, 0)) == NULL) {
        fprintf(stderr, "Corrupt patch: bz2 open %s: %d\n", "extra", errctrl);
        goto map_extra_err;
    }

    /* stat old file */
    if ((fseek(fold,0,SEEK_END) != 0) ||
        ((oldsize = (size_t)ftell(fold)) == (size_t)-1) ||
        (fseek(fold, 0, SEEK_SET) != 0))
    {
        fprintf(stderr, "Error reading old file size: %d\n", errno);
        goto stat_old_err;
    }
    /* skip SMC header; TODO: property in apbp? */
    if (oldsize % 0x400 == 0x200)
    {
        printf("Note: skipping SMC header\n");
        oldsize -= 0x200;
        if (fseek(fold, 0x200, SEEK_SET)) {
            fprintf(stderr, "Error reading old file: %d\n", errno);
            goto stat_old_err;
        }
    }
    /* alloc old */
    if ((olddata = (uint8_t*)malloc(oldsize+1)) == NULL)
    {
        fprintf(stderr, "Error allocating old buffer\n");
        goto malloc_old_err;
    }
    /* read old file */
    if (fread(olddata, 1, oldsize, fold) != oldsize)
    {
        fprintf(stderr, "Error reading old file: %d\n", errno);
        goto read_old_err;
    }
    /* verify checksum of old file (this is an apbp feature, not bsdiff) */
    if (checksum) {
        if (strlen(checksum) != 32) { // hex encoded md5 is 2*16
            fprintf(stderr, "APBP includes unsupported checksum\n");
            goto read_old_err;
        }
        MD5Init (&mdContext);
        MD5Update (&mdContext, olddata, oldsize);
        MD5Final (&mdContext);
        for (i=0; i<16; i++) {
            uint8_t val;
            sscanf(checksum + 2*i, "%2hhx", &val);
            if (val != mdContext.digest[i]) {
                fprintf(stderr, "Checksum error! Wrong input file?\n");
                goto read_old_err;
            }
        }
    }
    /* alloc new buffer */
    if ((newdata = (uint8_t*)malloc(newsize+1)) == NULL)
    {
      fprintf(stderr, "Error allocating new buffer\n", errno);
      goto malloc_new_err;
    }

    /* apply bsdiff */
    oldpos=0; newpos=0;
    while(newpos<newsize) {
        uint8_t buf[8];
    	off_t lenread;
    	off_t i;
        /* Read control data */
        for(i=0;i<=2;i++) {
            lenread = BZ2_bzRead(&errctrl, bz2ctrl, buf, 8);
            if ((lenread < 8) || ((errctrl != BZ_OK) &&
                (errctrl != BZ_STREAM_END)))
                    goto bsdiff_corrupt;
            ctrl[i]=offtin(buf);
        };

        /* Sanity-check */
        if(newpos+ctrl[0]>newsize)
            goto bsdiff_corrupt;

        /* Read diff string */
        lenread = BZ2_bzRead(&errdata, bz2data, newdata + newpos, ctrl[0]);
        if ((lenread < ctrl[0]) ||
            ((errdata != BZ_OK) && (errdata != BZ_STREAM_END)))
                goto bsdiff_corrupt;

        /* Add old data to diff string */
        for(i=0;i<ctrl[0];i++)
            if((oldpos+i>=0) && (oldpos+i<oldsize))
                newdata[newpos+i]+=olddata[oldpos+i];

        /* Adjust pointers */
        newpos+=ctrl[0];
        oldpos+=ctrl[0];

        /* Sanity-check */
        if(newpos+ctrl[1]>newsize)
            goto bsdiff_corrupt;

        /* Read extra string */
        lenread = BZ2_bzRead(&errextra, bz2extra, newdata + newpos, ctrl[1]);
        if ((lenread < ctrl[1]) ||
            ((errextra != BZ_OK) && (errextra != BZ_STREAM_END)))
                goto bsdiff_corrupt;

        /* Adjust pointers */
        newpos+=ctrl[1];
        oldpos+=ctrl[2];
    };

    /* write new file */
    fnew = fopen(newfile, "wb");
    if (!fnew) {
        fprintf(stderr, "Error creating newfile: %d\n", errno);
        goto bsdiff_err;
    }
    if (fwrite(newdata, 1, newsize, fnew) != newsize) {
        fprintf(stderr, "Error writing newfile: %d\n", errno);
        goto write_err;
    }

    /* clean up */
    fclose(fnew);
    free(newdata);
    free(olddata);
    BZ2_bzReadClose(&errextra, bz2extra);
    BZ2_bzReadClose(&errdata, bz2data);
    BZ2_bzReadClose(&errctrl, bz2ctrl);
    fclose(fextra);
    fclose(fdata);
    fclose(fctrl);
    free(patch_data);
    fclose(fold);
    return true;

write_err:
    fclose(fnew);
    goto bsdiff_err;
bsdiff_corrupt:    
    fprintf(stderr, "Corrupt patch\n");
bsdiff_err:
    free(newdata);
malloc_new_err:
read_old_err:
    free(olddata);
malloc_old_err:
stat_old_err:
    BZ2_bzReadClose(&errextra, bz2extra);
map_extra_err:
    fclose(fextra);
    BZ2_bzReadClose(&errdata, bz2data);
map_data_err:
    fclose(fdata);
    BZ2_bzReadClose(&errctrl, bz2ctrl);
map_ctrl_err:
    fclose(fctrl);
read_err:
    free(game);
    free(patch_data);
    fclose(fold);
    return false;
}

EMSCRIPTEN_KEEPALIVE
bool info(const char *patchfile)
{
    char *game = NULL;
    char *fileext = NULL;
    if (read_patch(patchfile, NULL, NULL, &game, NULL, &fileext)) {
        printf("game: %s\n", game ? game : "Unknown");
        printf("file ext: %s\n", fileext ? fileext : "*");
        free(game);
        free(fileext);
        return true;
    }
    return false;
}

#ifndef __EMSCRIPTEN__
void print_usage(const char* app)
{
    printf("Usage: %s <oldfile> <newfile> <patchfile>\n", app);
    printf("       %s <oldfile> <patchfile>\n\n", app);
    printf("       %s --info <patchfile>\n", app);
    printf("       %s --version\n\n", app);
}

int main(int argc, char** argv)
{
    bool res;
    const char *oldfile, *patchfile;
    const char *slash, *bslash;
    char *newfile;

    if (argc>1 && strcmp(argv[1], "--version")==0) {
        printf("%s\n", VERSION);
        return 0;
    }

    if (argc<3 || argc>4) {
        const char *app = argv[0] ? argv[0] : APPNAME;
        slash = strrchr(app, '/');
        bslash = strrchr(app, '\\');
        if (slash) app = slash+1;
        if (bslash && bslash>slash) app = bslash+1;
        print_usage(app);
        return 1;
    }

    if (argc==3 && strcmp(argv[1], "--info")==0) {
        patchfile = argv[2];
        return info(patchfile) ? 0 : 1;
    }
    else if (argc>3) {
        oldfile = argv[1];
        newfile = argv[2];
        patchfile = argv[3];
    } else {
        const char *ext, *pext;
        size_t patchfile_baselen;
        oldfile = argv[1];
        patchfile = argv[2];
        ext = strrchr(oldfile, '.');
        slash = strrchr(oldfile, '/');
        bslash = strrchr(oldfile, '\\');
        if ((slash && slash > ext) || (bslash && bslash > ext)) ext = NULL;
        pext = strrchr(patchfile, '.');
        slash = strrchr(patchfile, '/');
        bslash = strrchr(oldfile, '\\');
        if ((slash && slash > pext) || (bslash && bslash > pext)) pext = NULL;
        if (!ext && !pext) ext = ".patched";
        else if (!ext) ext = "";
        patchfile_baselen = strlen(patchfile) - (pext ? strlen(pext) : 0);
        newfile = (char*)malloc(patchfile_baselen + strlen(ext) + 1);
        memcpy(newfile, patchfile, patchfile_baselen);
        strcpy(newfile + patchfile_baselen, ext);
    }

    res = patch(oldfile, newfile, patchfile);

    if (argc<4) free(newfile);

    return res ? 0 : 1;
}
#endif
