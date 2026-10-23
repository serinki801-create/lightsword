/* cve86950.h — CoreGraphics aa_* glyph rasterizer integer overflow (26.2 live).
 *
 * Fixed in 26.7.1 by clamping aa_double_to_fixed(). On 23C55 the moveto path
 * saturates with FCVTZS (INT32_MAX) while lineto truncates via FCVTZS+XTN, so
 * the bbox stays narrow and the per-scanline coverage buffer is undersized.
 * aa_cache_render then writes 16-bit alpha increments at edge coordinates that
 * are outside the buffer. Allocation is malloc when bbox width_px > 1015 and
 * alloca otherwise; the leaf width in font units selects which.
 *
 * This module is a userland probe only: it proves the primitive on-device and
 * records which decode path reaches it. It does not touch the kernel. */
#ifndef NK_CVE86950_H
#define NK_CVE86950_H

#include <stdint.h>

typedef struct {
    int      mode;       /* nk_86950_* */
    int      heap;       /* 1 = malloc coverage buffer, 0 = alloca */
    int      began;      /* trigger entry reached */
    int      survived;   /* decode returned without killing the process */
    uint64_t elapsed_ms;
} nk_86950_stat_t;

enum {
    NK_86950_IMAGEIO = 0,  /* CGImageSourceCreateThumbnailAtIndex */
    NK_86950_CGPDF   = 1,  /* CGPDFDocument + CGContextDrawPDFPage */
    NK_86950_FONT    = 2   /* CGFont + CGContextShowGlyphsAtPositions */
};

int         nk_86950_run(int mode, int heap, nk_86950_stat_t *out);
const char *nk_86950_name(int mode);

#endif
