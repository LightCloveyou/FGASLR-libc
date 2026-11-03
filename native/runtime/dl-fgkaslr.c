/* Native x86-64 load-time function permutation.  SPDX-License-Identifier: 0BSD
   Runs before rtld relocation; deliberately has no libc/GOT/TLS dependencies.
   The small .fgboot nucleus is page-isolated and never writable/executable.
   All addresses in the embedded metadata are relative to the ELF load bias. */
#pragma GCC optimize("Oz")
typedef unsigned long fg_addr_t;
typedef long fg_saddr_t;
typedef unsigned int fg_u32_t;
typedef unsigned char fg_u8_t;
#include "dl-fg-policy.h"
#define FG_BOOTSTRAP __attribute__ ((section (".fgboot"), noinline, visibility ("hidden")))
#define FG_LOCAL static __attribute__ ((section (".fgboot"), noinline))
#define FG_METADATA_MAGIC 0x314e474652444cUL
#define FG_METADATA_MARKER 0x46474b41534c52UL
#define FG_MAX_RANDOM_GAP 15UL
#ifndef FG_STAMP
#define FG_STAMP(index) ((void)0)
#endif
struct fg_elf_phdr
{
  fg_u32_t type, flags;
  fg_addr_t off, va, pa, filesz, memsz, align;
};
struct fg_elf_header
{
  fg_u8_t ident[16];
  unsigned short type, machine;
  fg_u32_t version;
  fg_addr_t entry, phoff, shoff;
  fg_u32_t flags;
  unsigned short ehsize, phsize, phnum;
};
struct fg_metadata_header
{
  fg_addr_t magic, version, count, patches, frames, lo, hi, ehbase, ehtab, entry, bootlo, boothi,
      bytes, fixed_patches, fixed_frames;
};
struct fg_code_unit
{
  fg_addr_t start, size, align;
  fg_u32_t patch_first, patch_count, frame_first, frame_count;
};
/* Unit index zero means fixed; otherwise index - 1 selects a movable unit.
   bias already includes the original place and relocation-kind arithmetic. */
struct fg_relocation_patch
{
  fg_addr_t dest, value, bias;
  fg_u32_t value_unit;
  fg_u8_t relative, width, sign, reserved;
};
struct fg_unwind_frame
{
  fg_addr_t pc;
  fg_saddr_t fde;
};
struct fg_random_state
{
  fg_u32_t words[256], left, gap_word, gaps;
};
/* Set to one by the final ELF preparation step; zero only in build-tree ld. */
static volatile fg_addr_t fg_metadata_required __attribute__ ((section (".data.fg_policy"))) = 0;
FG_LOCAL fg_saddr_t
fg_syscall6 (fg_addr_t n, fg_addr_t a, fg_addr_t b, fg_addr_t c, fg_addr_t d, fg_addr_t e,
             fg_addr_t f)
{
  register fg_addr_t r10 __asm__ ("r10") = d;
  register fg_addr_t r8 __asm__ ("r8") = e;
  register fg_addr_t r9 __asm__ ("r9") = f;
  fg_saddr_t result;
  __asm__ volatile ("syscall"
                    : "=a"(result)
                    : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10), "r"(r8), "r"(r9)
                    : "rcx", "r11", "memory");
  return result;
}
static __attribute__ ((always_inline)) inline fg_saddr_t
fg_syscall3 (fg_addr_t n, fg_addr_t a, fg_addr_t b, fg_addr_t c)
{
  fg_saddr_t result;
  __asm__ volatile ("syscall"
                    : "=a"(result)
                    : "a"(n), "D"(a), "S"(b), "d"(c)
                    : "rcx", "r11", "memory");
  return result;
}
FG_LOCAL __attribute__ ((noreturn)) void
fg_bootstrap_fail (void)
{
  /* Stack literal avoids any pre-relocation data reference. */
  char msg[] = "ld.so: native FGKASLR failed\n";
  fg_syscall3 (1, 2, (fg_addr_t)msg, sizeof (msg) - 1);
  fg_syscall3 (231, 127, 0, 0);
  for (;;)
    __asm__ volatile ("ud2");
}
FG_LOCAL fg_u32_t
fg_random_u32 (struct fg_random_state *r)
{
  if (!r->left)
    {
      fg_addr_t done = 0;
      while (done < sizeof (r->words))
        {
          fg_saddr_t got
              = fg_syscall3 (318, (fg_addr_t)r->words + done, sizeof (r->words) - done, 0);
          if (got == -4)
            continue;
          if (got <= 0)
            fg_bootstrap_fail ();
          done += got;
        }
      r->left = 256;
    }
  return r->words[--r->left];
}
/* Lemire's unbiased multiply/reject reduction, with 32-bit kernel words.
   The range is at most 100000; no 32-bit seed or PRNG is introduced. */
FG_LOCAL fg_addr_t
fg_random_below (struct fg_random_state *r, fg_u32_t n)
{
  fg_addr_t product = (fg_addr_t)fg_random_u32 (r) * n;
  fg_u32_t low = (fg_u32_t)product;
  if (low < n)
    {
      fg_u32_t threshold = (fg_u32_t)-n % n;
      while (low < threshold)
        {
          product = (fg_addr_t)fg_random_u32 (r) * n;
          low = (fg_u32_t)product;
        }
    }
  return product >> 32;
}
FG_LOCAL fg_addr_t
fg_random_gap (struct fg_random_state *r)
{
  if (!r->gaps)
    {
      r->gap_word = fg_random_u32 (r);
      r->gaps = 8;
    }
  fg_u32_t gap = r->gap_word & FG_MAX_RANDOM_GAP;
  r->gap_word >>= 4;
  --r->gaps;
  return gap;
}
FG_LOCAL fg_addr_t
fg_translate_address (fg_addr_t v, const struct fg_code_unit *u, const fg_addr_t *dst, fg_addr_t n)
{
  fg_addr_t lo = 0, hi = n;
  while (lo < hi)
    {
      fg_addr_t m = lo + (hi - lo) / 2;
      if (u[m].start <= v)
        lo = m + 1;
      else
        hi = m;
    }
  if (lo && v - u[lo - 1].start < u[lo - 1].size)
    return dst[lo - 1] + v - u[lo - 1].start;
  return v;
}
FG_LOCAL void
fg_copy_bytes (fg_u8_t *to, const fg_u8_t *from, fg_addr_t n)
{
  __asm__ volatile ("rep movsb" : "+D"(to), "+S"(from), "+c"(n)::"memory");
}
FG_LOCAL void
fg_fill_bytes (fg_u8_t *to, fg_u8_t value, fg_addr_t n)
{
  __asm__ volatile ("rep stosb" : "+D"(to), "+c"(n) : "a"(value) : "memory");
}
FG_LOCAL void
fg_apply_patch (const struct fg_relocation_patch *p, const fg_addr_t *dst, fg_addr_t delta,
                fg_addr_t origin)
{
  fg_addr_t value = p->value, address = origin + p->dest + delta;
  if (p->value_unit)
    value += dst[p->value_unit - 1];
  if (p->relative)
    value += p->bias - delta;
  if (p->width == 4)
    {
      if (p->sign ? (fg_saddr_t)value != (fg_saddr_t)(int)value : value != (fg_u32_t)value)
        fg_bootstrap_fail ();
      __asm__ volatile ("movl %k1,(%0)" ::"r"(address), "r"(value) : "memory");
    }
  else
    __asm__ volatile ("movq %1,(%0)" ::"r"(address), "r"(value) : "memory");
}
/* Check before making any mapping writable. Metadata cannot authorize writes
   into itself or into the executing bootstrap. ELF headers are loader input. */
FG_LOCAL int
fg_range_is_mapped (struct fg_elf_phdr *ph, fg_addr_t num, fg_addr_t va, fg_addr_t bytes,
                    fg_addr_t bootlo, fg_addr_t boothi)
{
  if (!bytes || va > -1UL - bytes || (va < boothi && bootlo < va + bytes))
    return 0;
  for (fg_addr_t i = 0; i < num; ++i)
    if (ph[i].type == 1 && ph[i].pa != FG_METADATA_MARKER && (ph[i].flags & 4) && va >= ph[i].va
        && va - ph[i].va <= ph[i].memsz && bytes <= ph[i].memsz - (va - ph[i].va))
      return 1;
  return 0;
}
#include "dl-fg-policy.inc"
FG_LOCAL void
fg_emit_unwind_entry (int *table, fg_addr_t index, fg_addr_t pc, fg_saddr_t fde, fg_addr_t ehbase)
{
  fg_saddr_t relative = pc - ehbase;
  if (relative != (fg_saddr_t)(int)relative)
    fg_bootstrap_fail ();
  table[2 * index] = relative;
  table[2 * index + 1] = fde;
}
FG_LOCAL fg_addr_t
fg_rebuild_unwind_table (int *table, const struct fg_metadata_header *h,
                         const struct fg_unwind_frame *frames, const struct fg_code_unit *u,
                         const fg_addr_t *dst, const fg_addr_t *order, fg_addr_t count)
{
  fg_addr_t fi = 0, ti = 0;
  for (fg_addr_t j = 0; j < count; ++j)
    {
      fg_addr_t i = order[j];
      for (fg_addr_t k = u[i].frame_first; k < (fg_addr_t)u[i].frame_first + u[i].frame_count; ++k)
        {
          fg_addr_t pc = dst[i] + frames[k].pc;
          while (fi < h->fixed_frames && frames[fi].pc <= pc)
            {
              fg_emit_unwind_entry (table, ti++, frames[fi].pc, frames[fi].fde, h->ehbase);
              ++fi;
            }
          fg_emit_unwind_entry (table, ti++, pc, frames[k].fde, h->ehbase);
        }
    }
  while (fi < h->fixed_frames)
    {
      fg_emit_unwind_entry (table, ti++, frames[fi].pc, frames[fi].fde, h->ehbase);
      ++fi;
    }
  return ti;
}
FG_LOCAL void
fg_set_segment_permissions (fg_addr_t base, struct fg_elf_phdr *ph, fg_addr_t num, fg_addr_t bootlo,
                            fg_addr_t boothi, int restore)
{
  for (fg_addr_t i = 0; i < num; ++i)
    if (ph[i].type == 1 && ph[i].memsz && ph[i].pa != FG_METADATA_MARKER)
      {
        if (ph[i].flags == 6)
          continue; /* Already RW; RELRO sealing happens later. */
        fg_addr_t lo = ph[i].va & -4096UL, hi = (ph[i].va + ph[i].memsz + 4095) & -4096UL;
        fg_addr_t prot = restore ? ((ph[i].flags & 4 ? 1 : 0) | (ph[i].flags & 2 ? 2 : 0)
                                    | (ph[i].flags & 1 ? 4 : 0))
                                 : 3;
        if (bootlo < boothi && lo < boothi && bootlo < hi)
          {
            if (lo < bootlo && fg_syscall3 (10, base + lo, bootlo - lo, prot))
              fg_bootstrap_fail ();
            if (boothi < hi && fg_syscall3 (10, base + boothi, hi - boothi, prot))
              fg_bootstrap_fail ();
          }
        else if (fg_syscall3 (10, base + lo, hi - lo, prot))
          fg_bootstrap_fail ();
      }
}
FG_LOCAL void
fg_validate_metadata (struct fg_metadata_header *h, fg_addr_t available, fg_addr_t base,
                      struct fg_elf_phdr *ph, fg_addr_t num, int self)
{
  if (h->magic != FG_METADATA_MAGIC || h->version != 5 || !h->count || h->hi <= h->lo
      || h->count > 100000 || h->patches > 1000000 || h->frames > 100000
      || h->fixed_patches > h->patches || h->fixed_frames > h->frames || h->bytes > available)
    fg_bootstrap_fail ();
  fg_policy_validate_metadata (h, sizeof (*h) + h->count * sizeof (struct fg_code_unit)
                                      + h->patches * sizeof (struct fg_relocation_patch)
                                      + h->frames * sizeof (struct fg_unwind_frame));
  const struct fg_code_unit *u = (void *)(h + 1);
  const struct fg_relocation_patch *patch = (void *)(u + h->count);
  const struct fg_unwind_frame *frames = (void *)(patch + h->patches);
  fg_addr_t bootlo = self ? h->bootlo : 0, boothi = self ? h->boothi : 0;
  if (self ? (bootlo >= boothi || bootlo % 4096 || boothi % 4096
              || (fg_addr_t)fg_validate_metadata - base < bootlo
              || (fg_addr_t)fg_validate_metadata - base >= boothi
              || !fg_range_is_mapped (ph, num, bootlo, boothi - bootlo, 0, 0))
           : (h->bootlo || h->boothi))
    fg_bootstrap_fail ();
  if (!fg_range_is_mapped (ph, num, h->lo, h->hi - h->lo, bootlo, boothi))
    fg_bootstrap_fail ();
  fg_addr_t code_lo = h->lo & -4096UL, code_hi = (h->hi + 4095) & -4096UL, executable = 0;
  for (fg_addr_t i = 0; i < num; ++i)
    if (ph[i].type == 1 && ph[i].flags == 5 && h->lo >= ph[i].va && h->hi <= ph[i].va + ph[i].memsz)
      executable = 1;
  if (!executable || (code_lo < boothi && bootlo < code_hi))
    fg_bootstrap_fail ();
  fg_addr_t worst = 0, last = h->lo, np = h->fixed_patches, nf = h->fixed_frames;
  for (fg_addr_t i = 0; i < h->count; ++i)
    {
      if (!u[i].size || !u[i].align || u[i].align > 4096 || (u[i].align & (u[i].align - 1))
          || u[i].start < last || u[i].start > h->hi || u[i].size > h->hi - u[i].start
          || u[i].start % u[i].align || u[i].size > h->hi - h->lo - worst
          || u[i].align - 1 + FG_MAX_RANDOM_GAP > h->hi - h->lo - worst - u[i].size
          || u[i].patch_first != np || u[i].frame_first != nf || u[i].patch_count > h->patches - np
          || u[i].frame_count > h->frames - nf)
        fg_bootstrap_fail ();
      worst += u[i].size + u[i].align - 1 + FG_MAX_RANDOM_GAP;
      last = u[i].start + u[i].size;
      np += u[i].patch_count;
      nf += u[i].frame_count;
    }
  if (np != h->patches || nf != h->frames)
    fg_bootstrap_fail ();
  /* Group intervals cover each record exactly once, with no overlap or gaps. */
  for (fg_addr_t group = 0; group <= h->count; ++group)
    {
      const struct fg_code_unit *unit = group ? u + group - 1 : 0;
      fg_addr_t first = unit ? unit->patch_first : 0,
                count = unit ? unit->patch_count : h->fixed_patches;
      for (fg_addr_t i = first; i < first + count; ++i)
        {
          const struct fg_relocation_patch *p = patch + i;
          if (p->value_unit > h->count || p->relative > 1 || p->sign > 1 || p->reserved
              || (p->width != 4 && p->width != 8)
              || (p->value_unit && p->value >= u[p->value_unit - 1].size))
            fg_bootstrap_fail ();
          if (unit)
            {
              if (p->dest < unit->start || p->dest - unit->start >= unit->size
                  || p->width > unit->size - (p->dest - unit->start))
                fg_bootstrap_fail ();
            }
          else if (!fg_range_is_mapped (ph, num, p->dest, p->width, bootlo, boothi)
                   || (p->dest < h->hi && p->dest + p->width > h->lo)
                   || (p->dest < code_lo && p->dest + p->width > code_lo)
                   || (p->dest < code_hi && p->dest + p->width > code_hi))
            fg_bootstrap_fail ();
        }
      first = unit ? unit->frame_first : 0;
      count = unit ? unit->frame_count : h->fixed_frames;
      for (fg_addr_t i = first; i < first + count; ++i)
        {
          const struct fg_unwind_frame *f = frames + i;
          if ((i > first && f->pc < frames[i - 1].pc) || f->fde != (fg_saddr_t)(int)f->fde
              || !fg_range_is_mapped (ph, num, h->ehbase + f->fde, 1, bootlo, boothi))
            fg_bootstrap_fail ();
          if (unit ? f->pc >= unit->size
                   : (!fg_range_is_mapped (ph, num, f->pc, 1, bootlo, boothi)
                      || (f->pc >= h->lo && f->pc < h->hi)))
            fg_bootstrap_fail ();
        }
    }
  if (h->frames
      && (!fg_range_is_mapped (ph, num, h->ehtab, h->frames * 8, bootlo, boothi)
          || !fg_range_is_mapped (ph, num, h->ehtab - 4, 4, bootlo, boothi)
          || *(fg_u32_t *)(base + h->ehtab - 4) != h->frames
          || (h->ehtab < code_hi && h->ehtab + h->frames * 8 > code_lo)))
    fg_bootstrap_fail ();
  if (!fg_range_is_mapped (ph, num, h->entry, 1, bootlo, boothi))
    fg_bootstrap_fail ();
}
FG_LOCAL fg_addr_t
fg_permute_object (fg_addr_t base, int self, const struct fg_policy *policy,
                   const struct fg_imports *views, fg_addr_t views_count, fg_addr_t *policy_state)
{
  FG_STAMP (0);
  struct fg_elf_header *eh = (void *)base;
  struct fg_elf_phdr *ph = (void *)(base + eh->phoff);
  struct fg_metadata_header *h = 0;
  fg_addr_t available = 0;
  for (fg_addr_t i = 0; i < eh->phnum; ++i)
    if (ph[i].type == 1)
      {
        if (ph[i].va > -1UL - base || base + ph[i].va > -4096UL
            || ph[i].memsz > -4096UL - base - ph[i].va)
          fg_bootstrap_fail ();
        if (ph[i].pa == FG_METADATA_MARKER)
          {
            if (h || ph[i].filesz < sizeof (*h) || ph[i].filesz > ph[i].memsz || ph[i].flags != 4
                || ph[i].va % 4096)
              fg_bootstrap_fail ();
            h = (void *)(base + ph[i].va);
            available = ph[i].filesz;
          }
      }
  if (!h)
    return 0; /* Unprepared build-tree ld only. */
  fg_validate_metadata (h, available, base, ph, eh->phnum, self);
  const struct fg_code_unit *u = (void *)(h + 1);
  const struct fg_relocation_patch *patch = (void *)(u + h->count);
  const struct fg_unwind_frame *frames = (void *)(patch + h->patches);
  fg_addr_t bootlo = self ? h->bootlo : 0, boothi = self ? h->boothi : 0;
  FG_STAMP (1);
  fg_addr_t code_lo = h->lo & -4096UL, code_hi = (h->hi + 4095) & -4096UL,
            code_size = code_hi - code_lo;
  if (code_size > -1UL - h->count * 16 - h->frames * 8)
    fg_bootstrap_fail ();
  fg_addr_t size = code_size + h->count * 16 + h->frames * 8;
  fg_saddr_t allocation = fg_syscall6 (9, 0, size, 3, 0x22, -1, 0);
  if (allocation < 0 && allocation >= -4095)
    fg_bootstrap_fail ();
  fg_u8_t *scratch = (void *)allocation;
  fg_addr_t *dst = (void *)(scratch + code_size), *order = dst + h->count;
  int *table = (void *)(order + h->count);
  struct fg_state *state = 0;
  fg_addr_t count = h->count;
  if (policy)
    count = fg_policy_select_units (base, h, policy, views, views_count, order, &state);
  else
    for (fg_addr_t i = 0; i < count; ++i)
      order[i] = i;
  FG_STAMP (2);
  struct fg_random_state rng;
  rng.left = 0;
  rng.gaps = 0;
  for (fg_addr_t i = count - 1; i; --i)
    {
      fg_addr_t j = fg_random_below (&rng, i + 1), v = order[i];
      order[i] = order[j];
      order[j] = v;
    }
  fg_addr_t worst = 0, largest = 0;
  for (fg_addr_t i = 0; i < count; ++i)
    {
      fg_addr_t index = order[i];
      worst += u[index].size + u[index].align - 1 + FG_MAX_RANDOM_GAP;
    }
  fg_addr_t guard = (h->lo + worst + 4095) & -4096UL;
  if (state)
    for (fg_addr_t i = 0; i < h->count; ++i)
      if (!state->flags[i])
        {
          dst[i] = guard;
          if (u[i].size > largest)
            largest = u[i].size;
        }
  if (largest && (guard > (h->hi & -4096UL) || largest > (h->hi & -4096UL) - guard))
    _dl_fg_policy_error ("insufficient permanent guard capacity", 0);
  fg_addr_t cursor = h->lo;
  for (fg_addr_t j = 0; j < count; ++j)
    {
      fg_addr_t i = order[j];
      cursor += fg_random_gap (&rng);
      cursor = (cursor + u[i].align - 1) & -u[i].align;
      dst[i] = cursor;
      cursor += u[i].size;
    }
  FG_STAMP (3);
  /* Original mappings remain untouched until the entire new code is ready.
     Walk output order, filling only gaps and repairing each copied unit in place. */
  fg_addr_t written = h->lo - code_lo;
  fg_copy_bytes (scratch, (void *)(base + code_lo), written);
  for (fg_addr_t j = 0; j < count; ++j)
    {
      fg_addr_t i = order[j], offset = dst[i] - code_lo, delta = dst[i] - u[i].start;
      fg_fill_bytes (scratch + written, 0xcc, offset - written);
      fg_copy_bytes (scratch + offset, (void *)(base + u[i].start), u[i].size);
      for (fg_addr_t k = u[i].patch_first; k < (fg_addr_t)u[i].patch_first + u[i].patch_count; ++k)
        fg_apply_patch (patch + k, dst, delta, (fg_addr_t)scratch - code_lo);
      written = offset + u[i].size;
    }
  /* Reserve complete unused tail pages without ever faulting them in. Keep
     INT3 in the two partial pages; the last page may contain fixed code/data
     beyond the pool, so it must survive even when the pool ends mid-page. */
  fg_addr_t hole_lo = (cursor + 4095) & -4096UL, hole_hi = h->hi & -4096UL;
  if (hole_lo < hole_hi)
    {
      fg_fill_bytes (scratch + written, 0xcc, hole_lo - code_lo - written);
      fg_fill_bytes (scratch + hole_hi - code_lo, 0xcc, h->hi - hole_hi);
    }
  else
    fg_fill_bytes (scratch + written, 0xcc, h->hi - code_lo - written);
  fg_copy_bytes (scratch + h->hi - code_lo, (void *)(base + h->hi), code_hi - h->hi);
  FG_STAMP (4);
  /* Moving PCs are already sorted by output order and within-unit offset.
     Merge fixed PCs, keeping each FDE with its PC, in linear time. */
  fg_addr_t frame_count = fg_rebuild_unwind_table (table, h, frames, u, dst, order, count);
  fg_addr_t entry = base + fg_translate_address (h->entry, u, dst, h->count);
  FG_STAMP (5);
  fg_set_segment_permissions (base, ph, eh->phnum, bootlo, boothi, 0);
  FG_STAMP (6);
  for (fg_addr_t i = 0; i < h->fixed_patches; ++i)
    {
      fg_addr_t origin = patch[i].dest >= code_lo && patch[i].dest < code_hi
                             ? (fg_addr_t)scratch - code_lo
                             : base;
      fg_apply_patch (patch + i, dst, 0, origin);
    }
  fg_copy_bytes ((void *)(base + h->ehtab), (void *)table, frame_count * 8);
  if (policy && h->frames)
    *(fg_u32_t *)(base + h->ehtab - 4) = frame_count;
  FG_STAMP (7);
  fg_set_segment_permissions (base, ph, eh->phnum, bootlo, boothi, 1);
  if (fg_syscall3 (10, (fg_addr_t)scratch, code_size, 5))
    fg_bootstrap_fail ();
  /* Move already-populated RX pages, avoiding a second copy and private faults
     on every original file-backed text page. The bootstrap is outside this span. */
  if ((fg_addr_t)fg_syscall6 (25, (fg_addr_t)scratch, code_size, code_size, 3, base + code_lo, 0)
      != base + code_lo)
    fg_bootstrap_fail ();
  /* mremap needs the source code span to remain one VMA, so install this
     inaccessible reservation after the move. No physical tail pages exist. */
  if (hole_lo < hole_hi && fg_syscall3 (10, base + hole_lo, hole_hi - hole_lo, 0))
    fg_bootstrap_fail ();
  FG_STAMP (8);
  fg_syscall3 (11, (fg_addr_t)scratch + code_size, size - code_size, 0);
  if (state)
    *policy_state = (fg_addr_t)state;
  /* Generation is complete. Late policy checks may refault the name index;
     retain the read-only file mapping. Advice denial only loses the RSS
     optimization, never the independently shuffled layout. */
  fg_syscall3 (28, (fg_addr_t)h, available, 4); /* MADV_DONTNEED: metadata only, never live code. */
  FG_STAMP (9);
  return entry;
}
FG_BOOTSTRAP fg_addr_t
_dl_fg_boot (fg_addr_t base, fg_addr_t original_entry)
{
  fg_addr_t entry = fg_permute_object (base, 1, 0, 0, 0, 0);
  if (!entry && fg_metadata_required)
    fg_bootstrap_fail ();
  return entry ? entry : original_entry;
}
FG_BOOTSTRAP fg_addr_t
_dl_fg_object (fg_addr_t base, const struct fg_policy *policy, const struct fg_imports *views,
               fg_addr_t count)
{
  fg_addr_t state = 0;
  fg_permute_object (base, 0, policy, views, count, &state);
  return state;
}
