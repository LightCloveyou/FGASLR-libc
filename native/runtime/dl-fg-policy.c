/* Read the main executable's policy after dependency mapping, before binding.
   This ordinary rtld code never executes while a code pool is being replaced.
   SPDX-License-Identifier: 0BSD */
#include <ldsodefs.h>
#include <link.h>
#include "dl-fg-policy.h"

extern struct link_map _dl_rtld_map attribute_hidden;
extern unsigned long _dl_fg_object (unsigned long, const struct fg_policy *,
                                    const struct fg_imports *, unsigned long) attribute_hidden;
extern void _dl_fg_check (unsigned long, const struct fg_imports *, unsigned long) attribute_hidden;
extern void _dl_fg_forget (unsigned long) attribute_hidden;
extern void _dl_fg_policy_error (const char *, const char *) attribute_hidden
    __attribute__ ((noreturn));
static struct fg_policy fg_main_policy;
static bool fg_policy_ready;

static bool
fg_map_is_readable (const struct link_map *map, ElfW (Addr) address, size_t bytes)
{
  if (address > (ElfW (Addr)) - 1 - bytes)
    return false;
  for (ElfW (Half) i = 0; i < map->l_phnum; ++i)
    {
      const ElfW (Phdr) *p = map->l_phdr + i;
      if (p->p_type != PT_LOAD || !(p->p_flags & PF_R)
          || p->p_vaddr > (ElfW (Addr)) - 1 - map->l_addr)
        continue;
      ElfW (Addr) start = map->l_addr + p->p_vaddr;
      if (address >= start && address - start <= p->p_memsz
          && bytes <= p->p_memsz - (address - start))
        return true;
    }
  return false;
}

static void
fg_policy_read_main (void)
{
  if (fg_policy_ready)
    return;
  struct link_map *map = GL (dl_ns)[LM_ID_BASE]._ns_loaded;
  if (!map || map->l_type != lt_executable)
    return;
  for (ElfW (Half) i = 0; i < map->l_phnum; ++i)
    {
      const ElfW (Phdr) *p = map->l_phdr + i;
      if (p->p_type != PT_NOTE || !p->p_filesz)
        continue;
      ElfW (Addr) at = map->l_addr + p->p_vaddr;
      if (!fg_map_is_readable (map, at, p->p_filesz))
        _dl_fg_policy_error ("unmapped executable note", NULL);
      size_t left = p->p_filesz;
      while (left >= 12)
        {
          const ElfW (Word) *note = (const void *)at;
          size_t names = (size_t)note[0], bytes = (size_t)note[1];
          if (names > left - 12 || names > (size_t)-1 - 3 || bytes > (size_t)-1 - 3)
            _dl_fg_policy_error ("invalid executable note size", NULL);
          names = (names + 3) & -4UL;
          bytes = (bytes + 3) & -4UL;
          if (names > left - 12 || bytes > left - 12 - names)
            _dl_fg_policy_error ("truncated executable note", NULL);
          const char *owner = (const void *)(at + 12);
          if (note[2] == 0x46475031 && note[0] == 4 && owner[0] == 'F' && owner[1] == 'G'
              && owner[2] == 'P' && !owner[3])
            {
              if (note[1] != sizeof (struct fg_rule))
                _dl_fg_policy_error ("invalid rule size", NULL);
              const struct fg_rule *r = (const void *)(at + 12 + names);
              if (r->magic != 0x46504731 || r->version != 1
                  || !memchr (r->name, 0, sizeof (r->name)))
                _dl_fg_policy_error ("invalid policy rule", NULL);
              if (r->action == 4 || r->action == 5)
                {
                  unsigned long mode = r->action == 4 ? 1 : 2;
                  if (r->name[0] || (fg_main_policy.mode && fg_main_policy.mode != mode))
                    _dl_fg_policy_error ("conflicting whitelist/blacklist modes", NULL);
                  fg_main_policy.mode = mode;
                }
              else if (r->action != 1 && r->action != 2)
                _dl_fg_policy_error ("unknown policy action", NULL);
              else if (!r->name[0])
                _dl_fg_policy_error ("empty function name", NULL);
              if (fg_main_policy.count == FG_RULE_LIMIT)
                _dl_fg_policy_error ("too many policy rules", NULL);
              fg_main_policy.rules[fg_main_policy.count++] = r;
            }
          size_t advance = 12 + names + bytes;
          at += advance;
          left -= advance;
        }
    }
  if (!fg_main_policy.mode)
    fg_main_policy.mode = 1;
  fg_policy_ready = true;
}

static void
fg_policy_collect_imports (struct link_map *map, unsigned int tag, unsigned int size,
                           struct fg_imports *views, unsigned long *count)
{
  if (!map->l_info[tag] || !map->l_info[size] || !map->l_info[DT_SYMTAB] || !map->l_info[DT_STRTAB]
      || !map->l_info[DT_STRSZ])
    return;
  if (tag == DT_JMPREL
      && (!map->l_info[DT_PLTREL] || map->l_info[DT_PLTREL]->d_un.d_val != DT_RELA))
    _dl_fg_policy_error ("unsupported PLT relocation encoding", NULL);
  ElfW (Addr) address = D_PTR (map, l_info[tag]);
  size_t bytes = map->l_info[size]->d_un.d_val;
  if (!bytes)
    return;
  if (bytes % sizeof (ElfW (Rela)) || bytes / sizeof (ElfW (Rela)) > 1000000
      || !fg_map_is_readable (map, address, bytes))
    _dl_fg_policy_error ("invalid dependency relocations", NULL);
  const ElfW (Rela) *rel = (const void *)address;
  size_t maximum = 0;
  for (size_t i = 0; i < bytes / sizeof (*rel); ++i)
    {
      size_t index = ELFW (R_SYM) (rel[i].r_info);
      if (index > maximum)
        maximum = index;
    }
  if (maximum > 1000000)
    _dl_fg_policy_error ("dependency symbol index too large", NULL);
  if (!maximum)
    return;
  ElfW (Addr) symbols = D_PTR (map, l_info[DT_SYMTAB]), strings = D_PTR (map, l_info[DT_STRTAB]);
  size_t strbytes = map->l_info[DT_STRSZ]->d_un.d_val;
  if (!fg_map_is_readable (map, symbols, (maximum + 1) * sizeof (ElfW (Sym)))
      || !fg_map_is_readable (map, strings, strbytes))
    _dl_fg_policy_error ("invalid dependency symbol table", NULL);
  if (*count == FG_VIEW_LIMIT)
    _dl_fg_policy_error ("too many dependency relocation tables", NULL);
  views[(*count)++]
      = (struct fg_imports){ (const void *)symbols, (const void *)strings, maximum + 1, strbytes,
                             (const void *)address, bytes / sizeof (*rel) };
}

void attribute_hidden
_dl_fg_apply_maps (struct link_map *root)
{
  fg_policy_read_main ();
  struct fg_imports views[FG_VIEW_LIMIT];
  unsigned long count = 0;
  const struct fg_policy *policy = fg_main_policy.count ? &fg_main_policy : NULL;
  if (policy)
    for (Lmid_t ns = 0; ns < GL (dl_nns); ++ns)
      for (struct link_map *m = GL (dl_ns)[ns]._ns_loaded; m; m = m->l_next)
        {
          fg_policy_collect_imports (m, DT_RELA, DT_RELASZ, views, &count);
          fg_policy_collect_imports (m, DT_JMPREL, DT_PLTRELSZ, views, &count);
        }
  for (unsigned int i = 0; i < root->l_searchlist.r_nlist; ++i)
    {
      struct link_map *m = root->l_searchlist.r_list[i];
      if (m->l_addr == _dl_rtld_map.l_addr)
        continue;
      bool libc = (m == GL (dl_ns)[m->l_ns].libc_map);
      if (!m->l_fg_done)
        {
          if (m->l_addr && m->l_map_start == m->l_addr)
            m->l_fg_state = (void *)_dl_fg_object (m->l_addr, libc ? policy : NULL, views, count);
          m->l_fg_done = 1;
        }
      if (policy && libc && !m->l_fg_state)
        _dl_fg_policy_error ("matching policy-enabled libc metadata required", NULL);
    }
  if (policy)
    for (Lmid_t ns = 0; ns < GL (dl_nns); ++ns)
      {
        struct link_map *m = GL (dl_ns)[ns].libc_map;
        if (m && m->l_fg_state)
          _dl_fg_check ((unsigned long)m->l_fg_state, views, count);
      }
}

void attribute_hidden
_dl_fg_unmap (struct link_map *map)
{
  _dl_fg_forget ((unsigned long)map->l_fg_state);
  map->l_fg_state = NULL;
  map->l_fg_done = 0;
}
