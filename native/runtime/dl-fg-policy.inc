/* Freestanding selection and immutable late-import checks. Included in .fgboot. */
struct fg_state
{
  fg_addr_t bytes, base;
  const struct fg_metadata_header *head;
  const struct fg_policy_info *info;
  fg_u8_t flags[];
};
FG_LOCAL fg_addr_t
fg_string_length_bounded (const char *s, fg_addr_t limit)
{
  fg_addr_t i = 0;
  while (i < limit && s[i])
    ++i;
  return i;
}
FG_LOCAL int
fg_string_compare (const char *a, const char *b)
{
  while (*a && (fg_u8_t)*a == (fg_u8_t)*b)
    {
      ++a;
      ++b;
    }
  return (fg_u8_t)*a - (fg_u8_t)*b;
}
FG_BOOTSTRAP __attribute__ ((noreturn)) void
_dl_fg_policy_error (const char *message, const char *name)
{
  const char prefix[] = "ld.so: FG policy: ";
  const char newline[] = "\n";
  fg_syscall3 (1, 2, (fg_addr_t)prefix, sizeof (prefix) - 1);
  fg_syscall3 (1, 2, (fg_addr_t)message, fg_string_length_bounded (message, 256));
  if (name)
    fg_syscall3 (1, 2, (fg_addr_t)name, fg_string_length_bounded (name, 128));
  fg_syscall3 (1, 2, (fg_addr_t)newline, 1);
  fg_syscall3 (231, 127, 0, 0);
  for (;;)
    __asm__ volatile ("ud2");
}
FG_LOCAL const struct fg_name *
fg_policy_names (const struct fg_policy_info *p)
{
  return (const void *)(p + 1);
}
FG_LOCAL const fg_u32_t *
fg_policy_roots (const struct fg_policy_info *p)
{
  return (const void *)(fg_policy_names (p) + p->names);
}
FG_LOCAL const char *
fg_policy_strings (const struct fg_policy_info *p)
{
  return (const void *)(fg_policy_roots (p) + p->roots);
}
FG_LOCAL const struct fg_policy_info *
fg_policy_metadata (const struct fg_metadata_header *h)
{
  return (const void *)((const fg_u8_t *)(h + 1) + h->count * sizeof (struct fg_code_unit)
                        + h->patches * sizeof (struct fg_relocation_patch)
                        + h->frames * sizeof (struct fg_unwind_frame));
}
FG_LOCAL void
fg_policy_validate_metadata (const struct fg_metadata_header *h, fg_addr_t core)
{
  if (h->bytes < core + sizeof (struct fg_policy_info))
    fg_bootstrap_fail ();
  const struct fg_policy_info *p = fg_policy_metadata (h);
  if (p->names > 1000000 || p->roots > h->count || p->strings > 16000000
      || p->bytes
             != sizeof (*p) + p->names * sizeof (struct fg_name) + p->roots * sizeof (fg_u32_t)
                    + p->strings
      || h->bytes != core + p->bytes)
    fg_bootstrap_fail ();
  const struct fg_name *names = fg_policy_names (p);
  const char *strings = fg_policy_strings (p);
  for (fg_addr_t i = 0; i < p->names; ++i)
    {
      fg_addr_t unit = names[i].unit & ~FG_EXPORTED;
      if (!unit || unit > h->count || names[i].string >= p->strings
          || fg_string_length_bounded (strings + names[i].string, p->strings - names[i].string)
                 == p->strings - names[i].string
          || (i
              && fg_string_compare (strings + names[i - 1].string, strings + names[i].string) > 0))
        fg_bootstrap_fail ();
    }
  const fg_u32_t *roots = fg_policy_roots (p);
  for (fg_addr_t i = 0; i < p->roots; ++i)
    if (!roots[i] || roots[i] > h->count)
      fg_bootstrap_fail ();
}
FG_LOCAL fg_addr_t
fg_policy_find_name (const struct fg_policy_info *p, const char *name)
{
  const struct fg_name *names = fg_policy_names (p);
  const char *strings = fg_policy_strings (p);
  fg_addr_t lo = 0, hi = p->names;
  while (lo < hi)
    {
      fg_addr_t mid = lo + (hi - lo) / 2;
      if (fg_string_compare (strings + names[mid].string, name) < 0)
        lo = mid + 1;
      else
        hi = mid;
    }
  return lo;
}
FG_LOCAL int
fg_policy_mark_function (struct fg_state *s, const char *name, fg_u8_t flags, int exports_only)
{
  const struct fg_policy_info *p = s->info;
  const struct fg_name *names = fg_policy_names (p);
  const char *strings = fg_policy_strings (p);
  int found = 0;
  for (fg_addr_t i = fg_policy_find_name (p, name);
       i < p->names && !fg_string_compare (strings + names[i].string, name); ++i)
    {
      if (exports_only && !(names[i].unit & FG_EXPORTED))
        continue;
      fg_addr_t index = (names[i].unit & ~FG_EXPORTED) - 1;
      found = 1;
      if (flags)
        s->flags[index] |= flags;
      else if (!(s->flags[index] & 1))
        _dl_fg_policy_error ("late import of forbidden function: ", name);
    }
  return found;
}
FG_LOCAL void
fg_policy_process_imports (struct fg_state *s, const struct fg_imports *views, fg_addr_t count,
                           fg_u8_t mark)
{
  for (fg_addr_t i = 0; i < count; ++i)
    {
      const struct fg_imports *v = views + i;
      for (fg_addr_t j = 0; j < v->count; ++j)
        {
          fg_addr_t index = v->relocations[j].info >> 32;
          if (!index)
            continue;
          if (index >= v->symbol_count)
            fg_bootstrap_fail ();
          const struct fg_symbol *symbol = v->symbols + index;
          if (symbol->section)
            continue;
          if (symbol->name >= v->string_bytes)
            fg_bootstrap_fail ();
          const char *name = v->strings + symbol->name;
          if (fg_string_length_bounded (name, v->string_bytes - symbol->name)
              == v->string_bytes - symbol->name)
            fg_bootstrap_fail ();
          fg_policy_mark_function (s, name, mark, 1);
        }
    }
}
FG_LOCAL fg_addr_t
fg_policy_select_units (fg_addr_t base, const struct fg_metadata_header *h,
                        const struct fg_policy *policy, const struct fg_imports *views,
                        fg_addr_t views_count, fg_addr_t *order, struct fg_state **state)
{
  fg_addr_t bytes = (sizeof (struct fg_state) + h->count + 4095) & -4096UL;
  fg_saddr_t allocation = fg_syscall6 (9, 0, bytes, 3, 0x22, -1, 0);
  if (allocation < 0 && allocation >= -4095)
    fg_bootstrap_fail ();
  struct fg_state *s = (void *)allocation;
  s->bytes = bytes;
  s->base = base;
  s->head = h;
  s->info = fg_policy_metadata (h);
  for (fg_addr_t i = 0; i < h->count; ++i)
    s->flags[i] = policy->mode == 2 ? 1 : 0;
  for (fg_addr_t i = 0; i < policy->count; ++i)
    {
      const struct fg_rule *r = policy->rules[i];
      if (r->action == 1 || r->action == 2)
        if (!fg_policy_mark_function (s, r->name, r->action == 1 ? 5 : 2, 0))
          _dl_fg_policy_error ("unknown libc function: ", r->name);
    }
  if (policy->mode == 2)
    for (fg_addr_t i = 0; i < h->count; ++i)
      if ((s->flags[i] & 2) && !(s->flags[i] & 4))
        s->flags[i] &= ~1U;
  const fg_u32_t *roots = fg_policy_roots (s->info);
  for (fg_addr_t i = 0; i < s->info->roots; ++i)
    s->flags[roots[i] - 1] |= 1;
  fg_policy_process_imports (s, views, views_count, 1);
  fg_addr_t count = 0;
  for (fg_addr_t i = 0; i < h->count; ++i)
    if (s->flags[i] & 1)
      order[count++] = i;
  const struct fg_code_unit *u = (const void *)(h + 1);
  const struct fg_relocation_patch *patch = (const void *)(u + h->count);
  for (fg_addr_t j = 0; j < count; ++j)
    {
      fg_addr_t i = order[j];
      if (s->flags[i] & 2)
        {
          const struct fg_name *names = fg_policy_names (s->info);
          const char *strings = fg_policy_strings (s->info);
          for (fg_addr_t k = 0; k < s->info->names; ++k)
            if ((names[k].unit & ~FG_EXPORTED) == i + 1)
              _dl_fg_policy_error ("denied function is required: ", strings + names[k].string);
          fg_bootstrap_fail ();
        }
      for (fg_addr_t k = u[i].patch_first; k < (fg_addr_t)u[i].patch_first + u[i].patch_count; ++k)
        {
          fg_addr_t target = patch[k].value_unit;
          if (target && !(s->flags[target - 1] & 1))
            {
              s->flags[target - 1] |= 1;
              order[count++] = target - 1;
            }
        }
    }
  if (!count)
    _dl_fg_policy_error ("empty permitted function set", 0);
  for (fg_addr_t i = 0; i < h->count; ++i)
    s->flags[i] &= 1;
  *state = s;
  return count;
}
FG_BOOTSTRAP void
_dl_fg_check (fg_addr_t address, const struct fg_imports *views, fg_addr_t count)
{
  if (address)
    fg_policy_process_imports ((void *)address, views, count, 0);
}
FG_BOOTSTRAP void
_dl_fg_forget (fg_addr_t address)
{
  if (address)
    {
      struct fg_state *s = (void *)address;
      fg_addr_t bytes = s->bytes;
      fg_syscall3 (11, address, bytes, 0);
    }
}
/* Strong link/load dependency emitted by the public C header. */
__attribute__ ((section (".fgboot"), noinline, visibility ("default"))) void
_dl_fg_policy_v1 (void)
{
}
