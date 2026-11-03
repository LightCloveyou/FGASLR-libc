/* Private native ld interface. SPDX-License-Identifier: 0BSD */
#ifndef DL_FG_POLICY_H
#define DL_FG_POLICY_H
#define FG_RULE_LIMIT 256
#define FG_VIEW_LIMIT 512
#define FG_EXPORTED 0x80000000U
struct fg_rule
{
  unsigned int magic, version, action;
  char name[128];
};
struct fg_policy
{
  unsigned long mode, count;
  const struct fg_rule *rules[FG_RULE_LIMIT];
};
struct fg_symbol
{
  unsigned int name;
  unsigned char info, other;
  unsigned short section;
  unsigned long value, size;
};
struct fg_rela
{
  unsigned long offset, info;
  long addend;
};
struct fg_imports
{
  const struct fg_symbol *symbols;
  const char *strings;
  unsigned long symbol_count, string_bytes;
  const struct fg_rela *relocations;
  unsigned long count;
};
/* Appended to v5 Unit/Patch/Frame metadata. Names sorted by string then unit.
 * unit is one-based; its high bit marks an exported name for import checking.
 */
struct fg_policy_info
{
  unsigned long names, roots, strings, bytes;
};
struct fg_name
{
  unsigned int string, unit;
};
#endif
