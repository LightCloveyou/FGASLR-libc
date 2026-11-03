/* Internal bootstrap regression tests. SPDX-License-Identifier: 0BSD */
#include <assert.h>
#include <stdio.h>
#include "../native/runtime/dl-fgkaslr.c"

_Static_assert (sizeof (struct fg_metadata_header) == 120, "v5 metadata header ABI");
_Static_assert (sizeof (struct fg_code_unit) == 40, "v5 code unit ABI");
_Static_assert (sizeof (struct fg_relocation_patch) == 32, "v5 patch ABI");
_Static_assert (sizeof (struct fg_unwind_frame) == 16, "v5 unwind frame ABI");
_Static_assert (sizeof (struct fg_policy_info) == 32, "v5 policy header ABI");

static void
test_address_translation (void)
{
  const struct fg_code_unit units[2]
      = { { .start = 100, .size = 20 }, { .start = 200, .size = 32 } };
  const fg_addr_t destinations[2] = { 400, 300 };
  assert (fg_translate_address (99, units, destinations, 2) == 99);
  assert (fg_translate_address (100, units, destinations, 2) == 400);
  assert (fg_translate_address (119, units, destinations, 2) == 419);
  assert (fg_translate_address (120, units, destinations, 2) == 120);
  assert (fg_translate_address (208, units, destinations, 2) == 308);
}

static void
test_memory_and_patches (void)
{
  fg_u8_t buffer[16];
  const fg_u8_t source[4] = { 1, 2, 3, 4 };
  fg_fill_bytes (buffer, 0xcc, sizeof (buffer));
  fg_copy_bytes (buffer, source, sizeof (source));
  assert (buffer[0] == 1 && buffer[3] == 4 && buffer[4] == 0xcc);

  fg_addr_t output = 0;
  const fg_addr_t destinations[1] = { 1000 };
  struct fg_relocation_patch relocation = { .dest = 0, .value = 8, .value_unit = 1, .width = 8 };
  fg_apply_patch (&relocation, destinations, 0, (fg_addr_t)&output);
  assert (output == 1008);
  relocation.width = 4;
  relocation.value_unit = 0;
  relocation.value = 100;
  relocation.relative = 1;
  relocation.bias = 5;
  fg_apply_patch (&relocation, destinations, 0, (fg_addr_t)&output);
  assert (output == 105);
}

static void
test_range_validation (void)
{
  struct fg_elf_phdr segment = { .type = 1, .flags = 5, .va = 100, .memsz = 100 };
  assert (fg_range_is_mapped (&segment, 1, 100, 100, 0, 0));
  assert (!fg_range_is_mapped (&segment, 1, 100, 101, 0, 0));
  assert (!fg_range_is_mapped (&segment, 1, 120, 10, 125, 140));
  assert (!fg_range_is_mapped (&segment, 1, (fg_addr_t)-2, 4, 0, 0));
  segment.pa = FG_METADATA_MARKER;
  assert (!fg_range_is_mapped (&segment, 1, 100, 10, 0, 0));
}

static void
test_random_ranges_and_strings (void)
{
  struct fg_random_state random = { 0 };
  for (unsigned int i = 0; i < 2048; ++i)
    {
      assert (fg_random_below (&random, 17) < 17);
      assert (fg_random_gap (&random) <= FG_MAX_RANDOM_GAP);
    }
  assert (fg_string_length_bounded ("hello", 3) == 3);
  assert (fg_string_length_bounded ("hello", 8) == 5);
  assert (fg_string_compare ("alpha", "beta") < 0);
  assert (fg_string_compare ("same", "same") == 0);
}

int
main (void)
{
  test_address_translation ();
  test_memory_and_patches ();
  test_range_validation ();
  test_random_ranges_and_strings ();
  puts ("PASS: native ABI, address translation, patching, memory, ranges and entropy");
  return 0;
}
