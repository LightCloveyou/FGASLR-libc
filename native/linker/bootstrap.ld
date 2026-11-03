SECTIONS
{
  .fgspace : { *(.fgspace) }
  .fgboot ALIGN(4096) : { *(.fgboot) . = ALIGN(4096); }
}
INSERT AFTER .text;
