# Vendor data attribution

Files in this directory are third-party Minecraft 26.2 protocol data used for
local development of Neptunium's configuration-phase handshake:

* `protocol-26.2.json` — packet structures from PrismarineJS `minecraft-data`
  (`pc_26_2` branch). License: MIT (PrismarineJS).
* `registry-fallback-26.2.mcr`, `tags-26.2.mcr` — byte captures of the
  official 26.2 server's Registry Data / Tags payloads, format by
  cmarshall108/mcsquared (`docs/generated/`). Check that repo's LICENSE
  before publishing any Neptunium release containing these bytes.
* `loginPacket-26.2.json` — Play Login defaults from PrismarineJS
  `minecraft-data` (`pc_26_2` branch). License: MIT.

These files are build inputs only (parsed at compile time via `include_str!`
where used). They are committed so the repo builds offline.
