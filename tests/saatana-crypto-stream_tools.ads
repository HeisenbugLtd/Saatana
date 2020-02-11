------------------------------------------------------------------------------
--  Source code copyright (C) 2017-2020 by Heisenbug Ltd.                   --
--                                                                          --
--  DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE                             --
--                      Version 2, December 2004                            --
--                                                                          --
--   Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>                       --
--                                                                          --
--   Everyone is permitted to copy and distribute verbatim or modified      --
--   copies of this license document, and changing it is allowed as long    --
--   as the name is changed.                                                --
--                                                                          --
--              DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE                 --
--     TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION      --
--                                                                          --
--    0. You just DO WHAT THE FUCK YOU WANT TO.                             --
------------------------------------------------------------------------------

package Saatana.Crypto.Stream_Tools with
  SPARK_Mode => Off
is

   type Ciphertext_Stream_Access is not null access constant Ciphertext_Stream;
   type Key_Stream_Access        is not null access constant Key_Stream;
   type MAC_Stream_Access        is not null access constant MAC_Stream;
   type Nonce_Stream_Access      is not null access constant Nonce_Stream;
   type Plaintext_Stream_Access  is not null access constant Plaintext_Stream;

   function To_Stream (Value : in String) return Ciphertext_Stream_Access;
   function To_Stream (Value : in String) return Key_Stream_Access;
   function To_Stream (Value : in String) return MAC_Stream_Access;
   function To_Stream (Value : in String) return Nonce_Stream_Access;
   function To_Stream (Value : in String) return Plaintext_Stream_Access;

end Saatana.Crypto.Stream_Tools;
