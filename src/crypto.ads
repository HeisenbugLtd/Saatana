------------------------------------------------------------------------------
--  Source code copyright (C) 2017 by Heisenbug Ltd.                        --
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

------------------------------------------------------------------------------
--
--  Crypto root package.
--
--  Defines encryption stream primitives.
--
------------------------------------------------------------------------------

with Interfaces;

package Crypto with
  Pure       => True,
  SPARK_Mode => On
is

   type Stream_Offset   is               range -2 ** 62 .. 2 ** 62 - 1; --  Restrict the range to accomodate the prover.
   subtype Stream_Index is Stream_Offset range 0 .. 2 ** 60 - 1;
   subtype Stream_Count is Stream_Offset range 0 .. 2 ** 62 - 1;

   type Byte is new Interfaces.Unsigned_8;

   --  For type conversions.
   type General_Stream    is array (Stream_Index range <>) of Byte;

   --  Provide some basic primitives.
   type Ciphertext_Stream is new General_Stream;
   type Key_Stream        is new General_Stream;
   type Plaintext_Stream  is new General_Stream;
   type MAC_Stream        is new General_Stream;
   type Nonce_Stream      is new General_Stream;

   function "+" (Left  : in Nonce_Stream;
                 Right : in Nonce_Stream) return Nonce_Stream with
     Global  => null,
     Depends => ("+"'Result => (Left,
                                Right)),
     Pre     => (Right'Length = Left'Length);

end Crypto;
