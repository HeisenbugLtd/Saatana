with Interfaces;

package Crypto with
  Pure       => True,
  SPARK_Mode => On
is

   type Stream_Offset   is               range 0 .. 2 ** 62 - 1; --  Restrict the range to accomodate the prover.
   subtype Stream_Index is Stream_Offset range 0 .. 2 ** 60 - 1;
   subtype Stream_Count is Stream_Offset;

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
                 Right : in Byte) return Nonce_Stream;

end Crypto;
