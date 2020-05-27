------------------------------------------------------------------------------
--  Copyright (C) 2017-2020 by Heisenbug Ltd. (gh+saatana@heisenbug.eu)
--
--  This work is free. You can redistribute it and/or modify it under the
--  terms of the Do What The Fuck You Want To Public License, Version 2,
--  as published by Sam Hocevar. See the LICENSE file for more details.
------------------------------------------------------------------------------
pragma License (Unrestricted);

------------------------------------------------------------------------------
--
--  Crypto root package.
--
--  Defines encryption stream primitives.
--
------------------------------------------------------------------------------

with Interfaces;

package Saatana.Crypto with
  Pure       => True,
  SPARK_Mode => On
is

   type Stream_Offset   is               range -2 ** 62 .. 2 ** 62 - 1; --  Restrict the range to accomodate the prover.
   subtype Stream_Index is Stream_Offset range 0 .. 2 ** 60 - 1;
   subtype Stream_Count is Stream_Offset range 0 .. 2 ** 62 - 1;

   type Byte is new Interfaces.Unsigned_8;
   type Word_32 is new Interfaces.Unsigned_32; --  "Word" would be confusing on 64 bit machines.

   --  For type conversions.
   type General_Stream is array (Stream_Index range <>) of Byte;

   --
   --  To_Unsigned
   --
   --  Converts the maximum four first values of the given Stream to a Word_32,
   --  assuming Low_Order_First byte order (little endian).
   --
   function To_Unsigned (Value : in General_Stream) return Word_32 with
     Global  => null,
     Depends => (To_Unsigned'Result => (Value)),
     Post    => (To_Unsigned'Result = (if Value'Length > 0 then (Shift_Left (Word_32 (Value (Value'First)),      0)) else 0) +
                                      (if Value'Length > 1 then (Shift_Left (Word_32 (Value (Value'First + 1)),  8)) else 0) +
                                      (if Value'Length > 2 then (Shift_Left (Word_32 (Value (Value'First + 2)), 16)) else 0) +
                                      (if Value'Length > 3 then (Shift_Left (Word_32 (Value (Value'First + 3)), 24)) else 0));

   --
   --  To_Stream
   --
   --  Converts the given Word_32 value to a stream in Low_Order_First
   --  byte order (little endian).
   --
   function To_Stream (Value : in Word_32) return General_Stream with
     Global  => null,
     Depends => (To_Stream'Result => Value),
     Post    => ((To_Stream'Result'Length = 4 and To_Stream'Result'First = 0) and then
                 To_Stream'Result = (0 => Byte (Shift_Right (Value,  0) mod 256),
                                     1 => Byte (Shift_Right (Value,  8) mod 256),
                                     2 => Byte (Shift_Right (Value, 16) mod 256),
                                     3 => Byte (Shift_Right (Value, 24) mod 256)));

   --  Provide some basic primitives.
   type Ciphertext_Stream is new General_Stream with Relaxed_Initialization;
   type Key_Stream        is new General_Stream;
   type Plaintext_Stream  is new General_Stream with Relaxed_Initialization;
   type MAC_Stream        is new General_Stream;
   type Nonce_Stream      is new General_Stream;

   function "+" (Left  : in Nonce_Stream;
                 Right : in Nonce_Stream) return Nonce_Stream with
     Global  => null,
     Depends => ("+"'Result => (Left,
                                Right)),
     Pre     => (Right'Length = Left'Length);

private

   --
   --  To_Stream
   --
   function To_Stream (Value : in Word_32) return General_Stream is
     (General_Stream'
       (0 => Byte (Value / 2 **  0 mod 256),
        1 => Byte (Value / 2 **  8 mod 256),
        2 => Byte (Value / 2 ** 16 mod 256),
        3 => Byte (Value / 2 ** 24 mod 256)));

   --
   --  To_Unsigned
   --
   --  Converts the maximum four first values of the given Stream to a Word_32,
   --  assuming Low_Order_First byte order (little endian).
   --
   function To_Unsigned (Value : in General_Stream) return Word_32 is
     ((if Value'Length > 0 then Word_32 (Value (Value'First + 0)) * 2 **  0 else 0) +
      (if Value'Length > 1 then Word_32 (Value (Value'First + 1)) * 2 **  8 else 0) +
      (if Value'Length > 2 then Word_32 (Value (Value'First + 2)) * 2 ** 16 else 0) +
      (if Value'Length > 3 then Word_32 (Value (Value'First + 3)) * 2 ** 24 else 0));

end Saatana.Crypto;
