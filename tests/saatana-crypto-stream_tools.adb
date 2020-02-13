------------------------------------------------------------------------------
--  Copyright (C) 2017-2020 by Heisenbug Ltd. (gh+saatana@heisenbug.eu)
--
--  This work is free. You can redistribute it and/or modify it under the
--  terms of the Do What The Fuck You Want To Public License, Version 2,
--  as published by Sam Hocevar. See the LICENSE file for more details.
------------------------------------------------------------------------------
pragma License (Unrestricted);

package body Saatana.Crypto.Stream_Tools with
  SPARK_Mode => Off
is

   function To_Stream (Value : in String) return General_Stream;
   function To_Stream (Value : in String) return General_Stream is
      Result : General_Stream (0 .. Value'Length / 2 - 1);
   begin
      for I in Result'Range loop
         Convert_Hex_Byte :
         declare
            Str_Idx : constant Positive := Value'First + Natural (I) * 2;
         begin
            Result (I) := Byte'Value ("16#" & Value (Str_Idx .. Str_Idx + 1) & "#");
         end Convert_Hex_Byte;
      end loop;

      return Result;
   end To_Stream;

   function To_Stream (Value : in String) return Ciphertext_Stream_Access is
   begin
      return new Ciphertext_Stream'(Ciphertext_Stream (General_Stream'(To_Stream (Value))));
   end To_Stream;

   function To_Stream (Value : in String) return Key_Stream_Access is
   begin
      return new Key_Stream'(Key_Stream (General_Stream'(To_Stream (Value))));
   end To_Stream;

   function To_Stream (Value : in String) return MAC_Stream_Access is
   begin
      return new MAC_Stream'(MAC_Stream (General_Stream'(To_Stream (Value))));
   end To_Stream;

   function To_Stream (Value : in String) return Nonce_Stream_Access is
   begin
      return new Nonce_Stream'(Nonce_Stream (General_Stream'(To_Stream (Value))));
   end To_Stream;

   function To_Stream (Value : in String) return Plaintext_Stream_Access is
   begin
      return new Plaintext_Stream'(Plaintext_Stream (General_Stream'(To_Stream (Value))));
   end To_Stream;

end Saatana.Crypto.Stream_Tools;
