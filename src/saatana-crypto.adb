------------------------------------------------------------------------------
--  Copyright (C) 2017-2020 by Heisenbug Ltd. (gh+saatana@heisenbug.eu)
--
--  This work is free. You can redistribute it and/or modify it under the
--  terms of the Do What The Fuck You Want To Public License, Version 2,
--  as published by Sam Hocevar. See the LICENSE file for more details.
------------------------------------------------------------------------------
pragma License (Unrestricted);

package body Saatana.Crypto is

   --
   --  "+"
   --
   function "+" (Left  : in Nonce_Stream;
                 Right : in Nonce_Stream) return Nonce_Stream
   is
      procedure Add_Carry (Left   : in out Byte;
                           Right  : in     Byte;
                           Carry  : in out Boolean) with
        Inline  => True,
        Depends => (Left => (Left,
                             Right,
                             Carry),
                    Carry => (Left,
                              Right)),
        Post    => (Left = Left'Old + Right + Boolean'Pos (Carry'Old) and then
                    Carry = (Left'Old + Right < Left'Old));

      procedure Add_Carry (Left   : in out Byte;
                           Right  : in     Byte;
                           Carry  : in out Boolean)
      is
         Old_Carry : constant Boolean := Carry;
      begin
         Left := Left + Right;

         Carry := Left < Right;
         Left  := Left + Boolean'Pos (Old_Carry);
      end Add_Carry;

      Result : Nonce_Stream := Left;
      Carry  : Boolean      := False;
   begin
      for Result_Idx in Result'Range loop
         Add_Byte_With_Carry :
         declare
            Operand_Idx : constant Stream_Index := Result_Idx - Result'First + Right'First;
         begin
            Add_Carry (Left   => Result (Result_Idx),
                       Right  => Right (Operand_Idx),
                       Carry  => Carry);
         end Add_Byte_With_Carry;
      end loop;

      return Result;
   end "+";

end Saatana.Crypto;
