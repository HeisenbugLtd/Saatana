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

package body Crypto is

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
         declare
            Operand_Idx : constant Stream_Index := Result_Idx - Result'First + Right'First;
         begin
            Add_Carry (Left   => Result (Result_Idx),
                       Right  => Right (Operand_Idx),
                       Carry  => Carry);
         end;
      end loop;

      return Result;
   end "+";

end Crypto;
