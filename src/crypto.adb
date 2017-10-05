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

   ---------
   -- "+" --
   ---------

   function "+" (Left  : in Nonce_Stream;
                 Right : in Byte) return Nonce_Stream
   is
      Result : Nonce_Stream := Left;
   begin
      if Result'Length > 0 then
         Result (Result'First) := Result (Result'First) + Right;

         if Result (Result'First) < Right and then Result'Length > 1 then
            --  If there was an overflow, we successively need to add 1 to the Nonce.
            declare
               Idx : Stream_Index := Result'First + 1;
            begin
               Add_Carry : loop
                  Result (Idx) := Result (Idx) + 1;
                  exit Add_Carry when Result (Idx) /= 0 or Idx = Result'Last;

                  Idx := Idx + 1;
                  pragma Loop_Invariant (Idx in Result'Range);
               end loop Add_Carry;
            end;
         end if;
      end if;

      return Result;
   end "+";

end Crypto;
