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

         if Result (Result'First) < Right then
            --  If there was an overflow, we successively need to add 1 to the Nonce.
            declare
               Idx : Stream_Index := Result'First + 1;
            begin
               Add_Carry : loop
                  Result (Idx) := Result (Idx) + 1;
                  exit Add_Carry when Result (Idx) /= 0 or Idx = Result'Last;

                  Idx := Idx + 1;
               end loop Add_Carry;
            end;
         end if;
      end if;

      return Result;
   end "+";

end Crypto;
