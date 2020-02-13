------------------------------------------------------------------------------
--  Copyright (C) 2017-2020 by Heisenbug Ltd. (gh+saatana@heisenbug.eu)
--
--  This work is free. You can redistribute it and/or modify it under the
--  terms of the Do What The Fuck You Want To Public License, Version 2,
--  as published by Sam Hocevar. See the LICENSE file for more details.
------------------------------------------------------------------------------
pragma License (Unrestricted);

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
