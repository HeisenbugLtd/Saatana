package Crypto.Stream_Tools with
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

end Crypto.Stream_Tools;
