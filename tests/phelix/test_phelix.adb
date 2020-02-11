------------------------------------------------------------------------------
--  Source code copyright (C) 2017-2020 by Heisenbug Ltd.                   --
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

with Ada.Text_IO;
with Saatana.Crypto.Phelix.Test_Vectors;

procedure Test_Phelix with
  SPARK_Mode => Off
is
   pragma Assertion_Policy (Check);

   use type Saatana.Crypto.MAC_Stream;
   use type Saatana.Crypto.Stream_Offset;

   Num_Tests      : Natural := 0;
   Num_Succeeded  : Natural := 0;

   procedure Add_Test (Passed : in Boolean);
   procedure Add_Test (Passed : in Boolean) is
   begin
      Num_Tests := Num_Tests + 1;

      Num_Succeeded := (if Passed then Num_Succeeded + 1 else Num_Succeeded);

      if not Passed then
         Ada.Text_IO.Put_Line ("<ERR> Test" & Natural'Image (Num_Tests) & " failed!");
      end if;
   end Add_Test;

   function Image (S : in Saatana.Crypto.General_Stream) return String;
   function Image (S : in Saatana.Crypto.General_Stream) return String
   is
      Result   : String (1 .. S'Length * 2);
      Hex_Char : constant array (Saatana.Crypto.Byte range 0 .. 15) of Character := "0123456789ABCDEF";
      use type Saatana.Crypto.Byte;
   begin
      for I in S'Range loop
         Result (Result'First + Natural (I - S'First) * 2)     := Hex_Char (S (I) / 16);
         Result (Result'First + Natural (I - S'First) * 2 + 1) := Hex_Char (S (I) mod 16);
      end loop;

      return Result;
   end Image;

begin
   Ada.Text_IO.Put_Line ("Running Phelix tests...");

   for T of Saatana.Crypto.Phelix.Test_Vectors.KAT loop
      declare
         use type Saatana.Crypto.Ciphertext_Stream;
         use type Saatana.Crypto.Plaintext_Stream;
         use type Saatana.Crypto.Phelix.MAC_Size_32;

         Mac_Len : constant Saatana.Crypto.Phelix.MAC_Size_32 := 8 * T.MAC.all'Length;
         This    :          Saatana.Crypto.Phelix.Context;
      begin
         Saatana.Crypto.Phelix.Setup_Key (This     => This,
                                  Key      => T.Key.all,
                                  Mac_Size => Mac_Len);

         declare
            Result_Cipher    : Saatana.Crypto.Ciphertext_Stream (T.Plaintext.all'Range);
            Result_Plaintext : Saatana.Crypto.Plaintext_Stream (T.Plaintext.all'Range);
            Result_MAC       : Saatana.Crypto.MAC_Stream (0 .. Saatana.Crypto.Stream_Offset (Mac_Len) / 8  - 1);
         begin
            Saatana.Crypto.Phelix.Setup_Nonce (This  => This,
                                       Nonce => T.Nonce.all);
            Saatana.Crypto.Phelix.Process_AAD (This => This,
                                       Aad  => T.Aad.all);
            Saatana.Crypto.Phelix.Encrypt_Bytes (This        => This,
                                         Source      => T.Plaintext.all,
                                         Destination => Result_Cipher);
            Saatana.Crypto.Phelix.Finalize (This => This,
                                    Mac  => Result_MAC);

            Add_Test (Result_Cipher = T.Cipher.all);
            Add_Test (Result_MAC = T.MAC.all);

            Saatana.Crypto.Phelix.Setup_Nonce (This  => This,
                                       Nonce => T.Nonce.all);
            Saatana.Crypto.Phelix.Process_AAD (This => This,
                                       Aad  => T.Aad.all);
            Saatana.Crypto.Phelix.Decrypt_Bytes (This        => This,
                                         Source      => T.Cipher.all,
                                         Destination => Result_Plaintext);
            Saatana.Crypto.Phelix.Finalize (This => This,
                                    Mac  => Result_MAC);

            Add_Test (Result_Plaintext = T.Plaintext.all);
            Add_Test (Result_MAC = T.MAC.all);
         end;

         declare
            Enc_Packet : Saatana.Crypto.Ciphertext_Stream (0 .. T.Plaintext.all'Length + T.Aad.all'Length - 1);
            Dec_Packet : Saatana.Crypto.Plaintext_Stream (0 .. T.Plaintext.all'Length + T.Aad.all'Length - 1);
            Result_MAC : Saatana.Crypto.MAC_Stream (0 .. Saatana.Crypto.Stream_Offset (Mac_Len) / 8  - 1);
         begin
            Saatana.Crypto.Phelix.Encrypt_Packet (This    => This,
                                          Nonce   => T.Nonce.all,
                                          Header  => T.Aad.all,
                                          Payload => T.Plaintext.all,
                                          Packet  => Enc_Packet,
                                          Mac     => Result_MAC);
            Add_Test (Saatana.Crypto.Ciphertext_Stream (T.Aad.all) & T.Cipher.all = Enc_Packet);
            Add_Test (Result_MAC = T.MAC.all);

            Saatana.Crypto.Phelix.Decrypt_Packet (This    => This,
                                          Nonce   => T.Nonce.all,
                                          Header  => T.Aad.all,
                                          Payload => T.Cipher.all,
                                          Packet  => Dec_Packet,
                                          Mac     => Result_MAC);
            Add_Test (T.Aad.all & T.Plaintext.all = Dec_Packet);
            Add_Test (Result_MAC = T.MAC.all);
         end;
      end;
   end loop;

   declare
      KEY_LENGTH   : constant := Saatana.Crypto.Phelix.Max_Key_Size / 8;
      MAC_LENGTH   : constant := Saatana.Crypto.Phelix.Max_MAC_Size / 8;
      NONCE_LENGTH : constant := Saatana.Crypto.Phelix.Max_Nonce_Size / 8;

      NONCE_FIRST : constant Saatana.Crypto.Stream_Offset  := 0;
      NONCE_LAST  : constant Saatana.Crypto.Stream_Offset  := NONCE_FIRST + NONCE_LENGTH - 1;
      MAC_FIRST   : constant Saatana.Crypto.Stream_Offset  := NONCE_LAST + 1;
      MAC_LAST    : constant Saatana.Crypto.Stream_Offset  := MAC_FIRST + MAC_LENGTH - 1;
      EMPTY       : constant Saatana.Crypto.General_Stream := (1 .. 0 => 0);

      use type Saatana.Crypto.Byte;
      use type Saatana.Crypto.Ciphertext_Stream;
      use type Saatana.Crypto.Key_Stream;
      use type Saatana.Crypto.Nonce_Stream;
      use type Saatana.Crypto.Phelix.MAC_Size_32;

      procedure Send_Nonce (Key    : in     Saatana.Crypto.Key_Stream;
                            Nonce  : in     Saatana.Crypto.Nonce_Stream;
                            Packet :    out Saatana.Crypto.Ciphertext_Stream);
      procedure Receive_Nonce (Key           : in     Saatana.Crypto.Key_Stream;
                               Packet        : in     Saatana.Crypto.Ciphertext_Stream;
                               Authenticated :    out Boolean);

      procedure Receive_Nonce (Key           : in     Saatana.Crypto.Key_Stream;
                               Packet        : in     Saatana.Crypto.Ciphertext_Stream;
                               Authenticated :    out Boolean)
      is
         Ctx   : Saatana.Crypto.Phelix.Context;
         Mac   : Saatana.Crypto.MAC_Stream (0 .. MAC_LENGTH - 1);
         Nonce : constant Saatana.Crypto.Nonce_Stream := Saatana.Crypto.Nonce_Stream (Packet (NONCE_FIRST .. NONCE_LAST));
         Received_Nonce : Saatana.Crypto.Nonce_Stream (0 .. NONCE_LENGTH - 1);
      begin
         Saatana.Crypto.Phelix.Setup_Key (This     => Ctx,
                                  Key      => Key,
                                  Mac_Size => MAC_LENGTH * 8);
         --  Verify received packet.
         Saatana.Crypto.Phelix.Decrypt_Packet (This    => Ctx,
                                       Nonce   => Nonce,
                                       Header  => Saatana.Crypto.Plaintext_Stream (Nonce),
                                       Payload => Saatana.Crypto.Ciphertext_Stream (EMPTY),
                                       Packet  => Saatana.Crypto.Plaintext_Stream (Received_Nonce),
                                       Mac     => Mac);
         --  MAC must match, otherwise someone tampered with our packet.
         Authenticated := Mac = Saatana.Crypto.MAC_Stream (Packet (MAC_FIRST .. MAC_LAST));
      end Receive_Nonce;

      procedure Send_Nonce (Key    : in     Saatana.Crypto.Key_Stream;
                            Nonce  : in     Saatana.Crypto.Nonce_Stream;
                            Packet :    out Saatana.Crypto.Ciphertext_Stream) is
         Ctx : Saatana.Crypto.Phelix.Context;
      begin
         Saatana.Crypto.Phelix.Setup_Key (This     => Ctx,
                                  Key      => Key,
                                  Mac_Size => MAC_LENGTH * 8);
         --  Transmit that Nonce to the client.
         Saatana.Crypto.Phelix.Encrypt_Packet (This    => Ctx,
                                       Nonce   => Nonce,
                                       Header  => Saatana.Crypto.Plaintext_Stream (Nonce),
                                       Payload => Saatana.Crypto.Plaintext_Stream (EMPTY),
                                       Packet  => Packet (NONCE_FIRST .. NONCE_LAST),
                                       Mac     => Saatana.Crypto.MAC_Stream (Packet (MAC_FIRST .. MAC_LAST)));
      end Send_Nonce;

      Key           : Saatana.Crypto.Key_Stream (0 .. KEY_LENGTH - 1);
      Nonce         : Saatana.Crypto.Nonce_Stream (0 .. NONCE_LENGTH - 1);
      Packet        : Saatana.Crypto.Ciphertext_Stream (NONCE_FIRST .. MAC_LAST);
      Authenticated : Boolean;
   begin
      --  Communication setup.
      Key   := (others => 0);
      --  Generate random/unique nonce.
      Nonce := (others => 0);

      for I in 1 .. 1024 loop
         Send_Nonce (Key    => Key,
                     Nonce  => Nonce,
                     Packet => Packet);

         Ada.Text_IO.Put_Line ("Key   : " & Image (Saatana.Crypto.General_Stream (Key)));
         Ada.Text_IO.Put_Line ("Nonce : " & Image (Saatana.Crypto.General_Stream (Nonce)));
         Ada.Text_IO.Put_Line ("Packet: " & Image (Saatana.Crypto.General_Stream (Packet)));
         Ada.Text_IO.New_Line;

         --  Check if the MAC matches with whatever has been sent.
         Receive_Nonce (Key           => Key,
                        Packet        => Packet,
                        Authenticated => Authenticated);
         Add_Test (Authenticated);

         --  Tamper with the packet. Authentication should fail now.
         Receive_Nonce (Key           => Key,
                        Packet        => (Packet (Packet'First) xor 1) & Packet (Packet'First + 1 .. Packet'Last),
                        Authenticated => Authenticated);
         Add_Test (not Authenticated);

         --  Use Nonce and MAC as new Key and increment the nonce.
         Key := Saatana.Crypto.Key_Stream (Packet (MAC_FIRST .. MAC_LAST)) & Key (NONCE_FIRST .. NONCE_LAST);

         --  "Randomly" advance Nonce.
         for J in 1 .. Key (Key'First) loop
            for K in 1 .. Key (Key'First + 1) loop
               Nonce := Nonce + Saatana.Crypto.Nonce_Stream (Key (Key'First .. Key'First + 13) & (14 .. NONCE_LENGTH - 1 => 0));
            end loop;
         end loop;
      end loop;
   end;

   Ada.Text_IO.Put_Line ("Test results:"
                         & Natural'Image (Num_Succeeded)
                         & " out of" & Natural'Image (Num_Tests)
                         & " succeeded.");
   Ada.Text_IO.Put_Line (if Num_Tests = Num_Succeeded then "<OK>" else "<FAILED>");
end Test_Phelix;
