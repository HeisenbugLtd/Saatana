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

with Ada.Text_IO;
with Crypto.Phelix.Test_Vectors;
with Interfaces;

procedure Test_Phelix with
  SPARK_Mode => Off
is
   pragma Assertion_Policy (Check);

   use type Crypto.MAC_Stream;
   use type Crypto.Stream_Offset;

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

   function Image (S : in Crypto.General_Stream) return String;
   function Image (S : in Crypto.General_Stream) return String
   is
      Result   : String (1 .. S'Length * 2);
      Hex_Char : constant array (Crypto.Byte range 0 .. 15) of Character := "0123456789ABCDEF";
      use type Crypto.Byte;
   begin
      for I in S'Range loop
         Result (Result'First + Natural (I - S'First) * 2)     := Hex_Char (S (I) / 16);
         Result (Result'First + Natural (I - S'First) * 2 + 1) := Hex_Char (S (I) mod 16);
      end loop;

      return Result;
   end Image;

begin
   Ada.Text_IO.Put_Line ("Running Phelix tests...");

   for T of Crypto.Phelix.Test_Vectors.KAT loop
      declare
         use type Crypto.Ciphertext_Stream;
         use type Crypto.Plaintext_Stream;
         use type Interfaces.Unsigned_32;

         Mac_Len : constant Crypto.Phelix.MAC_Size_32 := 8 * T.MAC.all'Length;
         This    :          Crypto.Phelix.Context;
      begin
         Crypto.Phelix.Setup_Key (This     => This,
                                  Key      => T.Key.all,
                                  Mac_Size => Mac_Len);

         declare
            Result_Cipher    : Crypto.Ciphertext_Stream (T.Plaintext.all'Range);
            Result_Plaintext : Crypto.Plaintext_Stream (T.Plaintext.all'Range);
            Result_MAC       : Crypto.MAC_Stream (0 .. Crypto.Stream_Offset (Mac_Len) / 8  - 1);
         begin
            Crypto.Phelix.Setup_Nonce (This  => This,
                                       Nonce => T.Nonce.all);
            Crypto.Phelix.Process_AAD (This => This,
                                       Aad  => T.Aad.all);
            Crypto.Phelix.Encrypt_Bytes (This        => This,
                                         Source      => T.Plaintext.all,
                                         Destination => Result_Cipher);
            Crypto.Phelix.Finalize (This => This,
                                    Mac  => Result_MAC);

            Add_Test (Result_Cipher = T.Cipher.all);
            Add_Test (Result_MAC = T.MAC.all);

            Crypto.Phelix.Setup_Nonce (This  => This,
                                       Nonce => T.Nonce.all);
            Crypto.Phelix.Process_AAD (This => This,
                                       Aad  => T.Aad.all);
            Crypto.Phelix.Decrypt_Bytes (This        => This,
                                         Source      => T.Cipher.all,
                                         Destination => Result_Plaintext);
            Crypto.Phelix.Finalize (This => This,
                                    Mac  => Result_MAC);

            Add_Test (Result_Plaintext = T.Plaintext.all);
            Add_Test (Result_MAC = T.MAC.all);
         end;

         declare
            Enc_Packet : Crypto.Ciphertext_Stream (0 .. T.Plaintext.all'Length + T.Aad.all'Length - 1);
            Dec_Packet : Crypto.Plaintext_Stream (0 .. T.Plaintext.all'Length + T.Aad.all'Length - 1);
            Result_MAC : Crypto.MAC_Stream (0 .. Crypto.Stream_Offset (Mac_Len) / 8  - 1);
         begin
            Crypto.Phelix.Encrypt_Packet (This    => This,
                                          Nonce   => T.Nonce.all,
                                          Header  => T.Aad.all,
                                          Payload => T.Plaintext.all,
                                          Packet  => Enc_Packet,
                                          Mac     => Result_MAC);
            Add_Test (Crypto.Ciphertext_Stream (T.Aad.all) & T.Cipher.all = Enc_Packet);
            Add_Test (Result_MAC = T.MAC.all);

            Crypto.Phelix.Decrypt_Packet (This    => This,
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
      use type Crypto.Nonce_Stream;

      KEY_LENGTH   : constant := Crypto.Phelix.Max_Key_Size / 8;
      MAC_LENGTH   : constant := Crypto.Phelix.Max_MAC_Size / 8;
      NONCE_LENGTH : constant := Crypto.Phelix.Max_Nonce_Size / 8;

      NONCE_FIRST : constant Crypto.Stream_Offset  := 0;
      NONCE_LAST  : constant Crypto.Stream_Offset  := NONCE_FIRST + NONCE_LENGTH - 1;
      MAC_FIRST   : constant Crypto.Stream_Offset  := NONCE_LAST + 1;
      MAC_LAST    : constant Crypto.Stream_Offset  := MAC_FIRST + MAC_LENGTH - 1;
      EMPTY       : constant Crypto.General_Stream := (1 .. 0 => 0);

      use type Crypto.Byte;
      use type Crypto.Ciphertext_Stream;
      use type Crypto.Key_Stream;
      use type Crypto.Phelix.MAC_Size_32;

      procedure Send_Nonce (Key    : in     Crypto.Key_Stream;
                            Nonce  : in     Crypto.Nonce_Stream;
                            Packet :    out Crypto.Ciphertext_Stream);
      procedure Receive_Nonce (Key           : in     Crypto.Key_Stream;
                               Packet        : in     Crypto.Ciphertext_Stream;
                               Authenticated :    out Boolean);

      procedure Receive_Nonce (Key           : in     Crypto.Key_Stream;
                               Packet        : in     Crypto.Ciphertext_Stream;
                               Authenticated :    out Boolean)
      is
         Ctx   : Crypto.Phelix.Context;
         Mac   : Crypto.MAC_Stream (0 .. MAC_LENGTH - 1);
         Nonce : constant Crypto.Nonce_Stream := Crypto.Nonce_Stream (Packet (NONCE_FIRST .. NONCE_LAST));
         Received_Nonce : Crypto.Nonce_Stream (0 .. NONCE_LENGTH - 1);
      begin
         Crypto.Phelix.Setup_Key (This     => Ctx,
                                  Key      => Key,
                                  Mac_Size => MAC_LENGTH * 8);
         --  Verify received packet.
         Crypto.Phelix.Decrypt_Packet (This    => Ctx,
                                       Nonce   => Nonce,
                                       Header  => Crypto.Plaintext_Stream (Nonce),
                                       Payload => Crypto.Ciphertext_Stream (EMPTY),
                                       Packet  => Crypto.Plaintext_Stream (Received_Nonce),
                                       Mac     => Mac);
         --  MAC must match, otherwise someone tampered with our packet.
         Authenticated := Mac = Crypto.MAC_Stream (Packet (MAC_FIRST .. MAC_LAST));
      end Receive_Nonce;

      procedure Send_Nonce (Key    : in     Crypto.Key_Stream;
                            Nonce  : in     Crypto.Nonce_Stream;
                            Packet :    out Crypto.Ciphertext_Stream) is
         Ctx : Crypto.Phelix.Context;
      begin
         Crypto.Phelix.Setup_Key (This     => Ctx,
                                  Key      => Key,
                                  Mac_Size => MAC_LENGTH * 8);
         --  Transmit that Nonce to the client.
         Crypto.Phelix.Encrypt_Packet (This    => Ctx,
                                       Nonce   => Nonce,
                                       Header  => Crypto.Plaintext_Stream (Nonce),
                                       Payload => Crypto.Plaintext_Stream (EMPTY),
                                       Packet  => Packet (NONCE_FIRST .. NONCE_LAST),
                                       Mac     => Crypto.MAC_Stream (Packet (MAC_FIRST .. MAC_LAST)));
      end Send_Nonce;

      Key           : Crypto.Key_Stream (0 .. KEY_LENGTH - 1);
      Nonce         : Crypto.Nonce_Stream (0 .. NONCE_LENGTH - 1);
      Packet        : Crypto.Ciphertext_Stream (NONCE_FIRST .. MAC_LAST);
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

         Ada.Text_IO.Put_Line ("Key   : " & Image (Crypto.General_Stream (Key)));
         Ada.Text_IO.Put_Line ("Nonce : " & Image (Crypto.General_Stream (Nonce)));
         Ada.Text_IO.Put_Line ("Packet: " & Image (Crypto.General_Stream (Packet)));
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
         Key := Crypto.Key_Stream (Packet (MAC_FIRST .. MAC_LAST)) & Key (NONCE_FIRST .. NONCE_LAST);

         --  "Randomly" advance Nonce.
         for J in 1 .. Key (Key'First) loop
            for K in 1 .. Key (Key'First + 1) loop
               Nonce := Nonce + Key (Key'Last);
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
