------------------------------------------------------------------------------
--  Copyright (C) 2017-2020 by Heisenbug Ltd. (gh+saatana@heisenbug.eu)
--
--  This work is free. You can redistribute it and/or modify it under the
--  terms of the Do What The Fuck You Want To Public License, Version 2,
--  as published by Sam Hocevar. See the LICENSE file for more details.
------------------------------------------------------------------------------
pragma License (Unrestricted);

with Ada.Command_Line;
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
      type Character_Lookup is array (Saatana.Crypto.Byte range <>) of Character;
      Result   : String (1 .. S'Length * 2);
      Hex_Char : constant Character_Lookup (0 .. 15) := "0123456789ABCDEF";
      use type Saatana.Crypto.Byte;
   begin
      for I in S'Range loop
         Result (Result'First + Natural (I - S'First) * 2)     := Hex_Char (S (I) / 16);
         Result (Result'First + Natural (I - S'First) * 2 + 1) := Hex_Char (S (I) mod 16);
      end loop;

      return Result;
   end Image;

   Verbose  : Boolean := False;
   KAT_Only : Boolean := False;
begin
   Evaluate_Command_Line :
   for Number in 1 .. Ada.Command_Line.Argument_Count loop
      Check_Argument :
      declare
         Argument : constant String :=
           Ada.Command_Line.Argument (Number => Number);
      begin
         if Argument = "--verbose" then
            Verbose := True;
         elsif Argument = "--kat-only" then
            KAT_Only := True;
         else
            Ada.Text_IO.Put_Line
              (File => Ada.Text_IO.Standard_Error,
               Item => "Unrecognized command line parameter """ & Argument & """ ignored.");
         end if;
      end Check_Argument;
   end loop Evaluate_Command_Line;

   Ada.Text_IO.Put_Line ("Running KAT (Known Answers Tests)...");

   KAT_Loop :
   for T of Saatana.Crypto.Phelix.Test_Vectors.KAT loop
      Test_Encrypt_Decrypt :
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

         Test_Encrypt_Decrypt_Bytes :
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

            if Verbose then
               --  KAT input.
               Ada.Text_IO.Put_Line ("Key       : " & Image (Saatana.Crypto.General_Stream (T.Key.all)));
               Ada.Text_IO.Put_Line ("Nonce     : " & Image (Saatana.Crypto.General_Stream (T.Nonce.all)));
               Ada.Text_IO.Put_Line ("AAD       : " & Image (Saatana.Crypto.General_Stream (T.Aad.all)));
               Ada.Text_IO.Put_Line ("Plaintext : " & Image (Saatana.Crypto.General_Stream (T.Plaintext.all)));
               --  Computed output, being compared with expected from KAT vector.
               Ada.Text_IO.Put_Line ("Ciphertext: " & Image (Saatana.Crypto.General_Stream (Result_Cipher)));
               Ada.Text_IO.Put_Line ("MAC       : " & Image (Saatana.Crypto.General_Stream (Result_MAC)));
               Ada.Text_IO.New_Line;
            end if;

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

            --  Same as above, but with byte-for-byte en/de-cryption.  This
            --  is done to verify that the implementation actually works as a
            --  stream cipher.
            --  NOTE:  Phelix does still require processing of 32-bit words in
            --         each step, so we cannot exactly call it byte-for-byte
            --         processing.  If an actual implementation needs to encrypt
            --         a stream in a byte-for-byte manner, it needs to store up
            --         to four bytes of the plaintext or cipher stream before
            --         calling Encrypt/Decrypt_Bytes.
            Saatana.Crypto.Phelix.Setup_Nonce (This  => This,
                                               Nonce => T.Nonce.all);
            Saatana.Crypto.Phelix.Process_AAD (This => This,
                                               Aad  => T.Aad.all);

            Loop_Over_Plaintext_Bytes :
            for I in T.Plaintext.all'Range loop
               if I mod 4 = 0 then
                  Process_Plaintext_Word :
                  declare
                     Last_Byte : constant Saatana.Crypto.Stream_Index :=
                       Saatana.Crypto.Stream_Index'Min (I + 3,
                                                        T.Plaintext.all'Last);
                  begin
                     --  Process only on word boundaries.
                     Saatana.Crypto.Phelix.Encrypt_Bytes
                       (This        => This,
                        Source      => T.Plaintext.all (I .. Last_Byte),
                        Destination => Result_Cipher (I .. Last_Byte));
                  end Process_Plaintext_Word;
               end if;
            end loop Loop_Over_Plaintext_Bytes;

            Saatana.Crypto.Phelix.Finalize (This => This,
                                            Mac  => Result_MAC);

            Add_Test (Result_Cipher = T.Cipher.all);
            Add_Test (Result_MAC = T.MAC.all);

            Saatana.Crypto.Phelix.Setup_Nonce (This  => This,
                                               Nonce => T.Nonce.all);
            Saatana.Crypto.Phelix.Process_AAD (This => This,
                                               Aad  => T.Aad.all);

            Loop_Over_Ciphertext_Bytes :
            for I in T.Cipher.all'Range loop
               if I mod 4 = 0 then
                  Process_Ciphertext_Word :
                  declare
                     Last_Byte : constant Saatana.Crypto.Stream_Index :=
                       Saatana.Crypto.Stream_Index'Min (I + 3,
                                                        T.Plaintext.all'Last);
                  begin
                     Saatana.Crypto.Phelix.Decrypt_Bytes
                       (This        => This,
                        Source      => T.Cipher.all (I .. Last_Byte),
                        Destination => Result_Plaintext (I .. Last_Byte));
                  end Process_Ciphertext_Word;
               end if;
            end loop Loop_Over_Ciphertext_Bytes;

            Saatana.Crypto.Phelix.Finalize (This => This,
                                            Mac  => Result_MAC);

            Add_Test (Result_Plaintext = T.Plaintext.all);
            Add_Test (Result_MAC = T.MAC.all);

         end Test_Encrypt_Decrypt_Bytes;

         Test_Encrypt_Decrypt_Packets :
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
         end Test_Encrypt_Decrypt_Packets;
      end Test_Encrypt_Decrypt;
   end loop KAT_Loop;

   if not KAT_Only then
      Ada.Text_IO.Put_Line ("Running additional ""Transmit"" tests...");

      Transmit_Tests :
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
            Nonce : constant Saatana.Crypto.Nonce_Stream :=
              Saatana.Crypto.Nonce_Stream (Packet (NONCE_FIRST .. NONCE_LAST));
            Received_Nonce : Saatana.Crypto.Nonce_Stream (0 .. NONCE_LENGTH - 1);
         begin
            Saatana.Crypto.Phelix.Setup_Key (This     => Ctx,
                                             Key      => Key,
                                             Mac_Size => MAC_LENGTH * 8);
            --  Verify received packet.
            Saatana.Crypto.Phelix.Decrypt_Packet
              (This    => Ctx,
               Nonce   => Nonce,
               Header  => Saatana.Crypto.Plaintext_Stream (Nonce),
               Payload => Saatana.Crypto.Ciphertext_Stream (EMPTY),
               Packet  => Saatana.Crypto.Plaintext_Stream (Received_Nonce),
               Mac     => Mac);
            --  MAC must match, otherwise someone tampered with our packet.
            Authenticated :=
              Mac = Saatana.Crypto.MAC_Stream (Packet (MAC_FIRST .. MAC_LAST));
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
            Saatana.Crypto.Phelix.Encrypt_Packet
              (This    => Ctx,
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

         Check_MAC_Handling :
         for I in 1 .. 1024 loop
            Send_Nonce (Key    => Key,
                        Nonce  => Nonce,
                        Packet => Packet);

            if Verbose then
               Ada.Text_IO.Put_Line ("Key   : " & Image (Saatana.Crypto.General_Stream (Key)));
               Ada.Text_IO.Put_Line ("Nonce : " & Image (Saatana.Crypto.General_Stream (Nonce)));
               Ada.Text_IO.Put_Line ("Packet: " & Image (Saatana.Crypto.General_Stream (Packet)));
               Ada.Text_IO.New_Line;
            end if;

            --  Check if the MAC matches with whatever has been sent.
            Receive_Nonce (Key           => Key,
                           Packet        => Packet,
                           Authenticated => Authenticated);
            Add_Test (Authenticated);

            --  Tamper with the packet. Authentication should fail now.
            Receive_Nonce
              (Key           => Key,
               Packet        => (Packet (Packet'First) xor 1) & Packet (Packet'First + 1 .. Packet'Last),
               Authenticated => Authenticated);
            Add_Test (not Authenticated);

            --  Use Nonce and MAC as new Key and increment the nonce.
            Key := Saatana.Crypto.Key_Stream (Packet (MAC_FIRST .. MAC_LAST)) & Key (NONCE_FIRST .. NONCE_LAST);

            --  "Randomly" advance Nonce.
            --
            --  We take the current key stream, null out its two low order bytes,
            --  and the result is being added Key (0) * Key (1) times to Nonce to
            --  create a new seemingly random Nonce.
            Shuffle_Nonce :
            declare
               Operand : constant Saatana.Crypto.Nonce_Stream :=
                 Saatana.Crypto.Nonce_Stream (Key (Key'First .. Key'First + 13) & (14 .. NONCE_LENGTH - 1 => 0));
            begin
               Loop_For_First_Byte_Of_Key :
               for J in 1 .. Key (Key'First) loop
                  Loop_For_Second_Byte_Of_Key :
                  for K in 1 .. Key (Key'First + 1) loop
                     Nonce := Nonce + Operand;
                  end loop Loop_For_Second_Byte_Of_Key;
               end loop Loop_For_First_Byte_Of_Key;
            end Shuffle_Nonce;
         end loop Check_MAC_Handling;

         --  Check for any regressions.  If, after all this Nonce shuffling above,
         --  the last packet is still the expected one, we are good.
         Add_Test (Image (Saatana.Crypto.General_Stream (Packet)) =
                     "8F636CA7CC87C0AC88B35964B605E0005A586B0519BA64C6245C8724D3BEDAF1");
      end Transmit_Tests;
   end if; -- KAT only requested

   Ada.Text_IO.Put_Line ("Test results:"
                         & Natural'Image (Num_Succeeded)
                         & " out of" & Natural'Image (Num_Tests)
                         & " succeeded.");
   Ada.Text_IO.Put_Line (if Num_Tests = Num_Succeeded then "<OK>" else "<FAILED>");
   Ada.Command_Line.Set_Exit_Status (Code => (if Num_Tests = Num_Succeeded
                                              then Ada.Command_Line.Success
                                              else Ada.Command_Line.Failure));
end Test_Phelix;
