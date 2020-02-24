------------------------------------------------------------------------------
--  Copyright (C) 2020 by Heisenbug Ltd. (gh+saatana@heisenbug.eu)
--
--  This work is free. You can redistribute it and/or modify it under the
--  terms of the Do What The Fuck You Want To Public License, Version 2,
--  as published by Sam Hocevar. See the LICENSE file for more details.
------------------------------------------------------------------------------
pragma License (Unrestricted);

with Ada.Command_Line;
with Saatana.Crypto.Phelix;

------------------------------------------------------------------------------
--
--  SPARK/Ada Algorithms Targeting Advanced Network Applications
--
--  Saatana - API demonstration.
--
--  Intended to show the API and how to use it, and proof of correctness
--  regarding call sequence.
--
--  Please note that we re-use the Nonce here purely for demonstration purposes!
--
------------------------------------------------------------------------------

procedure Test_Phelix_API with
  SPARK_Mode => On
is
   pragma Assertion_Policy (Check);

   use type Saatana.Crypto.Stream_Index;
   use type Saatana.Crypto.Word_32;

   Key         : constant Saatana.Crypto.Key_Stream   := (0 .. 15 => 1);
   Nonce       : constant Saatana.Crypto.Nonce_Stream := (0 .. 15 => 0);
   AAD         : constant Saatana.Crypto.Plaintext_Stream
     := (0 => Character'Pos ('A'),
         1 => Character'Pos ('A'),
         2 => Character'Pos ('D'));
   Plaintext  : constant Saatana.Crypto.Plaintext_Stream
     := (0 => Character'Pos ('P'),
         1 => Character'Pos ('l'),
         2 => Character'Pos ('a'),
         3 => Character'Pos ('i'),
         4 => Character'Pos ('n'),
         5 => Character'Pos ('t'),
         6 => Character'Pos ('e'),
         7 => Character'Pos ('x'),
         8 => Character'Pos ('t'));

   subtype Packet_Range is Saatana.Crypto.Stream_Index range
     0 .. AAD'Length + Plaintext'Length - 1;
   subtype AAD_Range is Packet_Range range
     Packet_Range'First .. AAD'Length - 1;
   subtype PT_Range  is Packet_Range range
     AAD'Length .. Packet_Range'Last;

   Packet_Enc  : Saatana.Crypto.Ciphertext_Stream (Packet_Range) := (others => 0);
   Packet_Dec  : Saatana.Crypto.Plaintext_Stream (Packet_Range)  := (others => 0);
   MAC         : Saatana.Crypto.MAC_Stream (0 .. 7);
   This        : Saatana.Crypto.Phelix.Context;
begin
   --
   --  Standard API.
   --

   --
   --  Encryption
   --
   --  Set up key, add a nonce, process AAD (if any), encrypt the payload and
   --  finalize for MAC calculation.
   Saatana.Crypto.Phelix.Setup_Key (This     => This,
                                    Key      => Key,
                                    Mac_Size => MAC'Length * 8);
   Saatana.Crypto.Phelix.Setup_Nonce (This => This,
                                      Nonce => Nonce);
   Saatana.Crypto.Phelix.Process_AAD (This => This,
                                      Aad  => AAD);
   Packet_Enc (AAD_Range) := Saatana.Crypto.Ciphertext_Stream (AAD);
   Saatana.Crypto.Phelix.Encrypt_Bytes
     (This        => This,
      Source      => Plaintext,
      Destination => Packet_Enc (PT_Range));
   Saatana.Crypto.Phelix.Finalize (This => This,
                                   Mac  => MAC);

   --
   --  Decryption
   --
   --  Set up key, add a nonce, process AAD (if any), decrypt the payload and
   --  finalize for MAC calculation.
   Saatana.Crypto.Phelix.Setup_Key (This     => This,
                                    Key      => Key,
                                    Mac_Size => MAC'Length * 8);
   Saatana.Crypto.Phelix.Setup_Nonce (This => This,
                                      Nonce => Nonce);
   Packet_Dec (AAD_Range) :=
     Saatana.Crypto.Plaintext_Stream (Packet_Enc (AAD_Range));
   Saatana.Crypto.Phelix.Process_AAD (This => This,
                                      Aad  => Packet_Dec (AAD_Range));
   Saatana.Crypto.Phelix.Decrypt_Bytes
     (This        => This,
      Source      => Packet_Enc (PT_Range),
      Destination => Packet_Dec (PT_Range));
   Saatana.Crypto.Phelix.Finalize (This => This,
                                   Mac  => MAC);

   --
   --  Extended API.
   --  Does most of the above in a single step.
   --

   --
   --  Encryption
   --
   Saatana.Crypto.Phelix.Setup_Key (This     => This,
                                    Key      => Key,
                                    Mac_Size => MAC'Length * 8);
   Saatana.Crypto.Phelix.Encrypt_Packet (This    => This,
                                         Nonce   => Nonce,
                                         Header  => AAD,
                                         Payload => Plaintext,
                                         Packet  => Packet_Enc,
                                         Mac     => MAC);

   --
   --  Decryption
   --
   Saatana.Crypto.Phelix.Setup_Key (This     => This,
                                    Key      => Key,
                                    Mac_Size => MAC'Length * 8);
   Saatana.Crypto.Phelix.Decrypt_Packet
     (This    => This,
      Nonce   => Nonce,
      Header  => Saatana.Crypto.Plaintext_Stream (Packet_Enc (AAD_Range)),
      Payload => Packet_Enc (PT_Range),
      Packet  => Packet_Dec,
      Mac     => MAC);

   Set_Exit_Status :
   declare
      use type Saatana.Crypto.Plaintext_Stream;
      Exit_Status : constant Ada.Command_Line.Exit_Status
        := (if Packet_Dec = AAD & Plaintext
            then Ada.Command_Line.Success
            else Ada.Command_Line.Failure);
   begin
      pragma Warnings
        (Off,
         "no Global contract available for ""Set_Exit_Status""");
      --  Setting the exit status is not part of the SPARK verification. This
      --  program is not even intended to be executed, the whole purpose is to
      --  verify that SPARK can successfully prove the API usage.
      Ada.Command_Line.Set_Exit_Status (Exit_Status);
      pragma Warnings (On,
                       "no Global contract available for ""Set_Exit_Status""");
   end Set_Exit_Status;
end Test_Phelix_API;
