------------------------------------------------------------------------------
--  Copyright (C) 2017-2020 by Heisenbug Ltd. (gh+saatana@heisenbug.eu)
--
--  This work is free. You can redistribute it and/or modify it under the
--  terms of the Do What The Fuck You Want To Public License, Version 2,
--  as published by Sam Hocevar. See the LICENSE file for more details.
------------------------------------------------------------------------------
pragma License (Unrestricted);

package body Saatana.Crypto.Phelix is

   --
   --  Exclusive_Or
   --
   --  Does an in place "xor" per element for the given argument with each
   --  element of "Xor_With".
   --
   procedure Exclusive_Or (Argument : in out Old_Z_4;
                           Xor_With : in     Old_Z_4) with
     Global  => null,
     Depends => (Argument => (Argument,
                              Xor_With)),
     Post    => (for all X in Argument'Range => Argument (X) = (Argument'Old (X) xor Xor_With (X))),
     Inline  => True;

   --  Phelix algorithm internal constants
   OLD_Z_REG    : constant := 4;                 --  which var used for "old" state
   MAC_INIT_CNT : constant := 8;                 --  how many words of pre-MAC mixing
   MAC_WORD_CNT : constant := Max_MAC_Size / 32; --  how many words of MAC output

   --  XOR constants
   MAC_Magic_XOR : constant Word_32 := 16#912D94F1#; --  magic constant for MAC
   AAD_Magic_XOR : constant Word_32 := 16#AADAADAA#; --  magic constant for AAD

   --
   --  H
   --
   --  This is Phelix' mixing function.
   --
   --  Document and reference implementation split this function into H0 and
   --  H1, but as they are always called in sequence, this implementation
   --  merges them into a single function.
   --
   procedure H (Z              : in out State_Words;
                Plaintext_Word : in     Word_32;
                Key_Word       : in     Word_32) with
     Global  => null,
     Depends => (Z => (Z, Plaintext_Word, Key_Word)),
     Post    => (Z = (0 => Rotate_Left (Rotate_Left (Z'Old (0) + (Z'Old (3) xor Plaintext_Word), 9) xor
                                        ((Rotate_Left (Z'Old (3), 15) xor (Z'Old (1) + Z'Old (4))) + Key_Word),
                                        20),
                      1 => Rotate_Left ((Rotate_Left (Z'Old (1) + Z'Old (4), 10) xor Rotate_Left (Z'Old (4), 25) +
                                         (Z'Old (2) xor (Z'Old (0) + (Z'Old (3) xor Plaintext_Word)))),
                                        11),
                      2 => Rotate_Left (Rotate_Left ((Z'Old (2) xor (Z'Old (0) + (Z'Old (3) xor Plaintext_Word))), 17) +
                                        (Rotate_Left (Z'Old (0) +
                                         (Z'Old (3) xor Plaintext_Word), 9) xor
                                         ((Rotate_Left (Z'Old (3), 15) xor (Z'Old (1) + Z'Old (4))) +
                                          Key_Word)),
                                        5),
                      3 => Rotate_Left (((Rotate_Left (Z'Old (3), 15)) xor (Z'Old (1) + Z'Old (4))), 30) +
                           (Rotate_Left ((Z'Old (1) + Z'Old (4)), 10) xor Rotate_Left (Z'Old (4), 25) +
                           (Z'Old (2) xor (Z'Old (0) + (Z'Old (3) xor Plaintext_Word)))),
                      4 => (Rotate_Left ((Rotate_Left (Z'Old (4), 25) +
                            (Z'Old (2) xor (Z'Old (0) + (Z'Old (3) xor Plaintext_Word)))), 13)) xor
                           (Rotate_Left ((Z'Old (2) xor (Z'Old (0) + (Z'Old (3) xor Plaintext_Word))), 17) +
                            ((Rotate_Left ((Z'Old (0) + (Z'Old (3) xor Plaintext_Word)), 9) xor
                              ((Rotate_Left (Z'Old (3), 15) xor (Z'Old (1) + Z'Old (4))) +
                               Key_Word))))));

   type End_Of_Stream_Mask is array (Stream_Count range 1 .. 4) of Word_32;

   MASK : constant End_Of_Stream_Mask := (16#00_00_00_FF#,
                                          16#00_00_FF_FF#,
                                          16#00_FF_FF_FF#,
                                          16#FF_FF_FF_FF#);

   --
   --  Decrypt_Bytes
   --
   procedure Decrypt_Bytes (This        : in out Context;
                            Source      : in     Ciphertext_Stream;
                            Destination :    out Plaintext_Stream)
   is
      Msg_Len : Stream_Count := Source'Length;
   begin
      This.CS.Msg_Len := This.CS.Msg_Len + Word_32 (Msg_Len mod 2 ** 32);
      This.CS.Z (1) := This.CS.Z (1) xor This.CS.AAD_Xor; --  do the AAD xor, if needed
      This.CS.AAD_Xor := 0; --  Next time, the xor will be a nop

      if Source'Length = 0 then
         Destination := (others => 0); --  Ensure "initialization".
      else
         declare
            J          : Mod_8;
            The_Key    : Word_32;
            Plain_Text : Word_32;
            Src_Idx    : Stream_Offset := Source'First;
            Dst_Idx    : Stream_Offset := Destination'First;
            Dst_Nxt    : Stream_Offset;
         begin
            while Msg_Len > 0 loop
               Decrypt_Word :
               declare
                  Remaining_Bytes : constant Stream_Count := Stream_Count'Min (Msg_Len, 4);
               begin
                  Msg_Len := Msg_Len - Remaining_Bytes;
                  Dst_Nxt := Dst_Idx + Remaining_Bytes;

                  J := Mod_8 (This.CS.I mod 8);
                  H (Z              => This.CS.Z,
                     Plaintext_Word => 0,
                     Key_Word       => This.KS.X_0 (J));

                  The_Key := This.CS.Z (OLD_Z_REG) + This.CS.Old_Z (Old_State_Words (This.CS.I mod 4));

                  --  If there was a partial word, the resulting Plain_Text needs
                  --  to be masked as it is used in the further derivation of new Z
                  --  values. Contrary to the C reference implementation which reads
                  --  undefined bytes at the end of the stream, here the same result
                  --  is achieved by masking the Key_Stream value, because
                  --  To_Unsigned already returns zero for the bytes.
                  Plain_Text :=
                    To_Unsigned (Source (Src_Idx .. Src_Idx + Remaining_Bytes - 1)) xor (The_Key and MASK (Remaining_Bytes));

                  Destination (Dst_Idx .. Dst_Nxt - 1) :=
                    Plaintext_Stream'(To_Stream (Plain_Text)) (0 .. Remaining_Bytes - 1);

                  H (Z              => This.CS.Z,
                     Plaintext_Word => Plain_Text,
                     Key_Word       => This.KS.X_1 (J) + This.CS.I);
                  This.CS.Old_Z (Old_State_Words (This.CS.I mod 4)) := This.CS.Z (OLD_Z_REG); --  Save The "old" Value

                  This.CS.I := This.CS.I + 1;
                  Src_Idx   := Src_Idx + Remaining_Bytes;
                  Dst_Idx   := Dst_Nxt;
               end Decrypt_Word;

               pragma Loop_Variant (Decreases => Msg_Len,
                                    Increases => This.CS.I,
                                    Increases => This.CS.Msg_Len,
                                    Increases => Src_Idx,
                                    Increases => Dst_Idx,
                                    Increases => Dst_Nxt);
               pragma Loop_Invariant (Src_Idx = Source'Last - Msg_Len + 1                                       and
                                        Dst_Idx >= Destination'First and Dst_Idx = Destination'Last - Msg_Len + 1 and
                                          Dst_Nxt = Dst_Idx);
               pragma Loop_Invariant (for all I in Destination'First .. Dst_Nxt - 1 =>
                                        Destination (I)'Initialized);
            end loop;
         end;
      end if;

      --  This assertion is not really needed, it is added here to be explicitly
      --  reason about the initialization of the output.
      --  And even in case it fails to prove, it may still speed up proof in
      --  dependent parts by at least satisfying the post condition.
      pragma Assert (Destination'Initialized);
   end Decrypt_Bytes;

   --
   --  Decrypt_Packet
   --
   procedure Decrypt_Packet (This    : in out Context;
                             Nonce   : in     Nonce_Stream;
                             Header  : in     Plaintext_Stream;
                             Payload : in     Ciphertext_Stream;
                             Packet  :    out Plaintext_Stream;
                             Mac     :    out MAC_Stream) is
   begin
      Setup_Nonce (This  => This,
                   Nonce => Nonce);
      Process_AAD (This => This,
                   Aad  => Header);
      Packet (Packet'First .. Packet'First + Header'Length - 1) := Header;

      Decrypt_Bytes (This        => This,
                     Source      => Payload,
                     Destination => Packet (Packet'First + Header'Length .. Packet'Last));

      Finalize (This => This,
                Mac  => Mac);

      --  This assertion is not really needed, it is added here to be explicitly
      --  reason about the initialization of the output.
      --  And even in case it fails to prove, it may still speed up proof in
      --  dependent parts by at least satisfying the post condition.
      pragma Assert (Packet'Initialized);
   end Decrypt_Packet;

   --
   --  Encrypt_Bytes
   --
   procedure Encrypt_Bytes (This        : in out Context;
                            Source      : in     Plaintext_Stream;
                            Destination :    out Ciphertext_Stream)
   is
      Msg_Len : Stream_Count := Source'Length;
   begin
      This.CS.Msg_Len := This.CS.Msg_Len + Word_32 (Msg_Len mod 2 ** 32);
      This.CS.Z (1) := This.CS.Z (1) xor This.CS.AAD_Xor; --  do the AAD xor, if needed
      This.CS.AAD_Xor := 0; --  Next time, the xor will be a nop

      if Source'Length = 0 then
         Destination := (others => 0); -- Ensure "initialization".
      else
         declare
            J           : Mod_8;
            The_Key     : Word_32;
            Plain_Text  : Word_32;
            Cipher_Text : Word_32;
            Src_Idx     : Stream_Offset := Source'First;
            Dst_Idx     : Stream_Offset := Destination'First;
            Dst_Nxt     : Stream_Offset;
         begin
            while Msg_Len > 0 loop
               Encrypt_Word :
               declare
                  Remaining_Bytes : constant Stream_Count := Stream_Count'Min (Msg_Len, 4);
               begin
                  Msg_Len := Msg_Len - Remaining_Bytes;
                  Dst_Nxt := Dst_Idx + Remaining_Bytes;

                  J := Mod_8 (This.CS.I mod 8);
                  H (Z              => This.CS.Z,
                     Plaintext_Word => 0,
                     Key_Word       => This.KS.X_0 (J));
                  The_Key     := This.CS.Z (OLD_Z_REG) + This.CS.Old_Z (Old_State_Words (This.CS.I mod 4));
                  Plain_Text  := To_Unsigned (Source (Src_Idx .. Src_Idx + Remaining_Bytes - 1));
                  Cipher_Text := The_Key xor Plain_Text;
                  Destination (Dst_Idx .. Dst_Nxt - 1) :=
                    Ciphertext_Stream'(To_Stream (Cipher_Text)) (0 .. Remaining_Bytes - 1);

                  H (Z              => This.CS.Z,
                     Plaintext_Word => Plain_Text,
                     Key_Word       => This.KS.X_1 (J) + This.CS.I);
                  This.CS.Old_Z (Old_State_Words (This.CS.I mod 4)) := This.CS.Z (OLD_Z_REG); --  Save The "old" Value

                  This.CS.I := This.CS.I + 1;
                  Src_Idx  := Src_Idx + Remaining_Bytes;
                  Dst_Idx  := Dst_Nxt;
               end Encrypt_Word;

               pragma Loop_Variant (Decreases => Msg_Len,
                                    Increases => This.CS.I,
                                    Increases => Src_Idx,
                                    Increases => Dst_Idx,
                                    Increases => Dst_Nxt);
               pragma Loop_Invariant (Src_Idx = Source'Last - Msg_Len + 1
                                      and Dst_Idx >= Destination'First and Dst_Idx = Destination'Last - Msg_Len + 1
                                      and Dst_Nxt = Dst_Idx);
               pragma Loop_Invariant (for all I in Destination'First .. Dst_Nxt - 1 =>
                                        Destination (I)'Initialized);
            end loop;
         end;
      end if;

      --  This assertion is not really needed, it is added here to be explicitly
      --  reason about the initialization of the output.
      --  And even in case it fails to prove, it may still speed up proof in
      --  dependent parts by at least satisfying the post condition.
      pragma Assert (Destination'Initialized);
   end Encrypt_Bytes;

   --
   --  Encrypt_Packet
   --
   procedure Encrypt_Packet (This    : in out Context;
                             Nonce   : in     Nonce_Stream;
                             Header  : in     Plaintext_Stream;
                             Payload : in     Plaintext_Stream;
                             Packet  :    out Ciphertext_Stream;
                             Mac     :    out MAC_Stream) is
   begin
      Setup_Nonce (This  => This,
                   Nonce => Nonce);
      Process_AAD (This => This,
                   Aad  => Header);
      Packet (Packet'First .. Packet'First + Header'Length - 1) := Ciphertext_Stream (Header);

      Encrypt_Bytes (This        => This,
                     Source      => Payload,
                     Destination => Packet (Packet'First + Header'Length .. Packet'Last));

      Finalize (This => This,
                Mac  => Mac);

      --  This assertion is not really needed, it is added here to be explicitly
      --  reason about the initialization of the output.
      --  And even in case it fails to prove, it may still speed up proof in
      --  dependent parts by at least satisfying the post condition.
      pragma Assert (Packet'Initialized);
   end Encrypt_Packet;

   --
   --  Exclusive_Or
   --
   procedure Exclusive_Or (Argument : in out Old_Z_4;
                           Xor_With : in     Old_Z_4) is
   begin
      for I in Argument'Range loop
         Argument (I) := Argument (I) xor Xor_With (I);
         pragma Loop_Invariant (for all S in Argument'First .. I =>
                                  Argument (S) = (Argument'Loop_Entry (S) xor Xor_With (S)));
      end loop;
   end Exclusive_Or;

   --
   --  Finalize
   --
   procedure Finalize (This : in out Context;
                       Mac  :    out MAC_Stream)
   is
      MAC_WORDS  : constant := MAC_INIT_CNT + MAC_WORD_CNT;
      Plain_Text : Word_32;
      Mac_Index  : Stream_Index;
      Tmp        : MAC_Stream (0 .. MAC_WORDS * 4 - 1)
        with Relaxed_Initialization;
      MAC_OFFSET : constant := Tmp'First + MAC_INIT_CNT * 4;
   begin
      Plain_Text := This.CS.Msg_Len mod 4;
      This.CS.Z (0) := This.CS.Z (0) xor MAC_Magic_XOR;
      This.CS.Z (4) := This.CS.Z (4) xor Word_32 (This.CS.AAD_Len mod 2 ** 32);
      This.CS.Z (2) := This.CS.Z (2) xor Word_32 (This.CS.AAD_Len / 2 ** 32);
      This.CS.Z (1) := This.CS.Z (1) xor This.CS.AAD_Xor;         -- do this in case Msg_Len = 0

      for K in Word_32 range 0 .. MAC_WORDS - 1 loop
         Calculate_MAC_Word :
         declare
            J : constant Mod_8 := Mod_8 (This.CS.I mod 8);
         begin
            H (Z              => This.CS.Z,
               Plaintext_Word => 0,
               Key_Word       => This.KS.X_0 (J));

            Store_MAC_Word :
            declare
               The_Key : constant Word_32 :=
                           This.CS.Z (OLD_Z_REG) + This.CS.Old_Z (Old_State_Words (This.CS.I mod 4));
            begin
               Mac_Index := Tmp'First + Stream_Offset (K) * 4;
               Tmp (Mac_Index .. Mac_Index + 3) := To_Stream (The_Key xor Plain_Text);
            end Store_MAC_Word;

            H (Z              => This.CS.Z,
               Plaintext_Word => Plain_Text,
               Key_Word       => This.KS.X_1 (J) + This.CS.I);
            This.CS.Old_Z (Old_State_Words (This.CS.I mod 4)) := This.CS.Z (OLD_Z_REG); -- save the "old" value
            This.CS.I := This.CS.I + 1;
         end Calculate_MAC_Word;

         pragma Loop_Variant (Increases => K,
                              Increases => Mac_Index,
                              Increases => This.CS.I);
         pragma Loop_Invariant (This.CS.I = This.CS.I'Loop_Entry + K + 1 and
                                Mac'Length = Stream_Count (This.KS.MAC_Size / 8) and
                                Mac_Index = Tmp'First + Stream_Offset (K) * 4 and
                                Mac_Index + 3 in Tmp'Range);
         pragma Loop_Invariant (for all I in Tmp'First .. Mac_Index + 3 =>
                                  Tmp (I)'Initialized);
      end loop;

      --  Copy the relevant bits back to MAC.
      Mac := Tmp (MAC_OFFSET .. MAC_OFFSET - 1 + Mac'Length);

      --  We finalized the stream, so the previous Nonce should never be
      --  reused. Ensure at least part of this condition by marking the current
      --  Nonce as invalid.
      This.Setup_Phase := Key_Has_Been_Setup;
   end Finalize;

   --
   --  H
   --
   procedure H (Z              : in out State_Words;
                Plaintext_Word : in     Word_32;
                Key_Word       : in     Word_32) is
   begin
      --  First half.
      Z (0) := Z (0) + (Z (3) xor Plaintext_Word);
      Z (3) := Rotate_Left (Value => Z (3), Amount => 15);

      Z (1) := Z (1) + Z (4);
      Z (4) := Rotate_Left (Value => Z (4), Amount => 25);

      Z (2) := Z (2) xor Z (0);
      Z (0) := Rotate_Left (Value => Z (0), Amount => 9);

      Z (3) := Z (3) xor Z (1);
      Z (1) := Rotate_Left (Value => Z (1), Amount => 10);

      Z (4) := Z (4) + Z (2);
      Z (2) := Rotate_Left (Value => Z (2), Amount => 17);

      --  Second half.
      Z (0) := Z (0) xor (Z (3) + Key_Word);
      Z (3) := Rotate_Left (Value => Z (3), Amount => 30);

      Z (1) := Z (1) xor Z (4);
      Z (4) := Rotate_Left (Value => Z (4), Amount => 13);

      Z (2) := Z (2) + Z (0);
      Z (0) := Rotate_Left (Value => Z (0), Amount => 20);

      Z (3) := Z (3) + Z (1);
      Z (1) := Rotate_Left (Value => Z (1), Amount => 11);

      Z (4) := Z (4) xor Z (2);
      Z (2) := Rotate_Left (Value => Z (2), Amount => 5);
   end H;

   --
   --  Process_AAD
   --
   procedure Process_AAD (This : in out Context;
                          Aad  : in     Plaintext_Stream) is
   begin
      This.CS.AAD_Len := This.CS.AAD_Len + Aad'Length;

      if Aad'Length = 0 then
         null;
      else
         declare
            Aad_Len : Stream_Count := Aad'Length;
            Src_Idx : Stream_Offset := Aad'First;
         begin
            while Aad_Len > 0 loop
               Process_AAD_Word :
               declare
                  Remaining_Bytes : constant Stream_Count := Stream_Count'Min (Aad_Len, 4);
                  J               : constant Mod_8 := Mod_8 (This.CS.I mod 8);
               begin
                  Aad_Len := Aad_Len - Remaining_Bytes;

                  H (Z              => This.CS.Z,
                     Plaintext_Word => 0,
                     Key_Word       => This.KS.X_0 (J));

                  H (Z              => This.CS.Z,
                     Plaintext_Word => To_Unsigned (Aad (Src_Idx .. Src_Idx + Remaining_Bytes - 1)),
                     Key_Word       => This.KS.X_1 (J) + This.CS.I);

                  This.CS.Old_Z (Old_State_Words (This.CS.I mod 4)) := This.CS.Z (OLD_Z_REG); --  Save the "old" value

                  This.CS.I := This.CS.I + 1;
                  Src_Idx := Src_Idx + Remaining_Bytes;
               end Process_AAD_Word;

               pragma Loop_Variant (Decreases => Aad_Len,
                                    Increases => Src_Idx,
                                    Increases => This.CS.I);
               pragma Loop_Invariant (Src_Idx + Aad_Len - 1 = Aad'Last and then
                                      Src_Idx >= Aad'First);
            end loop;
         end;
      end if;
   end Process_AAD;

   --
   --  Setup_Key
   --
   procedure Setup_Key (This     :    out Context;
                        Key      : in     Key_Stream;
                        Mac_Size : in     MAC_Size_32)
   is
      Key_Size : constant Key_Size_32 := 8 * Key'Length;
   begin
      --  These values are going to be overwritten by Setup_Nonce.
      --  We initialize them here merely to satisfy the prover.
      This.CS := Cipher_State'(Old_Z   => (others => 0),
                               Z       => (others => 0),
                               AAD_Len => 0,
                               I       => 0,
                               Msg_Len => 0,
                               AAD_Xor => 0);
      This.KS.X_1 := (others => 0);

      --  save key and mac sizes, nonce size is always 128
      This.KS.Key_Size := Key_Size;
      This.KS.MAC_Size := Mac_Size;

      --  Pre-compute X_1_bump "constant" to save clock cycles during
      --  Setup_Nonce.
      --  To be honest, I am really not certain if that micro-optimization
      --  which I carried over from the C reference implementation is worth the
      --  effort.
      This.KS.X_1_Bump := Key_Size / 2 + 256 * (Mac_Size mod Max_MAC_Size);

      --  copy key to X_0, in correct endianness
      --  Special case for zero length key, there we just set everything to 0.
      --  This is done unconditionally to satisfy the prover that X_0 is fully
      --  initialized in each path.
      This.KS.X_0 := (others => 0);

      if Key'Length /= 0 then
         for I in This.KS.X_0'Range loop
            Process_Key_Schedule_Word :
            declare
               Subkey_First : constant Stream_Offset :=
                                Stream_Offset'Min (Key'First + Stream_Offset (I - This.KS.X_0'First) * 4, Key'Last + 1);
               Subkey_Last  : constant Stream_Index :=
                                Stream_Index'Min (Subkey_First + 3, Key'Last);
            begin
               This.KS.X_0 (I) := To_Unsigned (Key (Subkey_First .. Subkey_Last));
               pragma Loop_Invariant
                 (for all S in This.KS.X_0'First .. I =>
                    This.KS.X_0 (S) =
                      To_Unsigned (Key (Key'First + Stream_Offset (S - This.KS.X_0'First) * 4 ..
                                        Stream_Index'Min (Key'First + Stream_Offset (S - This.KS.X_0'First) * 4 + 3,
                                                          Key'Last))));
            end Process_Key_Schedule_Word;
         end loop;
      end if;

      --  Now process the padded "raw" key, using a Feistel network
      Process_Raw_Key :
      declare
         Z : State_Words;
      begin
         for I in Mod_8'Range loop
            Process_Key_Word :
            declare
               K : Mod_8;
            begin
               K := 4 * (I mod 2);

               --  Assignment done via aggregrate rather than array concatenation
               --  ("Z := This.KS.X_0 (K .. K + 3) & (Key_Size / 8 + 64);") as
               --  this is better handled by the prover.
               Z := State_Words'(0 => This.KS.X_0 (K + 0),
                                 1 => This.KS.X_0 (K + 1),
                                 2 => This.KS.X_0 (K + 2),
                                 3 => This.KS.X_0 (K + 3),
                                 4 => Key_Size / 8 + 64);

               H (Z              => Z,
                  Plaintext_Word => 0,
                  Key_Word       => 0);
               H (Z              => Z,
                  Plaintext_Word => 0,
                  Key_Word       => 0);

               K := K + 4; --  mod 8 is done automatically

               Exclusive_Or (Argument => This.KS.X_0 (K .. K + 3),
                             Xor_With => Z (0 .. 3));
            end Process_Key_Word;
         end loop;
      end Process_Raw_Key;

      --  Key has been set up. Require a Nonce later.
      This.Setup_Phase := Key_Has_Been_Setup;
   end Setup_Key;

   --
   --  Setup_Nonce
   --
   procedure Setup_Nonce (This  : in out Context;
                          Nonce : in     Nonce_Stream) is
   begin
      --  Initialize subkeys and Z values
      for I in Mod_8 range 0 .. 3 loop
         Init_Subkey_Word :
         declare
            N : constant Word_32 :=
                  To_Unsigned (Nonce (Nonce'First + Stream_Offset (I) * 4 .. Nonce'First + Stream_Offset (I) * 4 + 3));
         begin
            This.KS.X_1 (I)     := This.KS.X_0 (I + 4) + N;
            This.KS.X_1 (I + 4) := This.KS.X_0 (I)     + (Word_32 (I) - N);
            This.CS.Z (I)       := This.KS.X_0 (I + 3) xor N;
         end Init_Subkey_Word;
      end loop;

      This.KS.X_1 (1) := This.KS.X_1 (1) + This.KS.X_1_Bump;  -- X' adjustment for i = 1 mod 4
      This.KS.X_1 (5) := This.KS.X_1 (5) + This.KS.X_1_Bump;
      This.CS.Z (OLD_Z_REG) := This.KS.X_0 (7);
      This.CS.AAD_Len := 0;
      This.CS.Msg_Len := 0;

      for I in Mod_8'Range loop
         --  customized version of loop for zero initialization
         H (Z              => This.CS.Z,
            Plaintext_Word => 0,
            Key_Word       => This.KS.X_0 (I));

         H (Z              => This.CS.Z,
            Plaintext_Word => 0,
            Key_Word       => This.KS.X_1 (I) + Word_32 (I));

         This.CS.Old_Z (I mod 4) := This.CS.Z (OLD_Z_REG); --  save the "old" value
      end loop;

      This.CS.AAD_Xor := AAD_Magic_XOR; --  perform the AAD xor
      This.CS.Z (1) := This.CS.Z (1) xor This.CS.AAD_Xor;

      This.CS.I := 8;

      --  Nonce has been set.
      This.Setup_Phase := Nonce_Has_Been_Setup;
   end Setup_Nonce;

end Saatana.Crypto.Phelix;
