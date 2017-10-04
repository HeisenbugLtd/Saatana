package body Crypto.Phelix is

   --
   --  BSWAP
   --
   function BSWAP (Value : in General_Stream) return Interfaces.Unsigned_32 is
     ((if Value'Length > 0 then Interfaces.Unsigned_32 (Value (Value'First + 0)) * 2 **  0 else 0) +
      (if Value'Length > 1 then Interfaces.Unsigned_32 (Value (Value'First + 1)) * 2 **  8 else 0) +
      (if Value'Length > 2 then Interfaces.Unsigned_32 (Value (Value'First + 2)) * 2 ** 16 else 0) +
      (if Value'Length > 3 then Interfaces.Unsigned_32 (Value (Value'First + 3)) * 2 ** 24 else 0)) with
   Depends => (BSWAP'Result => (Value));

   function BSWAP (Value : in Ciphertext_Stream) return Interfaces.Unsigned_32 is
     (BSWAP (General_Stream (Value))) with
   Depends => (BSWAP'Result => (Value));

   function BSWAP (Value : in Key_Stream) return Interfaces.Unsigned_32 is
     (BSWAP (General_Stream (Value))) with
   Depends => (BSWAP'Result => (Value));

   function BSWAP (Value : in Nonce_Stream) return Interfaces.Unsigned_32 is
     (BSWAP (General_Stream (Value))) with
   Depends => (BSWAP'Result => (Value));

   function BSWAP (Value : in Plaintext_Stream) return Interfaces.Unsigned_32 is
     (BSWAP (General_Stream (Value))) with
   Depends => (BSWAP'Result => (Value));

   --
   --  BSWAP
   --
   function BSWAP (Value  : in Interfaces.Unsigned_32;
                   Length : in Stream_Count) return General_Stream is
     (General_Stream'
       (0 => (if Length > 0 then Byte (Interfaces.Shift_Right (Value,  0) mod 256) else 0),
        1 => (if Length > 1 then Byte (Interfaces.Shift_Right (Value,  8) mod 256) else 0),
        2 => (if Length > 2 then Byte (Interfaces.Shift_Right (Value, 16) mod 256) else 0),
        3 => (if Length > 3 then Byte (Interfaces.Shift_Right (Value, 24) mod 256) else 0))) with
   Post => (BSWAP'Result'Length = 4 and BSWAP'Result'First = 0);

   --  Phelix algorithm internal constants
   OLD_Z_REG    : constant := 4;                  --  which var used for "old" state
   MAC_INIT_CNT : constant := 8;                  --  how many words of pre-MAC mixing
   MAC_WORD_CNT : constant := Max_MAC_Size / 32; --  how many words of MAC output

   --  XOR constants
   MAC_Magic_XOR : constant Interfaces.Unsigned_32 := 16#912D94F1#; --  magic constant for MAC
   AAD_Magic_XOR : constant Interfaces.Unsigned_32 := 16#AADAADAA#; --  magic constant for AAD

   --
   --  H
   --
   procedure H (Z              : in out State_Words;
                Plaintext_Word : in     Interfaces.Unsigned_32;
                Key_Word       : in     Interfaces.Unsigned_32) with
     Depends => (Z => (Z, Plaintext_Word, Key_Word));

   MASK : constant array (Stream_Count range 1 .. 4) of Interfaces.Unsigned_32 :=
            (16#00_00_00_FF#,
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
      J          : Mod_8;
      The_Key    : Interfaces.Unsigned_32;
      Plain_Text : Interfaces.Unsigned_32;
      Src_Idx    : Stream_Offset := Source'First;
      Dst_Idx    : Stream_Offset := Destination'First;
      Msg_Len    : Stream_Count  := Source'Length;
      Dst_Nxt    : Stream_Offset;
   begin
      This.CS.Msg_Len := This.CS.Msg_Len + Interfaces.Unsigned_32 (Msg_Len mod 2 ** 32);
      This.CS.Z (1) := This.CS.Z (1) xor This.CS.AAD_Xor; --  do the AAD xor, if needed
      This.CS.AAD_Xor := 0; --  Next time, the xor will be a nop

      while Msg_Len > 0 loop
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

            --  If there was a partial word, the resulting Plain_Text needs to be masked as it is used
            --  in the further derivation of new Z values. Contrary to the C reference implementation
            --  which reads undefined bytes at the end of the stream, here the same result is achieved
            --  by masking the Key_Stream value, because BSWAP already returns zero for the bytes.
            Plain_Text :=
              BSWAP (Source (Src_Idx .. Src_Idx + Remaining_Bytes - 1)) xor (The_Key and MASK (Remaining_Bytes));

            Destination (Dst_Idx .. Dst_Nxt - 1) :=
              Plaintext_Stream (BSWAP (Value  => Plain_Text,
                                       Length => Remaining_Bytes)) (0 .. Remaining_Bytes - 1);
            pragma Assert (for all X in Dst_Idx .. Dst_Nxt - 1 => Destination (X) in Byte);
            pragma Annotate (GNATprove,
                             False_Positive,
                             """Destination"" might not be initialized",
                             "This is bonkers, there's an explicit assignment above");

            H (Z              => This.CS.Z,
               Plaintext_Word => Plain_Text,
               Key_Word       => This.KS.X_1 (J) + This.CS.I);
            This.CS.Old_Z (Old_State_Words (This.CS.I mod 4)) := This.CS.Z (OLD_Z_REG); --  Save The "old" Value

            This.CS.I := This.CS.I + 1;
            Src_Idx   := Src_Idx + Remaining_Bytes;
            Dst_Idx   := Dst_Nxt;
         end;

         pragma Loop_Variant (Decreases => Msg_Len,
                              Increases => This.CS.I,
                              Increases => This.CS.Msg_Len,
                              Increases => Src_Idx,
                              Increases => Dst_Idx,
                              Increases => Dst_Nxt);
         pragma Loop_Invariant (Src_Idx >= Source'First      and Src_Idx = Source'Last      - Msg_Len + 1 and
                                Dst_Idx >= Destination'First and Dst_Idx = Destination'Last - Msg_Len + 1 and
                                Dst_Nxt >= Destination'First and Dst_Nxt - 1 <= Destination'Last          and
                                (for all X in Destination'First .. Dst_Nxt - 1 => Destination (X) in Byte));
      end loop;
   end Decrypt_Bytes;

   --
   --  Decrypt_Packet
   --
   procedure Decrypt_Packet (This    : in     Context;
                             Nonce   : in     Nonce_Stream;
                             Header  : in     Plaintext_Stream;
                             Payload : in     Ciphertext_Stream;
                             Packet  :    out Plaintext_Stream;
                             Mac     :    out MAC_Stream)
   is
      Msg_Header : Plaintext_Stream renames Packet (Packet'First .. Packet'First + Header'Length - 1);
      Msg_Body   : Plaintext_Stream renames Packet (Packet'First + Header'Length .. Packet'Last);
      Local_Ctx  : Context := This;
   begin
      Setup_Nonce (This  => Local_Ctx,
                   Nonce => Nonce);
      Process_AAD (This => Local_Ctx,
                   Aad  => Header);
      Msg_Header := Header;

      --  These assertions are all proved and copy the pre-condition of Decrypt_Bytes.
      --  SPARK still can't prove that the precondition won't fail.
      pragma Assert (Payload'First in Stream_Index and Packet'First in Stream_Index);
      pragma Assert (Msg_Body'Length = Payload'Length);
      pragma Assert (This.CS.Msg_Len mod 4 = 0);
      Decrypt_Bytes (This        => Local_Ctx,
                     Source      => Payload,
                     Destination => Msg_Body);

      Finalize (This => Local_Ctx,
                Mac  => Mac);
   end Decrypt_Packet;

   --
   --  Encrypt_Bytes
   --
   procedure Encrypt_Bytes (This        : in out Context;
                            Source      : in     Plaintext_Stream;
                            Destination :    out Ciphertext_Stream)
   is
      J           : Mod_8;
      The_Key     : Interfaces.Unsigned_32;
      Plain_Text  : Interfaces.Unsigned_32;
      Cipher_Text : Interfaces.Unsigned_32;
      Src_Idx     : Stream_Offset := Source'First;
      Dst_Idx     : Stream_Offset := Destination'First;
      Dst_Nxt     : Stream_Offset;
      Msg_Len     : Stream_Count  := Source'Length;
   begin
      This.CS.Msg_Len := This.CS.Msg_Len + Interfaces.Unsigned_32 (Msg_Len mod 2 ** 32);
      This.CS.Z (1) := This.CS.Z (1) xor This.CS.AAD_Xor; --  do the AAD xor, if needed
      This.CS.AAD_Xor := 0; --  Next time, the xor will be a nop

      while Msg_Len > 0 loop
         declare
            Remaining_Bytes : constant Stream_Count := Stream_Count'Min (Msg_Len, 4);
         begin
            pragma Assert (Remaining_Bytes > 0);

            Msg_Len := Msg_Len - Remaining_Bytes;
            Dst_Nxt := Dst_Idx + Remaining_Bytes;

            J := Mod_8 (This.CS.I mod 8);
            H (Z              => This.CS.Z,
               Plaintext_Word => 0,
               Key_Word       => This.KS.X_0 (J));
            The_Key     := This.CS.Z (OLD_Z_REG) + This.CS.Old_Z (Old_State_Words (This.CS.I mod 4));
            Plain_Text  := BSWAP (Source (Src_Idx .. Src_Idx + Remaining_Bytes - 1));
            Cipher_Text := The_Key xor Plain_Text;
            Destination (Dst_Idx .. Dst_Nxt - 1) :=
              Ciphertext_Stream (BSWAP (Value  => Cipher_Text,
                                        Length => Remaining_Bytes)) (0 .. Remaining_Bytes - 1);
            pragma Assert (for all X in Dst_Idx .. Dst_Nxt - 1 => Destination (X) in Byte);
            pragma Annotate (GNATprove,
                             False_Positive,
                             """Destination"" might not be initialized",
                             "This is bonkers, there's an explicit assignment above");

            H (Z              => This.CS.Z,
               Plaintext_Word => Plain_Text,
               Key_Word       => This.KS.X_1 (J) + This.CS.I);
            This.CS.Old_Z (Old_State_Words (This.CS.I mod 4)) := This.CS.Z (OLD_Z_REG); --  Save The "old" Value

            This.CS.I := This.CS.I + 1;
            Src_Idx  := Src_Idx + Remaining_Bytes;
            Dst_Idx  := Dst_Nxt;
         end;

         pragma Loop_Variant (Decreases => Msg_Len,
                              Increases => This.CS.I,
                              Increases => Src_Idx,
                              Increases => Dst_Idx,
                              Increases => Dst_Nxt);
         pragma Loop_Invariant (Src_Idx >= Source'First      and Src_Idx = Source'Last      - Msg_Len + 1 and
                                Dst_Idx >= Destination'First and Dst_Idx = Destination'Last - Msg_Len + 1 and
                                Dst_Nxt >= Destination'First and Dst_Nxt - 1 <= Destination'Last          and
                                (for all X in Destination'First .. Dst_Nxt - 1 => Destination (X) in Byte));
      end loop;
   end Encrypt_Bytes;

   --
   --  Encrypt_Packet
   --
   procedure Encrypt_Packet (This    : in     Context;
                             Nonce   : in     Nonce_Stream;
                             Header  : in     Plaintext_Stream;
                             Payload : in     Plaintext_Stream;
                             Packet  :    out Ciphertext_Stream;
                             Mac     :    out MAC_Stream) is
      Msg_Header : Ciphertext_Stream renames Packet (Packet'First .. Packet'First + Header'Length - 1);
      Msg_Body   : Ciphertext_Stream renames Packet (Packet'First + Header'Length .. Packet'Last);
      Local_Ctx  : Context := This;
   begin
      Setup_Nonce (This  => Local_Ctx,
                   Nonce => Nonce);
      Process_AAD (This => Local_Ctx,
                   Aad  => Header);
      Msg_Header := Ciphertext_Stream (Header);

      --  These assertions are all proved and copy the pre-condition of Decrypt_Bytes.
      --  SPARK still can't prove that the precondition won't fail.
      pragma Assert (Payload'First in Stream_Index and Packet'First in Stream_Index);
      pragma Assert (Msg_Body'Length = Payload'Length);
      pragma Assert (This.CS.Msg_Len mod 4 = 0);
      Encrypt_Bytes (This        => Local_Ctx,
                     Source      => Payload,
                     Destination => Msg_Body);
      Finalize (This => Local_Ctx,
                Mac  => Mac);
   end Encrypt_Packet;

   --
   --  Finalize
   --
   procedure Finalize (This : in     Context;
                       Mac  :    out MAC_Stream)
   is
      MAC_WORDS  : constant := MAC_INIT_CNT + MAC_WORD_CNT;
      Plain_Text : Interfaces.Unsigned_32;
      Mac_Index  : Stream_Offset;
      Tmp        : MAC_Stream (0 .. MAC_WORDS * 4 - 1);
      MAC_OFFSET : constant := Tmp'First + MAC_INIT_CNT * 4;
      --  Finalization step, we do not further modify the context.
      --  Still, we need to adjust some variables, so let's take a local copy.
      CS         : Cipher_State := This.CS;
   begin
      Plain_Text := CS.Msg_Len mod 4;
      CS.Z (0) := CS.Z (0) xor MAC_Magic_XOR;
      CS.Z (4) := CS.Z (4) xor Interfaces.Unsigned_32 (CS.AAD_Len mod 2 ** 32);
      CS.Z (2) := CS.Z (2) xor Interfaces.Unsigned_32 (CS.AAD_Len / 2 ** 32);
      CS.Z (1) := CS.Z (1) xor CS.AAD_Xor;         -- do this in case msgLen == 0

      for K in Interfaces.Unsigned_32 range 0 .. MAC_WORDS - 1 loop
         declare
            J : constant Mod_8 := Mod_8 (CS.I mod 8);
         begin
            H (Z              => CS.Z,
               Plaintext_Word => 0,
               Key_Word       => This.KS.X_0 (J));

            declare
               The_Key : constant Interfaces.Unsigned_32 :=
                           CS.Z (OLD_Z_REG) + CS.Old_Z (Old_State_Words (CS.I mod 4));
            begin
               Mac_Index := Tmp'First + Stream_Offset (K) * 4;
               Tmp (Mac_Index .. Mac_Index + 3) :=
                 MAC_Stream (BSWAP (Value  => The_Key xor Plain_Text,
                                    Length => 4));
               pragma Assert (for all X in Mac_Index .. Mac_Index + 3 => Tmp (X) in Byte);
               pragma Annotate (GNATprove,
                                False_Positive,
                                """Tmp"" might not be initialized",
                                "This is bonkers, there's an explicit assignment above");
            end;

            H (Z              => CS.Z,
               Plaintext_Word => Plain_Text,
               Key_Word       => This.KS.X_1 (J) + CS.I);
            CS.Old_Z (Old_State_Words (CS.I mod 4)) := CS.Z (OLD_Z_REG); -- save the "old" value
            CS.I := CS.I + 1;
         end;

         pragma Loop_Variant (Increases => K,
                              Increases => CS.I);
         pragma Loop_Invariant ((CS.I = CS.I'Loop_Entry + K + 1 and
                                 Mac'Length = Stream_Count (This.KS.MAC_Size / 8) and
                                 Mac_Index + 3 in Tmp'Range) and then
                                (for all X in Tmp'First .. Mac_Index + 3 => Tmp (X) in Byte));
      end loop;

      --  Copy the relevant bits back to MAC.
      Mac := Tmp (MAC_OFFSET .. MAC_OFFSET - 1 + Mac'Length);
   end Finalize;

   --
   --  H
   --
   procedure H (Z              : in out State_Words;
                Plaintext_Word : in     Interfaces.Unsigned_32;
                Key_Word       : in     Interfaces.Unsigned_32) is
   begin
      --  First half.
      Z (0) := Z (0) + (Z (3) xor Plaintext_Word);
      Z (3) := Interfaces.Rotate_Left (Value => Z (3), Amount => 15);

      Z (1) := Z (1) + Z (4);
      Z (4) := Interfaces.Rotate_Left (Value => Z (4), Amount => 25);

      Z (2) := Z (2) xor Z (0);
      Z (0) := Interfaces.Rotate_Left (Value => Z (0), Amount => 9);

      Z (3) := Z (3) xor Z (1);
      Z (1) := Interfaces.Rotate_Left (Value => Z (1), Amount => 10);

      Z (4) := Z (4) + Z (2);
      Z (2) := Interfaces.Rotate_Left (Value => Z (2), Amount => 17);

      --  Second half.
      Z (0) := Z (0) xor (Z (3) + Key_Word);
      Z (3) := Interfaces.Rotate_Left (Value => Z (3), Amount => 30);

      Z (1) := Z (1) xor Z (4);
      Z (4) := Interfaces.Rotate_Left (Value => Z (4), Amount => 13);

      Z (2) := Z (2) + Z (0);
      Z (0) := Interfaces.Rotate_Left (Value => Z (0), Amount => 20);

      Z (3) := Z (3) + Z (1);
      Z (1) := Interfaces.Rotate_Left (Value => Z (1), Amount => 11);

      Z (4) := Z (4) xor Z (2);
      Z (2) := Interfaces.Rotate_Left (Value => Z (2), Amount => 5);
   end H;

   --
   --  Process_AAD
   --
   procedure Process_AAD (This : in out Context;
                          Aad  : in     Plaintext_Stream)
   is
      Aad_Len : Stream_Count  := Aad'Length;
      Src_Idx : Stream_Offset := Aad'First;
   begin
      This.CS.AAD_Len := This.CS.AAD_Len + Aad'Length;

      while Aad_Len > 0 loop
         declare
            Remaining_Bytes : constant Stream_Count := Stream_Count'Min (Aad_Len, 4);
            J               : constant Mod_8 := Mod_8 (This.CS.I mod 8);
         begin
            Aad_Len := Aad_Len - Remaining_Bytes;

            H (Z              => This.CS.Z,
               Plaintext_Word => 0,
               Key_Word       => This.KS.X_0 (J));

            H (Z              => This.CS.Z,
               Plaintext_Word => BSWAP (Aad (Src_Idx .. Src_Idx + Remaining_Bytes - 1)),
               Key_Word       => This.KS.X_1 (J) + This.CS.I);

            This.CS.Old_Z (Old_State_Words (This.CS.I mod 4)) := This.CS.Z (OLD_Z_REG); --  Save the "old" value

            This.CS.I := This.CS.I + 1;
            Src_Idx := Src_Idx + Remaining_Bytes;
         end;

         pragma Loop_Variant (Decreases => Aad_Len,
                              Increases => Src_Idx,
                              Increases => This.CS.I);
         pragma Loop_Invariant (Src_Idx + Aad_Len - 1 = Aad'Last and then
                                Src_Idx >= Aad'First);
      end loop;
   end Process_AAD;

   --
   --  Setup_Key
   --
   procedure Setup_Key (This     : in out Context;
                        Key      : in     Key_Stream;
                        Mac_Size : in     MAC_Size_32)
   is
      Key_Size : constant Key_Size_32 := 8 * Key'Length;
      Z        : State_Words := (others => 0); --  FIXME: Unnecessary initialization. Speeds up proof, though.
   begin
      --  save key and mac sizes, nonce size is always 128
      This.KS.Key_Size := Key_Size;
      This.KS.MAC_Size := Mac_Size;

      --  pre-compute X_1_bump "constant" to save clock cycles during Setup_Nonce
      This.KS.X_1_Bump := Key_Size / 2 + 256 * (Mac_Size mod Max_MAC_Size);

      --  copy key to X[], in correct endianness
      --  Special case for zero length key, then we just set everything to 0.
      if Key'Length = 0 then
         This.KS.X_0 := (others => 0);
      else
         for I in This.KS.X_0'Range loop
            declare
               Subkey_First : constant Stream_Offset :=
                                Stream_Offset'Min (Key'First + Stream_Offset (I - This.KS.X_0'First) * 4, Key'Last + 1);
               Subkey_Last  : constant Stream_Offset :=
                                Stream_Offset'Min (Subkey_First + 3, Key'Last);
            begin
               This.KS.X_0 (I) := BSWAP (Key (Subkey_First .. Subkey_Last));
               pragma Loop_Invariant (for all S in This.KS.X_0'First .. I =>
                                        This.KS.X_0 (S) =
                                        BSWAP (Key (Key'First + Stream_Offset (S - This.KS.X_0'First) * 4 ..
                                            Stream_Offset'Min (Key'First + Stream_Offset (S - This.KS.X_0'First) * 4 + 3,
                                                               Key'Last))));
            end;
         end loop;
      end if;

      --  Now process the padded "raw" key, using a Feistel network
      for I in Mod_8'Range loop
         declare
            K : Mod_8;
         begin
            K := 4 * (I mod 2);
            pragma Assert (K in 0 | 4);

            Z (Z'First .. Z'Last - 1) := This.KS.X_0 (K .. K + 3);
            Z (Z'Last)                := Key_Size / 8 + 64;

            H (Z              => Z,
               Plaintext_Word => 0,
               Key_Word       => 0);
            H (Z              => Z,
               Plaintext_Word => 0,
               Key_Word       => 0);

            K := K + 4; --  mod 8 is done automatically
            pragma Assert (K in 4 | 0);

            --  This.KS.X_0 (K .. K + 3) := This.KS.X_0 (K .. K + 3) xor Z (0 .. 3);
            for J in Mod_8 range K .. K + 3 loop
               This.KS.X_0 (J) := This.KS.X_0 (J) xor Z (J - K);
               pragma Loop_Invariant (for all S in K .. J =>
                                        This.KS.X_0 (S) = (This.KS.X_0'Loop_Entry (S) xor Z (S - K)));
            end loop;
         end;
      end loop;
   end Setup_Key;

   --
   --  Setup_Nonce
   --
   procedure Setup_Nonce (This  : in out Context;
                          Nonce : in     Nonce_Stream) is
   begin
      --  Initialize subkeys and Z values
      for I in Mod_8 range 0 .. 3 loop
         declare
            N : constant Interfaces.Unsigned_32 :=
                  BSWAP (Nonce (Nonce'First + Stream_Offset (I) * 4 .. Nonce'First + Stream_Offset (I) * 4 + 3));
         begin
            This.KS.X_1 (I)     := This.KS.X_0 (I + 4) + N;
            This.KS.X_1 (I + 4) := This.KS.X_0 (I)     + (Interfaces.Unsigned_32 (I) - N);
            This.CS.Z (I)       := This.KS.X_0 (I + 3) xor N;
         end;
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
            Key_Word       => This.KS.X_1 (I) + Interfaces.Unsigned_32 (I));

         This.CS.Old_Z (I mod 4) := This.CS.Z (OLD_Z_REG); --  save the "old" value
      end loop;

      This.CS.AAD_Xor := AAD_Magic_XOR; --  perform the AAD xor
      This.CS.Z (1) := This.CS.Z (1) xor This.CS.AAD_Xor;

      This.CS.I := 8;
   end Setup_Nonce;

end Crypto.Phelix;
