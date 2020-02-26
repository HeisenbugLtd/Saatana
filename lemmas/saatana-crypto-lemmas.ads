------------------------------------------------------------------------------
--  Copyright (C) 2020 by Heisenbug Ltd. (gh+saatana@heisenbug.eu)
--
--  This work is free. You can redistribute it and/or modify it under the
--  terms of the Do What The Fuck You Want To Public License, Version 2,
--  as published by Sam Hocevar. See the LICENSE file for more details.
------------------------------------------------------------------------------
pragma License (Unrestricted);

private package Saatana.Crypto.Lemmas with
  SPARK_Mode => On
is

   --
   --  Prove additional properties of the types declared in the parent
   --  package.
   --
   --  These proofs are not actively used anywhere, but they should help
   --  building confidence in the correctness of certain subprograms.

   ---------------------------------------------------------------------
   --  Stream conversions
   ---------------------------------------------------------------------

   --  Fully prove bijectivity of conversion subprogram(s).

   --  Part I

   --  Converting a Word_32 into a stream representation and converting
   --  the stream back into a Word_32 should result in the same value.
   pragma Assert (for all W in Word_32'Range =>
                    To_Unsigned (General_Stream'(To_Stream (W))) = W);

   --  Part II

   --  The inverse of the above is harder to accomplish, because there
   --  seems no easy way to write a quantifiying expression for
   --  different length arrays (at least none of the ones I could think
   --  of are less complex than the relatively simple five different
   --  expressions below).

   --  Luckily, the number of possibilities here is low, so let's simply
   --  prove all cases one by one.

   --  Proof for Stream'Length = 4
   pragma Assert (for all A in Byte =>
                    (for all B in Byte =>
                       (for all C in Byte =>
                            (for all D in Byte =>
                                 General_Stream'(To_Stream (To_Unsigned (General_Stream'(0 => A, 1 => B, 2 => C, 3 => D)))) =
                                   General_Stream'(0 => A, 1 => B, 2 => C, 3 => D)))));

   --  Proof for Stream'Length = 3
   pragma Assert (for all A in Byte =>
                    (for all B in Byte =>
                       (for all C in Byte =>
                            General_Stream'(To_Stream (To_Unsigned (General_Stream'(0 => A, 1 => B, 2 => C)))) =
                              General_Stream'(0 => A, 1 => B, 2 => C, 3 => 0))));

   --  Proof for Stream'Length = 2
   pragma Assert (for all A in Byte =>
                    (for all B in Byte =>
                       General_Stream'(To_Stream (To_Unsigned (General_Stream'(0 => A, 1 => B)))) =
                         General_Stream'(0 => A, 1 => B, 2 .. 3 => 0)));

   --  Proof for Stream'Length = 1
   pragma Assert (for all A in Byte =>
                    General_Stream'(To_Stream (To_Unsigned (General_Stream'(0 => A)))) =
                      General_Stream'(0 => A, 1 .. 3 => 0));

   --  Proof for Stream'Length = 0 (i.e. the empty stream).
   pragma Assert (General_Stream'(To_Stream (To_Unsigned (General_Stream'(1 .. 0 => 0)))) =
                    General_Stream'(0 .. 3 => 0));

end Saatana.Crypto.Lemmas;
