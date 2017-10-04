--  Default is running in SPARK mode.
pragma SPARK_Mode (On);

--  Restricted run-time (safe tasking subset). This should cover most of the
--  required restrictions from ARM D.7 (tasking restrictions)
pragma Profile (Ravenscar);

--  SPARK also requires sequential elaboration, so that the elaboration is
--  guaranteed to be finished before tasks are started.
pragma Partition_Elaboration_Policy (Sequential);

--
--  Additional restrictions.
--

--  High integrity restrictions (ARM H.4)
--pragma Restrictions (No_Allocators);
--pragma Restrictions (No_Local_Allocators);
pragma Restrictions (No_Coextensions);
pragma Restrictions (No_Access_Parameter_Allocators);
pragma Restrictions (Immediate_Reclamation);

pragma Restrictions (No_Exceptions);
pragma Restrictions (No_Access_Subprograms);
pragma Restrictions (No_Dispatch);
--pragma Restrictions (No_IO);
pragma Restrictions (No_Relative_Delay);
