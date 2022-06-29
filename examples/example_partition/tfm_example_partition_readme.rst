###############################
TF-M Example Partition - Readme
###############################
The TF-M example partition is a simple secure partition implementation provided
to aid development of new secure partitions. It implements one App RoT Service
and one interrupt handler.

********************************
How to run the example partition
********************************
#. Copy the ``example_partition`` directory to the ``secure_fw/partitions``
   directory of the TF-M repo.

#. Add the partition to the TF-M CMake by inserting
   ``add_subdirectory(partitions/example_partition)`` in
   ``secure_fw/CMakeLists.txt``, in the block below the line
   ``add_subdirectory(partitions/lib/sprt)``.

#. Add the following entry to ``tools/tfm_manifest_list.yaml``. The ``pid``
   field must be unique (currently used partition ids are documented in
   tfm_secure_partition_addition.rst on line 150), or can omitted which will
   allocate one automatically. ::

    {
      "name": "TF-M Example Partition",
      "short_name": "TFM_SP_EXAMPLE",
      "manifest": "secure_fw/partitions/example_partition/tfm_example_partition.yaml",
      "conditional": "TFM_PARTITION_EXAMPLE",
      "version_major": 0,
      "version_minor": 1,
      "pid": 356,
      "linker_pattern": {
        "library_list": [
           "*tfm_*partition_example.*"
        ]
      }
    }

#. Build TF-M in the usual way, but provide ``-DTFM_PARTITION_EXAMPLE=ON`` as a
   parameter to the CMake command.

--------------

*Copyright (c) 2020-2021, Arm Limited. All rights reserved.*
