#########################################
Voice Activity Detection demo application
#########################################

A demo application for the AN552 FPGA showcasing:

* secure partition using MVE to speed up algorithms
* secure peripheral usage from secure partition with interrupt handling
* AWS cloud connectivity with OTA on the non-secure side

---------------
Brief Operation
---------------

After boot-up the application first checks whether Over-the-Air update (OTA)
was initiated from AWS cloud. If yes, the OTA process is executed, otherwise
the voice activity detection algorithm is started on the secure side. While the
algorithm is running the non-secure side keep polling it for results. After a
minute the algorithm is stopped, and the operation restarted with the OTA check
again.

If the algorithm detects voice, a short audio sample (~100 ms) is recorded, and
the highest energy frequency component is calculated. This frequency is written
onto the serial line and it is sent to AWS cloud. Then the algorithm is
restarted or the OTA check is started if the timeout is up.

By default the solution requires ethernet connectivity, it will not start the
main operation until the network is up. This can be overwritten if the
``-DVAD_AN552_NO_CONNECTIVITY=ON`` cmake flag is defined. The effect is:

* No need for Ethernet connection.
* No need for IoT thing creation in AWS cloud and source update with
  its credentials.
* OTA check and AWS cloud communication is not executed.

---------------
HW requirements
---------------

* AN552 Version 2.0 FPGA image on MPS3 board.
* Ethernet connection with access to the internet. (Not needed if
  ``-DVAD_AN552_NO_CONNECTIVITY=ON`` is added for cmake.)
* 2 or 3 pole microphone connected into the audio connector. In case of a
  stereo microphone only the right channel is used.

------------------
Build instructions
------------------

*********************************************************
AWS thing creation and source update with the credentials
*********************************************************

By default it is required to create an IoT thing in AWS to run the application,
but this can be skipped if ``-DVAD_AN552_NO_CONNECTIVITY=ON`` is added for
cmake.

###################################
Create an IoT thing for your device
###################################

#. Login to your account and browse to the `AWS IoT console <https://console.aws.amazon.com/iotv2/>`__.
#. In the left navigation pane, choose ``All devices``, and then choose ``Things``.
#. Click on ``Create things``.
#. Choose ``Create single thing``.
#. At the ``Specify thing properties`` page add the name of your thing at
   ``Thing name``. You will need to add the name later to your C code. Click
   ``Next``.
#. At the ``Configure device certificate`` page choose ``Auto-generate a new
   certificate``, and click ``Next``.
#. The thing can be created by clicking on ``Create thing`` at the
   ``Attach policies to certificate`` page. The policy will be created at the
   next section.
#. Download the key files and the certificate, and make a note of the name of
   the certificate.
#. Activate your certificate if it is not active by default.

###############
Create a policy
###############

For the sake of simplicity in this example a very permissive Policy is created,
for production usage a more restrictive one is recommended.

#. In the navigation pane of the AWS IoT console, choose ``Security``, and then
   choose ``Policies``.
#. At the ``Policies`` page, choose ``Create policy``.
#. At the ``Create a policy`` page, enter a name for the policy.
#. At the Policy document click on JSON, and paste the following snippet into the
   Policy document textbox, then click on ``Create``. (``Region`` and
   ``Account ID`` must be updated.)

.. code-block:: JSON

   {
   "Version": "2012-10-17",
   "Statement": [
      {
         "Effect": "Allow",
         "Action": [
         "iot:Connect",
         "iot:Publish",
         "iot:Subscribe",
         "iot:Receive"
         ],
         "Resource": "arn:aws:iot:<Region>:<Account ID without dashes>:*"
      }
   ]
   }

#######################################
Attach the created policy to your thing
#######################################

#. In the left navigation pane of the AWS IoT console, choose ``Secure``, and
   then choose ``Certificates``. You should see the certificate that you have
   created earlier.
#. Click on the three dots next to the certificate and choose
   ``Attach policy``.
#. In the ``Attach policies to certificate(s)`` window choose the created
   policy and click ``Attach``.

####################################
Update source with thing credentials
####################################

Edit `examples/vad_an552/ns_side/amazon-freertos/aws_clientcredential.h` file and
set the value of the following macros:

* `clientcredentialMQTT_BROKER_ENDPOINT`, set this to the endpoint name of your
  amazon account. To find this go to the AWS IoT console page and in the left
  navigation pane click on ``Settings``. The Endpoint can be found under
  ``Device data endpoint``.

* `clientcredentialIOT_THING_NAME`, set this to the name of the created thing.

Recreate or update examples/vad_an552/ns_side/amazon-freertos/aws_clientcredential_keys.h`
with the downloaded certificate and keys.

Recreate with the html tool from Amazon-FreeRTOS:

#. Clone `Amazon-FreeRTOS <https://github.com/aws/amazon-freertos>`__.
#. Open ``Amazon-FreeRTOS/tools/certificate_configuration/CertificateConfigurator.html``
   in your browser.
#. Upload the downloaded certificate and the private key.
#. Click on ``Generate and save aws_clientcredential_keys.h``
#. Download the file and update `examples/vad_an552/ns_side/amazon-freertos/aws_clientcredential_keys.h`
   with it.

Alternatively, the file can be updated by hand by setting the values of the
following macros:

* ``keyCLIENT_CERTIFICATE_PEM``, content of ``<your-thing-certificate-unique-string>-certificate.pem.crt``.
* ``keyCLIENT_PRIVATE_KEY_PEM``, content of ``<your-thing-certificate-unique-string>-private.pem.key``.
* ``keyCLIENT_PUBLIC_KEY_PEM``, content of ``<your-thing-certificate-unique-string>-public.pem.key``.

##################
Running TF-M build
##################

For building TF-M's build system is used with the following mandatory CMAKE
flags::

    -DTFM_PLATFORM=arm/mps3/an552
    -DNS_EVALUATION_APP_PATH=<path-to-tf-m-extras-repo>/examples/vad_an552/ns_side
    -DTFM_EXTRA_PARTITION_PATHS=<path-to-tf-m-extras-repo>/partitions/vad_an552_sp/
    -DTFM_EXTRA_MANIFEST_LIST_FILES=<path-to-tf-m-extras-repo>/partitions/vad_an552_sp/extra_manifest_list.yaml
    -DPROJECT_CONFIG_HEADER_FILE=<path-to-tf-m-extras-repo>/examples/vad_an552/ns_side/project_config.h
    -DTFM_PARTITION_FIRMWARE_UPDATE=ON -DMCUBOOT_DATA_SHARING=ON
    -DMCUBOOT_UPGRADE_STRATEGY=SWAP_USING_SCRATCH
    -DMCUBOOT_IMAGE_NUMBER=1 -DMCUBOOT_SIGNATURE_KEY_LEN=2048
    -DCONFIG_TFM_ENABLE_MVE=ON -DCONFIG_TFM_SPM_BACKEND=IPC
    -DPLATFORM_HAS_FIRMWARE_UPDATE_SUPPORT=ON -DTFM_PARTITION_PLATFORM=ON
    -DTFM_PARTITION_CRYPTO=ON -DTFM_PARTITION_INTERNAL_TRUSTED_STORAGE=ON
    -DTFM_PARTITION_PROTECTED_STORAGE=ON -DMCUBOOT_CONFIRM_IMAGE=ON


The application also can be run without MVE support, in that case the
``-DCONFIG_TFM_ENABLE_MVE=ON`` flags should be omitted, and the
``configENABLE_MVE`` can be set to ``0`` in the
``ns_side/amazon-freertos/FreeRTOSConfig.h`` file.
Our measurements showed that MVE speeds up the frequency calculation by 10
times with release GCC build.

You can check TF-M's build instructions
`here <https://tf-m-user-guide.trustedfirmware.org/docs/technical_references/instructions/tfm_build_instruction.html>`__.

-----------------------
Running the application
-----------------------

It is covered by the generic TF-M run instructions for AN552
`here <https://tf-m-user-guide.trustedfirmware.org/platform/ext/target/arm/mps3/an552/README.html>`__.

---------------------------
Testing the voice algorithm
---------------------------

Start up the board, wait until ``==== Start listening ====`` is written on the
serial console and start talking, or make some noise. You can check that the
``Voice detected with most energy at X Hz`` message is written onto the serial
console, and the same message is sent to AWS cloud.

For checking the AWS messages:

#. In the left navigation pane of the AWS IoT console, choose ``Test``.
#. Define ``<Name of your thing>/vad_an552`` as the topic filter.
#. Click on ``Subscribe``.
#. Once a message is sent to AWS cloud you should see it on this page.

.. note::

   For this test it is recommended to find a quiet environment, because any
   noise can trigger the voice activity algorithm.

For testing the frequency calculation pure sine signals should be used,
the accuracy is about +/- 100 Hz.

----------------------
Testing Amazon AWS OTA
----------------------

To run an OTA update a new image must be created with higher version number.
This can be easily done by rebuilding the solution with the following cmake
flag: ``-DMCUBOOT_IMAGE_VERSION_S=2.1.0``. (The version itself can be anything, but
must be higher than the version of the currently running image.) The
``-DMCUBOOT_CONFIRM_IMAGE`` flag should be set to OFF in the new image build
config, because the demo going to confirm the new image after downloading it.

The image signature must be extracted from the final binary, can be done by
openssl running the following commands in the build directory:

#. ``openssl dgst -sha256 -binary -out update-digest.bin tfm_s_ns_signed.bin``
#. ``openssl pkeyutl -sign -pkeyopt digest:sha256 -pkeyopt rsa_padding_mode:pss -pkeyopt rsa_mgf1_md:sha256 -inkey <path to tfm source>/bl2/ext/mcuboot/root-RSA-2048.pem -in update-digest.bin -out update-signature.bin``
#. ``openssl base64 -A -in update-signature.bin -out update-signature.txt``

Once the signature extracted into ``update-signature.txt`` file, the OTA job
can be created:

#. `Create an Amazon S3 bucket to store your update <https://docs.aws.amazon.com/freertos/latest/userguide/dg-ota-bucket.html>`__.
#. `Create an OTA Update service role <https://docs.aws.amazon.com/freertos/latest/userguide/create-service-role.html>`__.
#. `Create an OTA user policy <https://docs.aws.amazon.com/freertos/latest/userguide/create-ota-user-policy.html>`__.
#. Go to AWS IoT web interface and choose ``Manage`` and then ``Jobs``.
#. Click the create job button and select ``Create FreeRTOS OTA update job``.
#. Give it a name and click next.
#. Select the device to update (the Thing you created in earlier steps).
#. Select ``MQTT`` transport only.
#. Select ``Use my custom signed file``.
#. Paste the signature string from the ``update-signature.txt`` file. Make sure
   that it is pasted as it is without any whitespace characters.
#. Select ``SHA-256`` and ``RSA`` algorithms.
#. For ``Path name of code signing certificate on device`` put in ``0``
   (the path is not used).
#. Select upload new file and select the signed update binary
   ``tfm_s_ns_signed.bin``.
#. Select the S3 bucket you created to upload the binary to.
#. For ``Path name of file on device`` put in ``combined image``.
#. As the role, select the OTA role you created.
#. Click next.
#. Click next, your update job is ready and running. If your board is running
   (or the next time it will be turned on) the update will be performed.

After the update happened the system resets, and the image version is written
onto the serial console. That way the update can be verified.

.. note::

   The OTA process only updates the image stored in RAM, so if the MPS3 board
   is power cycled the system will boot up with the original image. The FPGA at
   power-on loads the application image from the SD card to RAM, and the SD
   card content is not changed during OTA.

-------------

*Copyright (c) 2021-2022, Arm Limited. All rights reserved.*
