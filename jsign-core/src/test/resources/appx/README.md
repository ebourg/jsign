APPX package & bundle
=====================

Steps to generate the APPX package and bundle:

1. Add `makeappx` to the PATH:

       set PATH=%PATH%;C:\Program Files (x86)\Windows Kits\10\App Certification Kit

2. Create the package:

       makeappx pack /f mapping.txt /p bundle/minimal.appx /o /h SHA512

3. Create the bundle:

       makeappx bundle /d bundle /p minimal.appxbundle /o
