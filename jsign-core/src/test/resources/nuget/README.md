NuGet package
=============

Steps to generate the NuGet package:

1. Download and install nuget.exe from https://www.nuget.org/downloads

2. Create the package:

       nuget pack minimal.nuspec -Exclude README.md
