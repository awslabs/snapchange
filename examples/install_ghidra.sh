#!/bin/bash

# If the ghidra directory is not currently installed, install it
if [ ! -d ./ghidra ]; then 
  # Install pre-reqs for Ghidra
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends openjdk-17-jdk unzip wget

  # Download the Ghidra package
  wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.2.2_build/ghidra_10.2.2_PUBLIC_20221115.zip -O ghidra.zip
  unzip ghidra.zip 

  # Remove the Ghidra zip
  rm ghidra.zip 
  mv ghidra_10* ghidra

  # Remove the demangler script as we want the demangled names for searching for asan, msan, lsan, ect
  /bin/rm ghidra/Ghidra/Features/Base/ghidra_scripts/DemangleAllScript.java
  /bin/rm ghidra/Ghidra/Features/Base/ghidra_scripts/DemangleSymbolScript.java
  /bin/rm -rf ghidra/Ghidra/Features/GnuDemangler
  /bin/rm -rf ghidra/GPL/DemanglerGnu
  /bin/rm -rf ghidra/Ghidra/Features/MicrosoftDemangler/


  ls -la
fi
