#!/bin/bash

GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.2.2_build/ghidra_10.2.2_PUBLIC_20221115.zip"

# If the ghidra directory is not currently installed, install it
if [ ! -d ./ghidra ]; then 

  # Download the Ghidra package
  wget -q "$GHIDRA_URL" -O ghidra.zip
  unzip ghidra.zip >/dev/null 2>&1
  rm ghidra.zip 
  mv ghidra_10* ghidra

  # Remove the demangler script as we want the demangled names for searching for asan, msan, lsan, ect
  rm ghidra/Ghidra/Features/Base/ghidra_scripts/DemangleAllScript.java
  rm ghidra/Ghidra/Features/Base/ghidra_scripts/DemangleSymbolScript.java
  rm -rf ghidra/Ghidra/Features/GnuDemangler
  rm -rf ghidra/GPL/DemanglerGnu
  rm -rf ghidra/Ghidra/Features/MicrosoftDemangler/
fi
