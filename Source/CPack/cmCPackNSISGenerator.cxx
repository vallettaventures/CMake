/*=========================================================================

  Program:   CMake - Cross-Platform Makefile Generator
  Module:    $RCSfile$
  Language:  C++
  Date:      $Date$
  Version:   $Revision$

  Copyright (c) 2002 Kitware, Inc., Insight Consortium.  All rights reserved.
  See Copyright.txt or http://www.cmake.org/HTML/Copyright.html for details.

     This software is distributed WITHOUT ANY WARRANTY; without even 
     the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR 
     PURPOSE.  See the above copyright notices for more information.

=========================================================================*/

#include "cmCPackNSISGenerator.h"

#include "cmake.h"
#include "cmGlobalGenerator.h"
#include "cmLocalGenerator.h"
#include "cmSystemTools.h"
#include "cmMakefile.h"
#include "cmGeneratedFileStream.h"

#include <cmsys/SystemTools.hxx>
#include <cmsys/Glob.hxx>

//----------------------------------------------------------------------
cmCPackNSISGenerator::cmCPackNSISGenerator()
{
}

//----------------------------------------------------------------------
cmCPackNSISGenerator::~cmCPackNSISGenerator()
{
}

//----------------------------------------------------------------------
int cmCPackNSISGenerator::ProcessGenerator()
{
  return this->Superclass::ProcessGenerator();
}

//----------------------------------------------------------------------
int cmCPackNSISGenerator::CompressFiles(const char* outFileName, const char* toplevel,
  const std::vector<std::string>& files)
{
  (void)outFileName; // TODO: Fix nsis to force out file name
  (void)toplevel;
  (void)files;
  std::string nsisInFileName = this->FindTemplate("NSIS.template.in");
  if ( nsisInFileName.size() == 0 )
    {
    std::cerr << "CPack error: Could not find NSIS installer template file." << std::endl;
    return false;
    }
  std::string nsisFileName = this->GetOption("CPACK_TOPLEVEL_DIRECTORY");
  std::string tmpFile = nsisFileName;
  tmpFile += "/NSISOutput.log";
  nsisFileName += "/project.nsi";
  std::cout << "Configure file: " << nsisInFileName << " to " << nsisFileName << std::endl;
  this->ConfigureFile(nsisInFileName.c_str(), nsisFileName.c_str());
  std::string nsisCmd = "\"";
  nsisCmd += this->GetOption("CPACK_INSTALLER_PROGRAM");
  nsisCmd += "\" \"" + nsisFileName + "\"";
  std::cout << "Execute: " << nsisCmd.c_str() << std::endl;
  std::string output;
  int retVal = 1;
  bool res = cmSystemTools::RunSingleCommand(nsisCmd.c_str(), &output, &retVal, 0, m_GeneratorVerbose, 0);
  if ( !res || retVal )
    {
    cmGeneratedFileStream ofs(tmpFile.c_str());
    ofs << "# Run command: " << nsisCmd.c_str() << std::endl
      << "# Output:" << std::endl
      << output.c_str() << std::endl;
    std::cerr << "Problem running NSIS command: " << nsisCmd.c_str() << std::endl;
    std::cerr << "Please check " << tmpFile.c_str() << " for errors" << std::endl;
    return 0;
    }
  return 1;
}

//----------------------------------------------------------------------
int cmCPackNSISGenerator::Initialize(const char* name)
{
  std::cout << "cmCPackNSISGenerator::Initialize()" << std::endl;
  int res = this->Superclass::Initialize(name);
  std::vector<std::string> path;
  std::string nsisPath;
  if ( !cmsys::SystemTools::ReadRegistryValue("HKEY_LOCAL_MACHINE\\SOFTWARE\\NSIS",
      nsisPath) )
    {
    std::cerr << "Cannot find NSIS registry value" << std::endl;
    return 0;
    }
  path.push_back(nsisPath);
  nsisPath = cmSystemTools::FindProgram("makensis", path, false);
  if ( nsisPath.empty() )
    {
    std::cerr << "Cannot find NSIS compiler" << std::endl;
    return 0;
    }
  this->SetOption("CPACK_INSTALLER_PROGRAM", nsisPath.c_str());
  return res;
}

