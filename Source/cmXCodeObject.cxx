/* Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
   file Copyright.txt or https://cmake.org/licensing for details.  */
#include "cmXCodeObject.h"

#include <ostream>
#include <sstream>
#include <iostream>
#include <iomanip>

#include <CoreFoundation/CoreFoundation.h>

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonCryptor.h>

#include "cmSystemTools.h"

const char* cmXCodeObject::PBXTypeNames[] = {
  /* clang-format needs this comment to break after the opening brace */
  "PBXGroup",
  "PBXBuildStyle",
  "PBXProject",
  "PBXHeadersBuildPhase",
  "PBXSourcesBuildPhase",
  "PBXFrameworksBuildPhase",
  "PBXNativeTarget",
  "PBXFileReference",
  "PBXBuildFile",
  "PBXContainerItemProxy",
  "PBXTargetDependency",
  "PBXShellScriptBuildPhase",
  "PBXResourcesBuildPhase",
  "PBXApplicationReference",
  "PBXExecutableFileReference",
  "PBXLibraryReference",
  "PBXToolTarget",
  "PBXLibraryTarget",
  "PBXAggregateTarget",
  "XCBuildConfiguration",
  "XCConfigurationList",
  "PBXCopyFilesBuildPhase",
  "None"
};

cmXCodeObject::~cmXCodeObject()
{
  this->Version = 15;
}

// Cache from hashing Key to object id
static std::map<std::string, std::string> objectIdCache;
static std::mutex objectIdCacheMutex;
static size_t sequenceIndex = 0;

static std::string cmGetUniqueXcodeId(const std::string& hashingKey, const std::string& prefix) {
    std::string lookupKey(prefix + "-" + hashingKey);

    auto it = objectIdCache.find(lookupKey);
    if (it != objectIdCache.end()) {
        return it->second;
    } else {
        // calculate sha-256 as base
        uint8_t digest[CC_SHA256_DIGEST_LENGTH] = {0};
        CC_SHA256(hashingKey.c_str(), (CC_LONG)hashingKey.length(), digest);

        // hex and truncate that to 24 chars
        std::stringstream idStream;
        for (size_t i = 0; i < 12; i += 1) {
            idStream << std::setw(2) << std::setfill('0') << std::hex;
            idStream << (int)digest[i];
        }

        std::string xcodeId = prefix + idStream.str();
        if (xcodeId.length() > 24) {
            xcodeId.erase(xcodeId.begin() + 24);
        }

        // TODO Check for collision?
        return objectIdCache[lookupKey] = xcodeId;
    }
}

void cmXCodeObject::resetIdSequence() {
    std::lock_guard<std::mutex> guard(objectIdCacheMutex);
    sequenceIndex = 0;
}

cmXCodeObject::cmXCodeObject(PBXType ptype, Type type, const std::string& hashingKey)
{
  this->Version = 15;
  this->Target = nullptr;
  this->Object = nullptr;

  this->IsA = ptype;

  if (type == OBJECT) {
     std::lock_guard<std::mutex> guard(objectIdCacheMutex);
      // Set the Id of an Xcode object to a unique string for each instance.
      // However the Xcode user file references certain Ids: for those cases,
      // override the generated Id using SetId().

      if (hashingKey.length() == 0) {
        sequenceIndex += 1;
        std::string id = std::to_string(sequenceIndex);
        while (id.length() < 22) {
            id = "0" + id;
        }
        this->Id = "01" + id;
      } else {
        this->Id = cmGetUniqueXcodeId(hashingKey, "02");
      }
  } else {
    this->Id =
      "Temporary cmake object, should not be referred to in Xcode file";
  }

  cmSystemTools::ReplaceString(this->Id, "-", "");
  if (this->Id.size() > 24) {
    this->Id = this->Id.substr(0, 24);
  }

  this->TypeValue = type;
  if (this->TypeValue == OBJECT) {
    this->AddAttribute("isa", nullptr);
  }
}

bool cmXCodeObject::IsEmpty() const
{
  switch (this->TypeValue) {
    case OBJECT_LIST:
      return this->List.empty();
    case STRING:
      return this->String.empty();
    case ATTRIBUTE_GROUP:
      return this->ObjectAttributes.empty();
    case OBJECT_REF:
    case OBJECT:
      return this->Object == nullptr;
  }
  return true; // unreachable, but quiets warnings
}

void cmXCodeObject::Indent(int level, std::ostream& out)
{
  while (level) {
    out << "\t";
    level--;
  }
}

void cmXCodeObject::Print(std::ostream& out)
{
  std::string separator = "\n";
  int indentFactor = 1;
  cmXCodeObject::Indent(2 * indentFactor, out);
  if (this->Version > 15 &&
      (this->IsA == PBXFileReference || this->IsA == PBXBuildFile)) {
    separator = " ";
    indentFactor = 0;
  }
  out << this->Id;
  this->PrintComment(out);
  out << " = {";
  if (separator == "\n") {
    out << separator;
  }
  cmXCodeObject::Indent(3 * indentFactor, out);
  out << "isa = " << PBXTypeNames[this->IsA] << ";" << separator;
  for (const auto& keyVal : this->ObjectAttributes) {
    if (keyVal.first == "isa") {
      continue;
    }

    PrintAttribute(out, 3, separator, indentFactor, keyVal.first,
                   keyVal.second, this);
  }
  cmXCodeObject::Indent(2 * indentFactor, out);
  out << "};\n";
}

void cmXCodeObject::PrintAttribute(std::ostream& out, int level,
                                   const std::string& separator, int factor,
                                   const std::string& name,
                                   const cmXCodeObject* object,
                                   const cmXCodeObject* parent)
{
  cmXCodeObject::Indent(level * factor, out);
  switch (object->TypeValue) {
    case OBJECT_LIST: {
      out << name << " = (";
      if (parent->TypeValue != ATTRIBUTE_GROUP) {
        out << separator;
      }
      for (unsigned int i = 0; i < object->List.size(); ++i) {
        if (object->List[i]->TypeValue == STRING) {
          object->List[i]->PrintString(out);
          if (i + 1 < object->List.size()) {
            out << ",";
          }
        } else {
          cmXCodeObject::Indent((level + 1) * factor, out);
          out << object->List[i]->Id;
          object->List[i]->PrintComment(out);
          out << "," << separator;
        }
      }
      if (parent->TypeValue != ATTRIBUTE_GROUP) {
        cmXCodeObject::Indent(level * factor, out);
      }
      out << ");" << separator;
    } break;

    case ATTRIBUTE_GROUP: {
      out << name << " = {";
      if (separator == "\n") {
        out << separator;
      }
      for (const auto& keyVal : object->ObjectAttributes) {
        PrintAttribute(out, (level + 1) * factor, separator, factor,
                       keyVal.first, keyVal.second, object);
      }
      cmXCodeObject::Indent(level * factor, out);
      out << "};" << separator;
    } break;

    case OBJECT_REF: {
      cmXCodeObject::PrintString(out, name);
      out << " = " << object->Object->Id;
      if (object->Object->HasComment() && name != "remoteGlobalIDString") {
        object->Object->PrintComment(out);
      }
      out << ";" << separator;
    } break;

    case STRING: {
      cmXCodeObject::PrintString(out, name);
      out << " = ";
      object->PrintString(out);
      out << ";" << separator;
    } break;

    default: {
      break;
    }
  }
}

void cmXCodeObject::PrintList(std::vector<cmXCodeObject*> const& objs,
                              std::ostream& out)
{
  cmXCodeObject::Indent(1, out);
  out << "objects = {\n";
  for (auto obj : objs) {
    if (obj->TypeValue == OBJECT) {
      obj->Print(out);
    }
  }
  cmXCodeObject::Indent(1, out);
  out << "};\n";
}

void cmXCodeObject::CopyAttributes(cmXCodeObject* copy)
{
  this->ObjectAttributes = copy->ObjectAttributes;
  this->List = copy->List;
  this->String = copy->String;
  this->Object = copy->Object;
}

void cmXCodeObject::PrintString(std::ostream& os, const std::string& String)
{
  // The string needs to be quoted if it contains any characters
  // considered special by the Xcode project file parser.
  bool needQuote = (String.empty() || String.find("//") != std::string::npos ||
                    String.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                             "abcdefghijklmnopqrstuvwxyz"
                                             "0123456789"
                                             "$_./") != std::string::npos);
  const char* quote = needQuote ? "\"" : "";

  // Print the string, quoted and escaped as necessary.
  os << quote;
  for (auto c : String) {
    if (c == '"' || c == '\\') {
      // Escape double-quotes and backslashes.
      os << '\\';
    }
    os << c;
  }
  os << quote;
}

void cmXCodeObject::PrintString(std::ostream& os) const
{
  cmXCodeObject::PrintString(os, this->String);
}

void cmXCodeObject::SetString(const std::string& s)
{
  this->String = s;
}
