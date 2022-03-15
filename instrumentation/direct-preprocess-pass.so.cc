/*
   american fuzzy lop - LLVM-mode instrumentation pass
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres. C bits copied-and-pasted
   from afl-as.c are Michal's fault.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This library is plugged into LLVM when invoking clang through afl-clang-fast.
   It tells the compiler to add code roughly equivalent to the bits discussed
   in ../afl-as.h.

 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <fstream>
#include <string>
#include <sstream>
#include <list>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Analysis/CFGPrinter.h"

#if defined(LLVM34)
#include "llvm/DebugInfo.h"
#else
#include "llvm/IR/DebugInfo.h"
#endif

#if defined(LLVM34) || defined(LLVM35) || defined(LLVM36)
#define LLVM_OLD_DEBUG_API
#endif

using namespace llvm;

cl::opt<std::string> TargetsFile(
    "targets",
    cl::desc("Input file containing the target lines of code."),
    cl::value_desc("targets"));

cl::opt<std::string> OutDirectory(
    "outdir",
    cl::desc("Output directory where Ftargets.txt, Fnames.txt, and BBnames.txt are generated."),
    cl::value_desc("outdir"));

namespace llvm {

template<>
struct DOTGraphTraits<Function*> : public DefaultDOTGraphTraits {
  DOTGraphTraits(bool isSimple=true) : DefaultDOTGraphTraits(isSimple) {}

  static std::string getGraphName(Function *F) {
    return "CFG for '" + F->getName().str() + "' function";
  }

  std::string getNodeLabel(BasicBlock *Node, Function *Graph) {
    if (!Node->getName().empty()) {
      return Node->getName().str();
    }

    std::string Str;
    raw_string_ostream OS(Str);

    Node->printAsOperand(OS, false);
    return OS.str();
  }
};

} // namespace llvm

namespace {

  class DirectPreprocess : public ModulePass {

    public:

      static char ID;
      DirectPreprocess() : ModulePass(ID) { }

      bool runOnModule(Module &M) override;

      // StringRef getPassName() const override {
      //  return "American Fuzzy Lop Instrumentation";
      // }

  };

}

char DirectPreprocess::ID = 0;

static void getDebugLoc(const Instruction *I, std::string &Filename,
                        unsigned &Line) {
#ifdef LLVM_OLD_DEBUG_API
  DebugLoc Loc = I->getDebugLoc();
  if (!Loc.isUnknown()) {
    DILocation cDILoc(Loc.getAsMDNode(M.getContext()));
    DILocation oDILoc = cDILoc.getOrigLocation();

    Line = oDILoc.getLineNumber();
    Filename = oDILoc.getFilename().str();

    if (filename.empty()) {
      Line = cDILoc.getLineNumber();
      Filename = cDILoc.getFilename().str();
    }
  }
#else
  if (DILocation *Loc = I->getDebugLoc()) {
    Line = Loc->getLine();
    Filename = Loc->getFilename().str();

    if (Filename.empty()) {
      DILocation *oDILoc = Loc->getInlinedAt();
      if (oDILoc) {
        Line = oDILoc->getLine();
        Filename = oDILoc->getFilename().str();
      }
    }
  }
#endif /* LLVM_OLD_DEBUG_API */
}

static bool isBlacklisted(const Function *F) {
  static const SmallVector<std::string, 8> Blacklist = {
    "asan.",
    "llvm.",
    "sancov.",
    "__ubsan_handle_",
    "free",
    "malloc",
    "calloc",
    "realloc"
  };

  for (auto const &BlacklistFunc : Blacklist) {
    if (F->getName().startswith(BlacklistFunc)) {
      return true;
    }
  }

  return false;
}

bool DirectPreprocess::runOnModule(Module &M) {

  if (TargetsFile.empty()) {
    errs() << "Cannot specify both '-targets'!\n";
    return false;
  }
  
  if (OutDirectory.empty()) {
    errs() << "Provide output directory '-outdir <directory>'\n";
    return false;
  }  

  std::list<std::string> targets;

  std::ifstream targetsfile(TargetsFile);
  std::string line;

  while (std::getline(targetsfile, line))
    targets.push_back(line);
  targetsfile.close();

  std::ofstream bbnames(OutDirectory + "/BBnames.txt", std::ofstream::out | std::ofstream::app);
  std::ofstream bbcalls(OutDirectory + "/BBcalls.txt", std::ofstream::out | std::ofstream::app);
  std::ofstream fnames(OutDirectory + "/Fnames.txt", std::ofstream::out | std::ofstream::app);
  std::ofstream ftargets(OutDirectory + "/Ftargets.txt", std::ofstream::out | std::ofstream::app);
  
  /* Create dot-files directory */
  std::string dotfiles(OutDirectory + "/dot-files");
  if (sys::fs::create_directory(dotfiles)) {
    errs() << "Could not create directory " << dotfiles.c_str() << ".\n";
  }
  
  Type *VoidTy = Type::getVoidTy(M.getContext());
  Type *Int32Ty = IntegerType::getInt32Ty(M.getContext());
  FunctionType *AssertFnTy = FunctionType::get(VoidTy, {Int32Ty}, false);
  FunctionCallee AssertFn = M.getOrInsertFunction("__afl_assert_failed", AssertFnTy);

  for (auto &F : M) {

    bool has_BBs = false;
    std::string funcName = F.getName().str();

    /* Black list of function names */
    if (isBlacklisted(&F)) {
      continue;
    }

    bool is_target = false;
    for (auto &BB : F) {

      std::string bb_name("");
      std::string filename;
      unsigned line;

      for (auto &I : BB) {
        getDebugLoc(&I, filename, line);

        /* Don't worry about external libs */
        static const std::string Xlibs("/usr/");
        if (filename.empty() || line == 0 || !filename.compare(0, Xlibs.size(), Xlibs))
          continue;

        if (bb_name.empty()) {

          std::size_t found = filename.find_last_of("/\\");
          if (found != std::string::npos)
            filename = filename.substr(found + 1);

          bb_name = filename + ":" + std::to_string(line);
        }

        if (!is_target) {
          for (auto &target : targets) {
            std::size_t found = target.find_last_of("/\\");
            if (found != std::string::npos)
              target = target.substr(found + 1);

            std::size_t pos = target.find_last_of(":");
            std::string target_file = target.substr(0, pos);
            unsigned int target_line = atoi(target.substr(pos + 1).c_str());

            if (!target_file.compare(filename) && target_line == line) {
              is_target = true;
              
              IRBuilder<> IRB(&I);
              // let target failed
              auto callInst = IRB.CreateCall(AssertFn, {ConstantInt::get(Int32Ty, 9487)});  
              callInst->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(M.getContext(), None));
              errs() << "Insert Assertion at " << filename << ":" << line << "\n";
              
            }

          }
        }

        if (auto *c = dyn_cast<CallInst>(&I)) {

          std::size_t found = filename.find_last_of("/\\");
          if (found != std::string::npos)
          filename = filename.substr(found + 1);  
          if (auto *CalledF = c->getCalledFunction()) {
            if (!isBlacklisted(CalledF))
              bbcalls << bb_name << "," << CalledF->getName().str() << "\n";
          }
        }
      }

      if (!bb_name.empty()) {

        BB.setName(bb_name + ":");
        if (!BB.hasName()) {
        std::string newname = bb_name + ":";
        Twine t(newname);
        SmallString<256> NameData;
        StringRef NameRef = t.toStringRef(NameData);
        MallocAllocator Allocator;
        BB.setValueName(ValueName::Create(NameRef, Allocator));
        }

        bbnames << BB.getName().str() << "\n";
        has_BBs = true;

      }
    }

    if (has_BBs) {
      /* Print CFG */
      std::string cfgFileName = dotfiles + "/cfg." + funcName + ".dot";
      std::error_code EC;
      raw_fd_ostream cfgFile(cfgFileName, EC, sys::fs::F_None);
      if (!EC) {
        WriteGraph(cfgFile, &F, true);
    }

      if (is_target) 
        ftargets << F.getName().str() << "\n";
      fnames << F.getName().str() << "\n";
    }
  
  }
  
  return true;

}


static void registerDirectPass(const PassManagerBuilder &,
                            legacy::PassManagerBase &PM) {

  PM.add(new DirectPreprocess());

}


static RegisterStandardPasses RegisterDirectPass(
    PassManagerBuilder::EP_OptimizerLast, registerDirectPass);

static RegisterStandardPasses RegisterDirectPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerDirectPass);
