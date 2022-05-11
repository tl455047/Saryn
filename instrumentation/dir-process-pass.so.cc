
#include "llvm/ADT/Statistic.h"
#include "llvm/Analysis/CFGPrinter.h"
#include "llvm/Analysis/PostDominators.h"
#include "llvm/IR/DebugInfoMetadata.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/SpecialCaseList.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Pass.h"

#include <algorithm>
#include <fstream>
#include <map>
#include <queue>
#include <unordered_set>
#include <utility>
#include <vector>

using namespace llvm;

static cl::opt<std::string> OptionTargetsFile(
    "targets",
    cl::desc("Input file containing the target lines of code."),
    cl::value_desc("targets"));

static cl::opt<std::string> OptionOutDirectory(
    "outdir",
    cl::desc("Output directory where Ftargets.txt, BBcalls.txt are generated."),
    cl::value_desc("outdir"));

static cl::opt<std::string> OptionCallSite(
    "callsite",
    cl::desc("Input file containing function call site."),
    cl::value_desc("callsite"));

static cl::opt<bool> OptionPreprocess(
    "preprocess",
    cl::desc("preprocess stage, collecting all function call site."),
    cl::value_desc("preprocess"));

static cl::opt<std::string> OptionDistanceFile(
    "distance",
    cl::desc("Distance file containing the distance of each basic block to the provided targets."),
    cl::value_desc("filename")
);

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

class DirProcessPass : public ModulePass {

public:
  static char ID;
  DirProcessPass() : ModulePass(ID) { }
  
  bool doInitialization(Module &M) override;
  bool runOnModule(Module &M) override;

private:

  void getDebugLoc(const Instruction *I, std::string &Filename,
                        unsigned &Line);

  void findReachableBBFromTarget(BasicBlock *BB, std::unordered_set<BasicBlock *> &reachable, 
                                                 std::queue<BasicBlock *> &worklist);

  void findReachableBBFromTargetDepth(BasicBlock *BB, std::unordered_set<BasicBlock *> &reachable,
                                      std::map<std::string, int> distance, LLVMContext *C);

  void setDistanceMetaData(Instruction *I, std::string BBName, int distance, LLVMContext *C);

  LLVMContext *C;

};

}  // namespace

char DirProcessPass::ID = 0;

bool DirProcessPass::doInitialization(Module &M) {

  return true;

}

void DirProcessPass::getDebugLoc(const Instruction *I, std::string &Filename,
                        unsigned &Line) {

  if (auto Loc = I->getDebugLoc()) {
    
    Line = Loc.getLine();
    auto *Scope = cast<llvm::DIScope>(Loc.getScope());
    Filename = Scope->getFilename().str();
    
    if (Filename.empty()) {
    
      auto oDILoc = Loc.getInlinedAt();
      if (oDILoc) {

        Line = oDILoc->getLine();
        Filename = oDILoc->getFilename().str();
      
      }
    
    }

  }

}

void DirProcessPass::setDistanceMetaData(Instruction *I, std::string BBName, int distance, LLVMContext *C) {
  
  /*MDNode *N = nullptr;
  if (!(N = I->getMetadata("cmp.distance"))) {
  
    if (distance < 0)
      distance = 1;

    MDNode* N = MDNode::get(*C, ConstantAsMetadata::get(ConstantInt::get(*C, llvm::APInt(32, distance, true))));
    
    I->setMetadata("cmp.distance", N);
  
  }*/

  std::vector<Metadata *> MetadataArray;
  MetadataArray.clear();
  MDNode *N;
  
  if ((N = I->getMetadata("cmp.distance"))) {
    for (auto it = N->op_begin(); it != N->op_end(); it++) {
      MetadataArray.push_back(it->get());
    }
  }
  
  if (distance < 0)
    distance  = 100 * 65536;

  //errs() << BBName << " " << distance << "\n";
  
  DIEnumerator *DIEn = DIEnumerator::get(*C, APInt(32, distance, true), true, 
    MDString::get(*C, BBName));

  MetadataArray.push_back(DIEn);
  N = MDNode::get(*C, MetadataArray);
  I->setMetadata("cmp.distance", N);

}

void DirProcessPass::findReachableBBFromTargetDepth(BasicBlock *BB, std::unordered_set<BasicBlock *> &reachable,
                                                    std::map<std::string, int> distance, LLVMContext *C) {

  
  for (auto pred : predecessors(BB)) {
  
    if (reachable.count(pred) == 0) {
      
      reachable.insert(pred);

      std::string BBName("");
      std::string filename;
      unsigned line;
      int dist = -1;

      for (auto &I : *pred) {
        
        getDebugLoc(&I, filename, line);

        std::size_t found = filename.find_last_of("/\\");
        if (found != std::string::npos)
        filename = filename.substr(found + 1);

        BBName = filename + ":" + std::to_string(line);

        dist = -1;
        
        /*auto it = distance.find(BBName);
        if (it != distance.end()) 
          dist = it->second;*/

        auto it = std::find_if(distance.begin(), distance.end(), 
          [&filename, &line](const std::pair<std::string, int> &e) -> bool
          {

            std::size_t found = e.first.find_last_of(":");

            if (e.first.substr(0, found).compare(filename) != 0)
              return false;

            int l = atoi(e.first.substr(found + 1).c_str()); 
            
            // if current line not exist distance, we find the next lines distance for it
            if (line == l || (line < l)) 
              return true;
            else
              return false; 

          });

        if (it != distance.end()) {
          dist = it->second;
        }

        CmpInst *selectcmpInst = nullptr; 
        if ((selectcmpInst = dyn_cast<CmpInst>(&I))) {
          
          // set metadata to tell cmplog for special handling for these cmp inst                   
          setDistanceMetaData(selectcmpInst, BBName, dist, C);

        }

      }

      /*for (auto &I : *pred) {
        
        CmpInst *selectcmpInst = nullptr; 
        if ((selectcmpInst = dyn_cast<CmpInst>(&I))) {
          
          errs () << BBName << " " << dist << "\n";

          // set metadata to tell cmplog for special handling for these cmp inst                   
          setDistanceMetaData(selectcmpInst, dist, C);

        }

      }*/

      findReachableBBFromTargetDepth(pred, reachable, distance, C);

    }

  }
    
}

void DirProcessPass::findReachableBBFromTarget(BasicBlock *BB, std::unordered_set<BasicBlock *> &reachable, 
                                         std::queue<BasicBlock *> &worklist) {
  
  worklist.push(BB);

  while (!worklist.empty()) {

    BasicBlock *front = worklist.front();
    worklist.pop();
    
    // we traverse all predecessors to find all reachable block from target
    for (auto pred : predecessors(front)) {
  
      if (reachable.count(pred) == 0) {
        /// We need the check here to ensure that we don't run 
        /// infinitely if the CFG has a loop in it
        /// i.e. the BB reaches itself directly or indirectly

        worklist.push(pred);
        reachable.insert(pred);

        for (auto &I : *pred) {

          CmpInst *selectcmpInst = nullptr; 
          if ((selectcmpInst = dyn_cast<CmpInst>(&I))) {
            // set metadata to tell cmplog for special handling for these cmp inst                   
          }

        }

      }

    }

    // check is entry block,  if is we try to find calle block, and
    // continue traverse all predecessors
    /*if (front == &front->getParent()->getEntryBlock()) {

      for (auto it = callInsts.begin(); it != callInsts.end(); it++) {

        if ((*it)->getCalledFunction()->getName() == front->getParent()->getName()) {

          auto calleeBB = (*it)->getParent();
          if (reachable.count(calleeBB) == 0) {
         
            worklist.push(calleeBB);
            reachable.insert(calleeBB);

            for (auto &I : *calleeBB) {

              CmpInst *selectcmpInst = nullptr; 
              if ((selectcmpInst = dyn_cast<CmpInst>(&I))) {
              
                // set metadata to tell cmplog for special handling for these cmp inst                   
              
              }
            
            }
          
          }

        }

      }

    }*/

  }

}

static bool isBlacklisted(StringRef funName) {
  
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
    if (funName.startswith(BlacklistFunc)) {
      return true;
    }
  }

  return false;

}

bool DirProcessPass::runOnModule(Module &M) {
  
  std::list<std::string> targets;

  C = &(M.getContext());

  if (OptionPreprocess) {

    // preprocess mode
    if (OptionTargetsFile.empty()) {
      
      errs() << "Provide target file '-target=<file>'\n";
      return false;
    
    }
    
    // obtain target file and line
    std::ifstream targetsFile(OptionTargetsFile);
    std::string line;
    while (std::getline(targetsFile, line))
      targets.push_back(line);
    targetsFile.close();
    
    // set output file
    std::ofstream FTargets(OptionOutDirectory + "/Ftargets.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream FNames(OptionOutDirectory + "/Fnames.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream BBNames(OptionOutDirectory + "/BBnames.txt", std::ofstream::out | std::ofstream::app);
    std::ofstream BBCalls(OptionOutDirectory + "/BBcalls.txt", std::ofstream::out | std::ofstream::app);
    
    //
    std::ofstream BBCallsF(OptionOutDirectory + "/BBcallsF.txt", std::ofstream::out | std::ofstream::app);

     /* Create dot-files directory */
    std::string dotfiles(OptionOutDirectory + "/dot-files");
    if (sys::fs::create_directory(dotfiles)) {
      errs() << "Could not create directory " << dotfiles.c_str() << ".\n";  
    }

    for (auto &F : M) {    
      
      bool hasBBs = false;
      std::string funcName = F.getName().str();

      if (isBlacklisted(F.getName()))
        continue;

      bool findTarget = false;  
      for (auto &BB : F) {
        
        std::string BBName("");
        std::string filename;
        unsigned line;
          
        for (auto &I : BB) {
          
          // get source code file and line info
          getDebugLoc(&I, filename, line);

          /* Don't worry about external libs */
          static const std::string Xlibs("/usr/");
          if (filename.empty() || line == 0 || !filename.compare(0, Xlibs.size(), Xlibs))
            continue;
            
          if (BBName.empty()) {

            std::size_t found = filename.find_last_of("/\\");
            if (found != std::string::npos)
              filename = filename.substr(found + 1);

            BBName = filename + ":" + std::to_string(line);

          }
 
          if (!findTarget) {
            
            // find target location
            for (auto &target : targets) {
              
              std::size_t found = target.find_last_of("/\\");
              if (found != std::string::npos)
                target = target.substr(found + 1);

              std::size_t pos = target.find_last_of(":");
              std::string targetFile = target.substr(0, pos);
              unsigned int targetLine = atoi(target.substr(pos + 1).c_str());

              if (!targetFile.compare(filename) && targetLine == line) {

                findTarget = true;

              }

            }
            
          }

          // find all callee location
          CallInst *selectcallInst = nullptr;
          if ((selectcallInst = dyn_cast<CallInst>(&I))) {
            
            // callInsts.push_back(selectcallInst);
            auto callF = selectcallInst->getCalledFunction();

            if (callF && !isBlacklisted(callF->getName())) {

              BBCallsF << F.getName().str() << ":" << callF->getName().str() << "\n";
              BBCalls << BBName << "," << callF->getName().str() << "\n";
            
            }

          }

        }
        
        if (!BBName.empty()) {

          BB.setName(BBName + ":");
          if (!BB.hasName()) {
            std::string newname = BBName + ":";
            Twine t(newname);
            SmallString<256> NameData;
            StringRef NameRef = t.toStringRef(NameData);
            MallocAllocator Allocator;
            BB.setValueName(ValueName::Create(NameRef, Allocator));
          }

          BBNames << BB.getName().str() << "\n";
          hasBBs = true;

        }

      }

      if (hasBBs) {

        /* Print CFG */
        std::string cfgFileName = dotfiles + "/cfg." + funcName + ".dot";
        std::error_code EC;
        raw_fd_ostream cfgFile(cfgFileName, EC, sys::fs::F_None);
        if (!EC) {
          WriteGraph(cfgFile, &F, true);
        }

        if (findTarget) {
          
          FTargets << F.getName().str() << "\n";
        
        }

        FNames << F.getName().str() << "\n";
      
      }

    }

    FTargets.close();
    FNames.close();
    BBNames.close();
    BBCalls.close();
    BBCallsF.close();

  }
  else {

    // process mode
    if (OptionCallSite.empty()) {

      errs() << "Provide call site file '-callsite=<file>'\n";
      return false;
    
    }

    if (OptionTargetsFile.empty()) {
      
      errs() << "Provide target file '-target=<file>'\n";
      return false;
    
    }

    if (OptionDistanceFile.empty()) {

      errs() << "Provide distance file '-distance=<file>'\n";
      return false;
    
    }
    
    std::unordered_set<BasicBlock *> reachable;
    std::queue<BasicBlock *> worklist;
  
    std::vector<std::string> callees;
    std::map<std::string, std::vector<std::string>> callSites;
    std::string callSite;

    std::map<std::string, int> distance;
   
    std::ifstream callSiteFile(OptionCallSite);
    while (callSiteFile >> callSite) {

      std::size_t pos = callSite.find_last_of(":");
      std::string caller = callSite.substr(0, pos);
      std::string callee = callSite.substr(pos + 1);

      callees.push_back(callee);
      
      auto it = callSites.find(caller);
      if (it == callSites.end()) {

        std::vector<std::string> v({callee});
        callSites.emplace(std::make_pair(caller, v));
        
      }
      else {

        it->second.push_back(callee);
      
      }

    }
    callSiteFile.close();

    // obtain target file and line
    std::ifstream targetsFile(OptionTargetsFile);
    std::string line;
    while (std::getline(targetsFile, line))
      targets.push_back(line);
    targetsFile.close();

    //obtain distance
    std::ifstream distanceFile(OptionDistanceFile);
    if (distanceFile.is_open()) {

      std::string line;
      while (getline(distanceFile, line)) {

        std::size_t pos = line.find(",");
        std::string BBName = line.substr(0, pos);
        int BBDis = (int) (100.0 * atof(line.substr(pos + 1, line.length()).c_str()));

        distance.emplace(BBName, BBDis);
       
      }

      distanceFile.close();

    } else {

      errs() << "Unable to find " << OptionDistanceFile.c_str() << ".\n";
      return false;
    
    }

    /*errs() << "load distance\n";
    for (auto it = distance.begin(); it != distance.end(); it++) {
      errs() << it->first << " " << it->second << "\n";
    }
    errs() << "load distance finished\n";*/

    for (auto &F : M) {    

      if (isBlacklisted(F.getName()))
        continue;

      // skip function not in call site
      if (callSites.find(F.getName().str()) == callSites.end() &&
          std::find(callees.begin(), callees.end(), F.getName().str()) == callees.end())
        continue;

      bool findTarget = false;
      unsigned reachableBB = reachable.size();
    
      for (auto &BB : F) {
        
        std::string filename;
        unsigned line;
          
        for (auto &I : BB) {
          
          // get source code file and line info
          getDebugLoc(&I, filename, line);

          if (!findTarget) {
            
            // find target location
            for (auto &target : targets) {
              
              std::size_t found = target.find_last_of("/\\");
              if (found != std::string::npos)
                target = target.substr(found + 1);

              std::size_t pos = target.find_last_of(":");
              std::string targetFile = target.substr(0, pos);
              unsigned int targetLine = atoi(target.substr(pos + 1).c_str());

              if (!targetFile.compare(filename) && targetLine == line) {

                findReachableBBFromTargetDepth(&BB, reachable, distance, C);  
                findTarget = true;

              }

            }
            
          }

          // find all callee location
          CallInst *selectcallInst = nullptr;
          if ((selectcallInst = dyn_cast<CallInst>(&I))) {
            
            // if is in call site caller
            auto it = callSites.find(F.getName().str());
            auto callF = selectcallInst->getCalledFunction();
            if (callF && it != callSites.end() && std::find(it->second.begin(), it->second.end(), 
              callF->getName().str()) != it->second.end()) {
              
              findReachableBBFromTargetDepth(&BB, reachable, distance, C);
                
            }
          
          }

        }

      }

      errs() << "reachable blocks in function " << F.getName() << ": " << reachable.size() - reachableBB << "\n";
    
    }

  }

  return true;

}

static void registerDirProcessPass(const PassManagerBuilder &,
                                           legacy::PassManagerBase &PM) {

  PM.add(new DirProcessPass());

}

static RegisterStandardPasses RegisterDirProcessPass(
    PassManagerBuilder::EP_OptimizerLast, registerDirProcessPass);

static RegisterStandardPasses RegisterDirProcessPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerDirProcessPass);

#if LLVM_VERSION_MAJOR >= 11
static RegisterStandardPasses RegisterCmpLogInstructionsPassLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast,
    registerDirProcessPass);
#endif