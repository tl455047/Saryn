
#include <fstream>
#include "memlog.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/InstVisitor.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/SpecialCaseList.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/Local.h"

using namespace llvm;

static cl::opt<bool> ClHookInst(
    "memlog-hook-inst",
    cl::desc("Insert calls to hook critical memory instructions, calls."),
    cl::Hidden, cl::init(true));

// for hook API list
static cl::list<std::string> ClHookABIListFiles(
    "memlog-hook-abilist",
    cl::desc("File listing native ABI functions and how the pass hooks them."),
    cl::Hidden);

// for debug
static cl::opt<bool> ClDebug(
    "memlog-debug",
    cl::desc("Output debug message."),
    cl::Hidden, cl::init(false));

static StringRef GetGlobalTypeString(const GlobalValue &G) {
  // Types of GlobalVariables are always pointer types.
  Type *GType = G.getValueType();
  // For now we support excluding struct types only.
  if (StructType *SGType = dyn_cast<StructType>(GType)) {
    if (!SGType->isLiteral())
      return SGType->getName();
  }
  return "<unknown type>";
}

namespace {


class HookABIList {
  std::unique_ptr<SpecialCaseList> SCL;

 public:
  HookABIList() = default;

  void set(std::unique_ptr<SpecialCaseList> List) { SCL = std::move(List); }

  /// Returns whether either this function or its source file are listed in the
  /// given category.
  bool isIn(const Function &F, StringRef Category) const {
    return isIn(*F.getParent(), Category) ||
           SCL->inSection("hook", "fun", F.getName(), Category);
  }

  /// Returns whether this global alias is listed in the given category.
  ///
  /// If GA aliases a function, the alias's name is matched as a function name
  /// would be.  Similarly, aliases of globals are matched like globals.
  bool isIn(const GlobalAlias &GA, StringRef Category) const {
    if (isIn(*GA.getParent(), Category))
      return true;

    if (isa<FunctionType>(GA.getValueType()))
      return SCL->inSection("hook", "fun", GA.getName(), Category);

    return SCL->inSection("hook", "global", GA.getName(), Category) ||
           SCL->inSection("hook", "type", GetGlobalTypeString(GA),
                          Category);
  }

  /// Returns whether this module is listed in the given category.
  bool isIn(const Module &M, StringRef Category) const {
    return SCL->inSection("hook", "src", M.getModuleIdentifier(), Category);
  }
};

class MemlogPass: public ModulePass, public InstVisitor<MemlogPass> {

    HookABIList __HookABIList; 

    const DataLayout *TaintDataLayout;
    
    MDNode *SanitizeMDNode;
  
    Type *Int64PtrTy;
    Type *Int8Ty;
    Type *Int32Ty;
    Type *Int128Ty;
    Type *SizeTy;
    
    FunctionType *MemlogHookDebugFnTy;
    FunctionType *MemlogHook1FnTy;
    FunctionType *MemlogHook2FnTy;
    FunctionType *MemlogHook3FnTy;
    FunctionType *MemlogHook4FnTy;
    FunctionType *MemlogGEPHookFnTy;

    FunctionCallee MemlogHookDebugFn;
    FunctionCallee MemlogHook1Fn;
    FunctionCallee MemlogHook2Fn;
    FunctionCallee MemlogHook3Fn;
    FunctionCallee MemlogHook4Fn;
    FunctionCallee MemlogGEPHookFn;

    static unsigned HookID;
    static unsigned OrigHookID;
    static const std::string HookIDFileName;
    static const unsigned int MemlogMapW;

    public:
        static char ID;
        
        MemlogPass(): ModulePass(ID) { 
            
            __HookABIList.set(
            SpecialCaseList::createOrDie(ClHookABIListFiles, *vfs::getRealFileSystem()));

            std::fstream InFile;
            InFile.open(HookIDFileName, std::ios::in | std::ios::out);
            if (InFile.eof()) 
                HookID = 0;
            else 
                InFile >> HookID;
            InFile.close();
            
            OrigHookID = HookID;

        }

        StringRef getPassName() const override {
            return StringRef("MemlogPass");
        }

        bool doInitialization(Module &M) override;
        bool runOnModule(Module &M) override;
    
        bool shouldHook(const Function *F);
        HookType getHookType(const Function *F);
        void whichType(Type *T);
        // visitor override
        //void visitLoadInst(LoadInst &LI);
        //void visitStoreInst(StoreInst &SI);
        void visitCallBase(CallBase &CB);
        void visitInvokeInst(InvokeInst &I);
        void visitGetElementPtrInst(GetElementPtrInst &I);
     
        void visitMemSetInst(MemSetInst &I);
        void visitMemCpyInst(MemCpyInst &I);
        void visitMemCpyInlineInst(MemCpyInlineInst &I);
        void visitMemMoveInst(MemMoveInst &I);
        //void visitMemTransferInst(MemTransferInst &I);

        void visitAllocaInst(AllocaInst &I);
        void visitExtractElementInst(ExtractElementInst &I);
        void visitInsertElementInst(InsertElementInst &I);  
        void visitExtractValueInst(ExtractValueInst &I);
        void visitInsertValueInst(InsertValueInst &I);
        void visitShuffleVectorInst(ShuffleVectorInst &I);

        void visitAtomicCmpXchgInst(AtomicCmpXchgInst &I);
        void visitAtomicRMWInst(AtomicRMWInst &I);

};

}

unsigned MemlogPass::HookID = 0;
unsigned MemlogPass::OrigHookID = 0;
const std::string MemlogPass::HookIDFileName = "/tmp/.MemlogHookID.txt";
const unsigned int MemlogPass::MemlogMapW = 65536;

char MemlogPass::ID = 0;

bool MemlogPass::doInitialization(Module &M) {

    TaintDataLayout = &M.getDataLayout();
    SanitizeMDNode = MDNode::get(M.getContext(), None);
    // get type
    Int64PtrTy = Type::getInt64PtrTy(M.getContext());
    Int8Ty = Type::getInt8Ty(M.getContext());
    Int32Ty = Type::getInt32Ty(M.getContext());
    Int128Ty = Type::getInt128Ty(M.getContext());
    SizeTy = Type::getInt64Ty(M.getContext());
    Type *VoidTy = Type::getVoidTy(M.getContext());

    MemlogHookDebugFnTy = FunctionType::get(VoidTy, {Int32Ty}, false);
    MemlogHook1FnTy = FunctionType::get(VoidTy, {Int32Ty, Int64PtrTy, SizeTy}, false);
    MemlogHook2FnTy = FunctionType::get(VoidTy, {Int32Ty, Int64PtrTy, Int64PtrTy, SizeTy}, false);
    MemlogHook3FnTy = FunctionType::get(VoidTy, {Int32Ty, SizeTy}, false);
    MemlogHook4FnTy = FunctionType::get(VoidTy, {Int32Ty, Int64PtrTy}, false);
    MemlogGEPHookFnTy = FunctionType::get(VoidTy, {Int32Ty, Int64PtrTy, Int32Ty}, true);
    
    return true;
}

bool MemlogPass::runOnModule(Module &M) {

    
    /**
     * Seems that object FunctionCallee will be released after doInitialization,
     * insert the function in runOnModule may be the better choice.
     * 
     */
    MemlogHookDebugFn = M.getOrInsertFunction("__memlog_hook_debug", MemlogHookDebugFnTy);
    MemlogHook1Fn = M.getOrInsertFunction("__memlog_hook1", MemlogHook1FnTy);
    MemlogHook2Fn = M.getOrInsertFunction("__memlog_hook2", MemlogHook2FnTy);
    MemlogHook3Fn = M.getOrInsertFunction("__memlog_hook3", MemlogHook3FnTy);
    MemlogHook4Fn = M.getOrInsertFunction("__memlog_hook4", MemlogHook4FnTy);
    MemlogGEPHookFn = M.getOrInsertFunction("__memlog_get_element_ptr_hook", MemlogGEPHookFnTy);
    
    /**
     * Replace argc with global variable.
     */
    /*GlobalVariable *Pipe_argc =
      new GlobalVariable(M, Type::getInt32Ty(M.getContext()), false,
                         GlobalValue::ExternalLinkage, ConstantInt::get(Type::getInt32Ty(M.getContext()), 10000), "__pipe_argc");
    for (Function &F : M) {
    
        if(F.getName() == "main") {
            errs() << F.getName()<<"\n"; 
            auto &BB = F.getEntryBlock();
            BasicBlock::iterator IP = BB.getFirstInsertionPt();
            IRBuilder<> IRB(&(*IP));
            Value *Argc = IRB.CreateLoad(Type::getInt32Ty(M.getContext()), Pipe_argc);
            F.getArg(0)->replaceAllUsesWith(Argc);
        }
        
    }*/

    for (Function &F : M) {
    
        if (!F.isIntrinsic() && 
                &F != MemlogHookDebugFn.getCallee()->stripPointerCasts() &&
                &F != MemlogHook1Fn.getCallee()->stripPointerCasts() &&
                &F != MemlogHook2Fn.getCallee()->stripPointerCasts() &&
                &F != MemlogHook3Fn.getCallee()->stripPointerCasts() &&
                &F != MemlogHook4Fn.getCallee()->stripPointerCasts() &&
                &F != MemlogGEPHookFn.getCallee()->stripPointerCasts()) {
            
            if (F.isDeclaration())
                continue;
            
            visit(F);
        
        }
        
    }
    
    errs() << "\x1b[0;36mMemlog Instrumentation\x1b[0m start ID: \x1b[0;36m" << HookID << "\x1b[0m\n";
    errs() << "[+] Instrumented \x1b[0;36m"<< HookID - OrigHookID << "\x1b[0m locations\n";
    std::fstream OutFile;
    OutFile.open(HookIDFileName, std::ios::out | std::ios::trunc);
    OutFile << HookID % MemlogMapW;
    OutFile.close();

    return true;
}

bool MemlogPass::shouldHook(const Function *F) {
    return __HookABIList.isIn(*F, "hook");
}

HookType MemlogPass::getHookType(const Function *F) {

    if (__HookABIList.isIn(*F, "hook1")) 
        return HT_HOOK1;
    else if (__HookABIList.isIn(*F, "hook2"))
        return HT_HOOK2;
    else if (__HookABIList.isIn(*F, "hook3"))
        return HT_HOOK3;
    else if (__HookABIList.isIn(*F, "hook4"))
        return HT_HOOK4;
    else if (__HookABIList.isIn(*F, "gephook"))
        return HT_GEP_HOOK;
    return HT_UNKNOWN;

}

void MemlogPass::whichType(Type *T) {

    if (T->isFloatingPointTy())
        errs() << "FloatingPoint\n";
    else if (T->isIntegerTy())
        errs() << "Integer\n";
    else if (T->isPointerTy())
        errs() << "Pointer\n";
    else if (T->isStructTy())
        errs() << "Struct\n";
    else if (T->isArrayTy()) 
        errs() << "Array\n";
    else if (T->isDoubleTy())
        errs() << "Double\n";
    else if (T->isVectorTy())
        errs() << "Vector\n";

}

void MemlogPass::visitCallBase(CallBase &CB) {
    auto F = CB.getCalledFunction();
    
    if (ClHookInst && F && !F->isIntrinsic() && shouldHook(F)) {
        
        if (ClDebug)
          errs() << CB.getFunction()->getName() << " hook "<< F->getName() << " " << HookID << "\n"; 
        
        IRBuilder <> IRB(&CB);
        Value *Arg;
        bool NonConstant;
        std::vector<Value *> ArgArray;
        ArgArray.push_back(ConstantInt::get(Int32Ty, 0));
        
        NonConstant = 0;
        for (User::op_iterator it = CB.arg_begin(); it != CB.arg_end(); it++) {
            Arg = *it;
            
            if (!isa<ConstantInt>(Arg)) 
                NonConstant = 1;
            
            if(Arg->getType()->isIntegerTy() && Arg->getType() != SizeTy)    
                Arg = IRB.CreateZExt(Arg, SizeTy);   

            ArgArray.push_back(Arg);

        }

        if (NonConstant) {
            // We only instrument when there is at least one non constant argument.
            ArgArray[0] = ConstantInt::get(Int32Ty, HookID++);
            switch(getHookType(F)) {
                
                case HT_HOOK1:
                    IRB.CreateCall(MemlogHook1Fn, ArgArray)->setMetadata(CB.getModule()->getMDKindID("nosanitize"), SanitizeMDNode);
                    break;
                case HT_HOOK2:
                    IRB.CreateCall(MemlogHook2Fn, ArgArray)->setMetadata(CB.getModule()->getMDKindID("nosanitize"), SanitizeMDNode);
                    break;
                case HT_HOOK3:
                    IRB.CreateCall(MemlogHook3Fn, ArgArray)->setMetadata(CB.getModule()->getMDKindID("nosanitize"), SanitizeMDNode);
                    break;
                case HT_HOOK4:
                    IRB.CreateCall(MemlogHook4Fn, ArgArray)->setMetadata(CB.getModule()->getMDKindID("nosanitize"), SanitizeMDNode);
                    break;
                default:
                    break;

            }
        
        }
        
    }

}

void MemlogPass::visitInvokeInst(InvokeInst &I) {
   
}

void MemlogPass::visitGetElementPtrInst(GetElementPtrInst &I) {
    
    if (ClHookInst) {

        if (ClDebug) 
            errs() << I.getFunction()->getName() << " hook GetElementPtr id: " << HookID << "\n";
        
        IRBuilder <> IRB(&I);
        Value *Arg;
        std::vector<Value *> ArgArray;  
        ArgArray.push_back(ConstantInt::get(Int32Ty, 0));
        ArgArray.push_back(I.getPointerOperand());
        // set num of idx to 0
        ArgArray.push_back(ConstantInt::get(Int32Ty, 0));
        // get non-constant idx and calculate how many such idx we have
        for (User::op_iterator it = I.idx_begin(); it != I.idx_end(); it++) {
            Arg = *it;
            if (!isa<ConstantInt>(Arg) && Arg->getType()->isIntegerTy()) {

                if (Arg->getType() != SizeTy)
                    Arg = IRB.CreateZExt(Arg, SizeTy);   

                ArgArray.push_back(Arg); 

            }
        }
        
        if (ArgArray.size() > 3) {
            // We only instrument when there is at least one non constant idx.
            ArgArray[0] = ConstantInt::get(Int32Ty, HookID++);
            ArgArray[2] = ConstantInt::get(Int32Ty, ArgArray.size() - 3);
            IRB.CreateCall(MemlogGEPHookFn, ArgArray)->setMetadata(I.getModule()->getMDKindID("nosanitize"), SanitizeMDNode);
        
        }
        
    }

}

void MemlogPass::visitMemSetInst(MemSetInst &I) {
   
    if (ClHookInst) {
        
        if (ClDebug)
            errs() << I.getFunction()->getName() << " hook MemSetInst id: " << HookID << "\n";

        IRBuilder <> IRB(&I);
        Value *Arg;
        bool NonConstant;
        std::vector<Value *> ArgArray;
        ArgArray.push_back(ConstantInt::get(Int32Ty, 0));
        
        NonConstant = 0;
        for (User::op_iterator it = I.arg_begin(); it != I.arg_end(); it++) {
            Arg = *it;
            
            if (!isa<ConstantInt>(Arg)) 
                NonConstant = 1;
            
            if(Arg->getType()->isIntegerTy() && Arg->getType() != SizeTy)    
                Arg = IRB.CreateZExt(Arg, SizeTy);   

            ArgArray.push_back(Arg);

        }

        if (NonConstant) {
            // We only instrument when there is at least one non constant argument.
            ArgArray[0] = ConstantInt::get(Int32Ty, HookID++);
            IRB.CreateCall(MemlogHook1Fn, ArgArray)->setMetadata(I.getModule()->getMDKindID("nosanitize"), SanitizeMDNode);
        
        }

    }

}

void MemlogPass::visitMemCpyInst(MemCpyInst &I) {
    
    if (ClHookInst) {
        
        if (ClDebug)
            errs() << I.getFunction()->getName() << " hook MemCpyInst id: " << HookID << "\n";

        IRBuilder <> IRB(&I);
        Value *Arg;
        bool NonConstant;
        std::vector<Value *> ArgArray;
        ArgArray.push_back(ConstantInt::get(Int32Ty, 0));
        
        NonConstant = 0;
        for (User::op_iterator it = I.arg_begin(); it != I.arg_end(); it++) {
            Arg = *it;
            
            if (!isa<ConstantInt>(Arg)) 
                NonConstant = 1;
            
            if(Arg->getType()->isIntegerTy() && Arg->getType() != SizeTy)    
                Arg = IRB.CreateZExt(Arg, SizeTy);   

            ArgArray.push_back(Arg);

        }

        if (NonConstant) {
            // We only instrument when there is at least one non constant argument.
            ArgArray[0] = ConstantInt::get(Int32Ty, HookID++);
            IRB.CreateCall(MemlogHook2Fn, ArgArray)->setMetadata(I.getModule()->getMDKindID("nosanitize"), SanitizeMDNode);
        
        }

    }

}

void MemlogPass::visitMemCpyInlineInst(MemCpyInlineInst &I) {

    if (ClHookInst) {
        
        if (ClDebug)
            errs() << I.getFunction()->getName() << " hook MemCpyInlineInst id: " << HookID << "\n";
        
        IRBuilder <> IRB(&I);
        Value *Arg;
        bool NonConstant;
        std::vector<Value *> ArgArray;
        ArgArray.push_back(ConstantInt::get(Int32Ty, 0));
        
        NonConstant = 0;
        for (User::op_iterator it = I.arg_begin(); it != I.arg_end(); it++) {
            Arg = *it;
            
            if (!isa<ConstantInt>(Arg)) 
                NonConstant = 1;
            
            if(Arg->getType()->isIntegerTy() && Arg->getType() != SizeTy)    
                Arg = IRB.CreateZExt(Arg, SizeTy);   

            ArgArray.push_back(Arg);

        }

        if (NonConstant) {
            // We only instrument when there is at least one non constant argument.
            ArgArray[0] = ConstantInt::get(Int32Ty, HookID++);
            IRB.CreateCall(MemlogHook2Fn, ArgArray)->setMetadata(I.getModule()->getMDKindID("nosanitize"), SanitizeMDNode);
        
        }

    }

}

void MemlogPass::visitMemMoveInst(MemMoveInst &I) {
    
    if (ClHookInst) {
        
        if (ClDebug)
            errs() << I.getFunction()->getName() << " hook MemMoveInst id: " << HookID << "\n";
        
        IRBuilder <> IRB(&I);
        Value *Arg;
        bool NonConstant;
        std::vector<Value *> ArgArray;
        ArgArray.push_back(ConstantInt::get(Int32Ty, 0));
        
        NonConstant = 0;
        for (User::op_iterator it = I.arg_begin(); it != I.arg_end(); it++) {
            Arg = *it;
            
            if (!isa<ConstantInt>(Arg)) 
                NonConstant = 1;
            
            if(Arg->getType()->isIntegerTy() && Arg->getType() != SizeTy)    
                Arg = IRB.CreateZExt(Arg, SizeTy);   

            ArgArray.push_back(Arg);

        }

        if (NonConstant) {
            // We only instrument when there is at least one non constant argument.
            ArgArray[0] = ConstantInt::get(Int32Ty, HookID++);
            IRB.CreateCall(MemlogHook2Fn, ArgArray)->setMetadata(I.getModule()->getMDKindID("nosanitize"), SanitizeMDNode);
        
        }

    }

}

void MemlogPass::visitAllocaInst(AllocaInst &I) {
    
}
/**
 * According to llvm manupage, extractValue/insertValue are used for register structure(?),
 * extractElement/insterElement are used for vector operations.
 * I don't know how to invode these instructions yet.
 * Since these instructions also contains memory read/write operations, better to cover it
 * in the future. 
 */
void MemlogPass::visitExtractElementInst(ExtractElementInst &I) {
   
}

void MemlogPass::visitInsertElementInst(InsertElementInst &I) {

}

void MemlogPass::visitExtractValueInst(ExtractValueInst &I) {
  
}

void MemlogPass::visitInsertValueInst(InsertValueInst &I) {

}

void MemlogPass::visitShuffleVectorInst(ShuffleVectorInst &I) {
 
}

void MemlogPass::visitAtomicCmpXchgInst(AtomicCmpXchgInst &I) {
   
}

void MemlogPass::visitAtomicRMWInst(AtomicRMWInst &I) {
    
}

static RegisterPass<MemlogPass> X("Memloghook", "MemlogPass", false, false);

static void registerMemlogPass(const PassManagerBuilder &,
                                 legacy::PassManagerBase &PM) {

  PM.add(new MemlogPass());

}

static RegisterStandardPasses
    RegisterMemlogPass(PassManagerBuilder::EP_OptimizerLast,
                   registerMemlogPass);

static RegisterStandardPasses
    RegisterMemlogPass0(PassManagerBuilder::EP_EnabledOnOptLevel0,
                   registerMemlogPass);

#if LLVM_VERSION_MAJOR >= 11
static RegisterStandardPasses RegisterMemlogPassLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast,
    registerMemlogPass);
#endif
