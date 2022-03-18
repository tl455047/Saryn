/*
   american fuzzy lop++ - LLVM CmpLog instrumentation
   --------------------------------------------------

   Written by Andrea Fioraldi <andreafioraldi@gmail.com>

   Copyright 2015, 2016 Google Inc. All rights reserved.
   Copyright 2019-2020 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <iostream>
#include <list>
#include <string>
#include <fstream>
#include <sys/time.h>

#include "llvm/Config/llvm-config.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Pass.h"
#include "llvm/Analysis/ValueTracking.h"

#if LLVM_VERSION_MAJOR >= 4 || \
    (LLVM_VERSION_MAJOR == 3 && LLVM_VERSION_MINOR > 4)
  #include "llvm/IR/Verifier.h"
  #include "llvm/IR/DebugInfo.h"
  #include "llvm/Support/raw_ostream.h"
#else
  #include "llvm/Analysis/Verifier.h"
  #include "llvm/DebugInfo.h"
  #define nullptr 0
#endif

#include <set>
#include "afl-llvm-common.h"

using namespace llvm;

namespace {

class CmpLogInstructions : public ModulePass {

 public:
  static char ID;
  CmpLogInstructions() : ModulePass(ID) {

    initInstrumentList();

  }

  bool runOnModule(Module &M) override;

#if LLVM_VERSION_MAJOR >= 4
  StringRef getPassName() const override {

#else
  const char *getPassName() const override {

#endif
    return "cmplog instructions";

  }

 private:
  bool hookInstrs(Module &M);
  void instrumentCurLoc(Module &M, IRBuilder <> &IRB, Instruction *cmpInst);
  void instrumentDistance(Module &M, IRBuilder <> &IRB, Instruction *cmpInst);
  void instrumentMetadata(Module &M, IRBuilder<> &IRB, Instruction *cmpInst);

  Type *       VoidTy; 
  IntegerType *Int8Ty;
  IntegerType *Int16Ty; 
  IntegerType *Int32Ty;
  IntegerType *Int64Ty;
  IntegerType *Int128Ty;
  Type *      IntptrTy;
  Type *      Int32PtrTy;
  Type *      Int64PtrTy;

  GlobalVariable *AFLLocPtr;
  GlobalVariable *AFLDisPtr;
  GlobalVariable *AFLNumOfSucc;

};

}  // namespace

char CmpLogInstructions::ID = 0;

template <class Iterator>
Iterator Unique(Iterator first, Iterator last) {

  while (first != last) {

    Iterator next(first);
    last = std::remove(++next, last, *first);
    first = next;

  }

  return last;

}

bool CmpLogInstructions::hookInstrs(Module &M) {

  std::vector<Instruction *> icomps;
  LLVMContext &              C = M.getContext();

  VoidTy = Type::getVoidTy(C);
  Int8Ty = IntegerType::getInt8Ty(C);
  Int16Ty = IntegerType::getInt16Ty(C);
  Int32Ty = IntegerType::getInt32Ty(C);
  Int64Ty = IntegerType::getInt64Ty(C);
  Int128Ty = IntegerType::getInt128Ty(C);

  IntptrTy = Type::getIntNTy(C, M.getDataLayout().getPointerSizeInBits());
  IRBuilder<> _IRB(C);
  Int32PtrTy = PointerType::getUnqual(_IRB.getInt32Ty());
  Int64PtrTy = PointerType::getUnqual(_IRB.getInt64Ty());

#if LLVM_VERSION_MAJOR >= 9
  FunctionCallee
#else
  Constant *
#endif
      c1 = M.getOrInsertFunction("__cmplog_ins_hook1", VoidTy, Int8Ty, Int8Ty,
                                 Int8Ty
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR >= 9
  FunctionCallee cmplogHookIns1 = c1;
#else
  Function *cmplogHookIns1 = cast<Function>(c1);
#endif

#if LLVM_VERSION_MAJOR >= 9
  FunctionCallee
#else
  Constant *
#endif
      c2 = M.getOrInsertFunction("__cmplog_ins_hook2", VoidTy, Int16Ty, Int16Ty,
                                 Int8Ty
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR >= 9
  FunctionCallee cmplogHookIns2 = c2;
#else
  Function *cmplogHookIns2 = cast<Function>(c2);
#endif

#if LLVM_VERSION_MAJOR >= 9
  FunctionCallee
#else
  Constant *
#endif
      c4 = M.getOrInsertFunction("__cmplog_ins_hook4", VoidTy, Int32Ty, Int32Ty,
                                 Int8Ty
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR >= 9
  FunctionCallee cmplogHookIns4 = c4;
#else
  Function *cmplogHookIns4 = cast<Function>(c4);
#endif

#if LLVM_VERSION_MAJOR >= 9
  FunctionCallee
#else
  Constant *
#endif
      c8 = M.getOrInsertFunction("__cmplog_ins_hook8", VoidTy, Int64Ty, Int64Ty,
                                 Int8Ty
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR >= 9
  FunctionCallee cmplogHookIns8 = c8;
#else
  Function *cmplogHookIns8 = cast<Function>(c8);
#endif

#if LLVM_VERSION_MAJOR >= 9
  FunctionCallee
#else
  Constant *
#endif
      c16 = M.getOrInsertFunction("__cmplog_ins_hook16", VoidTy, Int128Ty,
                                  Int128Ty, Int8Ty
#if LLVM_VERSION_MAJOR < 5
                                  ,
                                  NULL
#endif
      );
#if LLVM_VERSION_MAJOR < 9
  Function *cmplogHookIns16 = cast<Function>(c16);
#else
  FunctionCallee cmplogHookIns16 = c16;
#endif

#if LLVM_VERSION_MAJOR >= 9
  FunctionCallee
#else
  Constant *
#endif
      cN = M.getOrInsertFunction("__cmplog_ins_hookN", VoidTy, Int128Ty,
                                 Int128Ty, Int8Ty, Int8Ty
#if LLVM_VERSION_MAJOR < 5
                                 ,
                                 NULL
#endif
      );
#if LLVM_VERSION_MAJOR >= 9
  FunctionCallee cmplogHookInsN = cN;
#else
  Function *cmplogHookInsN = cast<Function>(cN);
#endif

  GlobalVariable *AFLCmplogPtr = M.getNamedGlobal("__afl_cmp_map");
  
  if (!AFLCmplogPtr) {

    AFLCmplogPtr = new GlobalVariable(M, PointerType::get(Int8Ty, 0), false,
                                      GlobalValue::ExternalWeakLinkage, 0,
                                      "__afl_cmp_map");

  }

  /* Used for storing each cmp instruction successors' CurLoc,
     since we don't want to break the cmp_hook interface. */
  
  AFLLocPtr = new GlobalVariable(M, PointerType::get(Int32Ty, 0), false,
      GlobalValue::ExternalLinkage, 0, "__afl_loc_ptr");
  
  AFLDisPtr = new GlobalVariable(M, PointerType::get(Int64Ty, 0), false,
      GlobalValue::ExternalLinkage, 0, "__afl_dis_ptr");
  
  AFLNumOfSucc = 
        new GlobalVariable(M, Int32Ty, false, 
                           GlobalValue::ExternalLinkage, 0, "__afl_num_of_succ");

  Constant *Null = Constant::getNullValue(PointerType::get(Int8Ty, 0));

  /* iterate over all functions, bbs and instruction and add suitable calls */
  for (auto &F : M) {

    if (!isInInstrumentList(&F, MNAME)) continue;

    for (auto &BB : F) {

      for (auto &IN : BB) {

        CmpInst *selectcmpInst = nullptr;
        if ((selectcmpInst = dyn_cast<CmpInst>(&IN))) {

          icomps.push_back(selectcmpInst);

        }

      }

    }

  }

  if (icomps.size()) {

    // if (!be_quiet) errs() << "Hooking " << icomps.size() <<
    //                          " cmp instructions\n";

    for (auto &selectcmpInst : icomps) {

      IRBuilder<> IRB2(selectcmpInst->getParent());
      IRB2.SetInsertPoint(selectcmpInst);
      LoadInst *CmpPtr = IRB2.CreateLoad(
#if LLVM_VERSION_MAJOR >= 14
          PointerType::get(Int8Ty, 0),
#endif
          AFLCmplogPtr);
      CmpPtr->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(C, None));
      auto is_not_null = IRB2.CreateICmpNE(CmpPtr, Null);
      auto ThenTerm =
          SplitBlockAndInsertIfThen(is_not_null, selectcmpInst, false);

      IRBuilder<> IRB(ThenTerm);

      Value *op0 = selectcmpInst->getOperand(0);
      Value *op1 = selectcmpInst->getOperand(1);
      Value *op0_saved = op0, *op1_saved = op1;
      auto   ty0 = op0->getType();
      auto   ty1 = op1->getType();

      IntegerType *intTyOp0 = NULL;
      IntegerType *intTyOp1 = NULL;
      unsigned     max_size = 0, cast_size = 0;
      unsigned     attr = 0, vector_cnt = 0, is_fp = 0;
      CmpInst *    cmpInst = dyn_cast<CmpInst>(selectcmpInst);
      
      if (!cmpInst) { continue; }

      switch (cmpInst->getPredicate()) {

        case CmpInst::ICMP_NE:
        case CmpInst::FCMP_UNE:
        case CmpInst::FCMP_ONE:
          break;
        case CmpInst::ICMP_EQ:
        case CmpInst::FCMP_UEQ:
        case CmpInst::FCMP_OEQ:
          attr += 1;
          break;
        case CmpInst::ICMP_UGT:
        case CmpInst::ICMP_SGT:
        case CmpInst::FCMP_OGT:
        case CmpInst::FCMP_UGT:
          attr += 2;
          break;
        case CmpInst::ICMP_UGE:
        case CmpInst::ICMP_SGE:
        case CmpInst::FCMP_OGE:
        case CmpInst::FCMP_UGE:
          attr += 3;
          break;
        case CmpInst::ICMP_ULT:
        case CmpInst::ICMP_SLT:
        case CmpInst::FCMP_OLT:
        case CmpInst::FCMP_ULT:
          attr += 4;
          break;
        case CmpInst::ICMP_ULE:
        case CmpInst::ICMP_SLE:
        case CmpInst::FCMP_OLE:
        case CmpInst::FCMP_ULE:
          attr += 5;
          break;
        default:
          break;

      }

      if (selectcmpInst->getOpcode() == Instruction::FCmp) {

        if (ty0->isVectorTy()) {

          VectorType *tt = dyn_cast<VectorType>(ty0);
          if (!tt) {

            fprintf(stderr, "Warning: cmplog cmp vector is not a vector!\n");
            continue;

          }

#if (LLVM_VERSION_MAJOR >= 12)
          vector_cnt = tt->getElementCount().getKnownMinValue();
          ty0 = tt->getElementType();
#endif

        }

        if (ty0->isHalfTy()
#if LLVM_VERSION_MAJOR >= 11
            || ty0->isBFloatTy()
#endif
        )
          max_size = 16;
        else if (ty0->isFloatTy())
          max_size = 32;
        else if (ty0->isDoubleTy())
          max_size = 64;
        else if (ty0->isX86_FP80Ty())
          max_size = 80;
        else if (ty0->isFP128Ty() || ty0->isPPC_FP128Ty())
          max_size = 128;
#if (LLVM_VERSION_MAJOR >= 12)
        else if (ty0->getTypeID() != llvm::Type::PointerTyID && !be_quiet)
          fprintf(stderr, "Warning: unsupported cmp type for cmplog: %u!\n",
                  ty0->getTypeID());
#endif

        attr += 8;
        is_fp = 1;
        // fprintf(stderr, "HAVE FP %u!\n", vector_cnt);

      } else {

        if (ty0->isVectorTy()) {

#if (LLVM_VERSION_MAJOR >= 12)
          VectorType *tt = dyn_cast<VectorType>(ty0);
          if (!tt) {

            fprintf(stderr, "Warning: cmplog cmp vector is not a vector!\n");
            continue;

          }

          vector_cnt = tt->getElementCount().getKnownMinValue();
          ty1 = ty0 = tt->getElementType();
#endif

        }

        intTyOp0 = dyn_cast<IntegerType>(ty0);
        intTyOp1 = dyn_cast<IntegerType>(ty1);

        if (intTyOp0 && intTyOp1) {

          max_size = intTyOp0->getBitWidth() > intTyOp1->getBitWidth()
                         ? intTyOp0->getBitWidth()
                         : intTyOp1->getBitWidth();

        } else {

#if (LLVM_VERSION_MAJOR >= 12)
          if (ty0->getTypeID() != llvm::Type::PointerTyID && !be_quiet) {

            fprintf(stderr, "Warning: unsupported cmp type for cmplog: %u\n",
                    ty0->getTypeID());

          }

#endif

        }

      }

      if (!max_size || max_size < 16) {

        // fprintf(stderr, "too small\n");
        continue;

      }

      if (max_size % 8) { max_size = (((max_size / 8) + 1) * 8); }

      if (max_size > 128) {

        if (!be_quiet) {

          fprintf(stderr,
                  "Cannot handle this compare bit size: %u (truncating)\n",
                  max_size);

        }

        max_size = 128;

      }

      // do we need to cast?
      switch (max_size) {

        case 8:
        case 16:
        case 32:
        case 64:
        case 128:
          cast_size = max_size;
          break;
        default:
          cast_size = 128;

      }

      // XXX FIXME BUG TODO
      if (is_fp && vector_cnt) { continue; }

      uint64_t cur = 0, last_val0 = 0, last_val1 = 0, cur_val;

      while (1) {

        std::vector<Value *> args;
        uint32_t             skip = 0;

        if (vector_cnt) {

          op0 = IRB.CreateExtractElement(op0_saved, cur);
          op1 = IRB.CreateExtractElement(op1_saved, cur);
          /*
          std::string errMsg;
          raw_string_ostream os(errMsg);
          op0_saved->print(os);
          fprintf(stderr, "X: %s\n", os.str().c_str());
          */
          if (is_fp) {

/*
            ConstantFP *i0 = dyn_cast<ConstantFP>(op0);
            ConstantFP *i1 = dyn_cast<ConstantFP>(op1);
            // BUG FIXME TODO: this is null ... but why?
            // fprintf(stderr, "%p %p\n", i0, i1);
            if (i0) {

              cur_val = (uint64_t)i0->getValue().convertToDouble();
              if (last_val0 && last_val0 == cur_val) { skip = 1; }
              last_val0 = cur_val;

            }

            if (i1) {

              cur_val = (uint64_t)i1->getValue().convertToDouble();
              if (last_val1 && last_val1 == cur_val) { skip = 1; }
              last_val1 = cur_val;

            }
*/

          } else {

            ConstantInt *i0 = dyn_cast<ConstantInt>(op0);
            ConstantInt *i1 = dyn_cast<ConstantInt>(op1);
            if (i0 && i0->uge(0xffffffffffffffff) == false) {

              cur_val = i0->getZExtValue();
              if (last_val0 && last_val0 == cur_val) { skip = 1; }
              last_val0 = cur_val;

            }

            if (i1 && i1->uge(0xffffffffffffffff) == false) {

              cur_val = i1->getZExtValue();
              if (last_val1 && last_val1 == cur_val) { skip = 1; }
              last_val1 = cur_val;

            }

          }

        }

        if (!skip) {
          
          instrumentMetadata(M, IRB, cmpInst);

          // errs() << "[CMPLOG] cmp  " << *cmpInst << "(in function " <<
          // cmpInst->getFunction()->getName() << ")\n";

          // first bitcast to integer type of the same bitsize as the original
          // type (this is a nop, if already integer)
          Value *op0_i = IRB.CreateBitCast(
              op0, IntegerType::get(C, ty0->getPrimitiveSizeInBits()));
          // then create a int cast, which does zext, trunc or bitcast. In our
          // case usually zext to the next larger supported type (this is a nop
          // if already the right type)
          Value *V0 =
              IRB.CreateIntCast(op0_i, IntegerType::get(C, cast_size), false);
          args.push_back(V0);
          Value *op1_i = IRB.CreateBitCast(
              op1, IntegerType::get(C, ty1->getPrimitiveSizeInBits()));
          Value *V1 =
              IRB.CreateIntCast(op1_i, IntegerType::get(C, cast_size), false);
          args.push_back(V1);

          // errs() << "[CMPLOG] casted parameters:\n0: " << *V0 << "\n1: " <<
          // *V1
          // << "\n";

          ConstantInt *attribute = ConstantInt::get(Int8Ty, attr);
          args.push_back(attribute);

          if (cast_size != max_size) {

            ConstantInt *bitsize = ConstantInt::get(Int8Ty, (max_size / 8) - 1);
            args.push_back(bitsize);

          }

          // fprintf(stderr, "_ExtInt(%u) castTo %u with attr %u didcast %u\n",
          //         max_size, cast_size, attr);

          switch (cast_size) {

            case 8:
              IRB.CreateCall(cmplogHookIns1, args);
              break;
            case 16:
              IRB.CreateCall(cmplogHookIns2, args);
              break;
            case 32:
              IRB.CreateCall(cmplogHookIns4, args);
              break;
            case 64:
              IRB.CreateCall(cmplogHookIns8, args);
              break;
            case 128:
              if (max_size == 128) {

                IRB.CreateCall(cmplogHookIns16, args);

              } else {

                IRB.CreateCall(cmplogHookInsN, args);

              }

              break;

          }

        }

        /* else fprintf(stderr, "skipped\n"); */

        ++cur;
        if (cur >= vector_cnt) { break; }
        skip = 0;

      }

    }

  }

  if (icomps.size())
    return true;
  else
    return false;

}

void CmpLogInstructions::instrumentDistance(Module &M, IRBuilder <> &IRB, Instruction *cmpInst) {

  long distance;
  GlobalVariable *FunctionGuardArray;
  int i = 0;

  MDNode *N = cmpInst->getMetadata("successor.distance");

  for (auto it = N->op_begin(); it != N->op_end(); it++) {
    
    Metadata *Meta = it->get();
    DIEnumerator *DIEn;
    
    if ((DIEn = dyn_cast<DIEnumerator>(Meta))) {  
      
      if ((FunctionGuardArray = M.getGlobalVariable(DIEn->getName(), true))) {
      
        distance = DIEn->getValue().getSExtValue();
        
        /* Load Dis pointer */
        
        Value *DisPtr = IRB.CreateGEP(Int64Ty, AFLDisPtr, ConstantInt::get(Int64Ty, i++));

        /* Store CurLoc */
        StoreInst *StoreCtx = IRB.CreateStore(ConstantInt::get(Int64Ty, distance), DisPtr);
        StoreCtx->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(M.getContext(), None));
        //errs() << FunctionGuardArray->getName() << " dis: " << DIEn->getValue() << "\n";    
      
      }

    }

  }
  //errs() << "\n";

}

void CmpLogInstructions::instrumentCurLoc(Module &M, IRBuilder <> &IRB, Instruction *cmpInst) {
  
  size_t Idx;
  GlobalVariable *FunctionGuardArray;
  int i = 0;
  
  MDNode *N = cmpInst->getMetadata("successor.curloc");
  
  for (auto it = N->op_begin(); it != N->op_end(); it++) {
    
    Metadata *Meta = it->get();
    DIEnumerator *DIEn;
    
    if ((DIEn = dyn_cast<DIEnumerator>(Meta))) {  
      
      if ((FunctionGuardArray = M.getGlobalVariable(DIEn->getName(), true))) {
        
        /* Get Guard pointer */
        Idx = DIEn->getValue().getZExtValue();
        Value *GuardPtr = IRB.CreateIntToPtr(
              IRB.CreateAdd(IRB.CreatePointerCast(FunctionGuardArray, IntptrTy),
                            ConstantInt::get(IntptrTy, Idx * 4)),
              Int32PtrTy);

        /* Load CurLoc */
        LoadInst *CurLoc = IRB.CreateLoad(Int32Ty, GuardPtr);
        CurLoc->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(M.getContext(), None));

        /* Load LOC pointer */

        Value *LocPtr = IRB.CreateGEP(Int32Ty, AFLLocPtr, ConstantInt::get(Int32Ty, i++));

        /* Store CurLoc */
        StoreInst *StoreCtx = IRB.CreateStore(CurLoc, LocPtr);
        StoreCtx->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(M.getContext(), None));
        //errs() << FunctionGuardArray->getName() << " : " << DIEn->getValue() << "\n";
      }

    }

  }
  //errs() << "\n";
        
}

void CmpLogInstructions::instrumentMetadata(Module &M, IRBuilder <> &IRB, Instruction *cmpInst) {

  int cnt = 0;
  MDNode *N;

  if ((N = cmpInst->getMetadata("successor.curloc"))) {
    
    for (auto it = N->op_begin(); it != N->op_end(); it++) {
    
      cnt++;
    
    }

    if (cnt <= 16) {
      
      /* Store number of successors */
      StoreInst *StoreCtx = IRB.CreateStore(ConstantInt::get(Int32Ty, cnt), AFLNumOfSucc);
      StoreCtx->setMetadata(M.getMDKindID("nosanitize"), MDNode::get(M.getContext(), None));
    
      instrumentCurLoc(M, IRB, cmpInst);

      if ((N = cmpInst->getMetadata("successor.distance"))) {
    
        instrumentDistance(M, IRB, cmpInst);

      }

    }

  }

}

bool CmpLogInstructions::runOnModule(Module &M) {

  if (getenv("AFL_QUIET") == NULL)
    printf("Running cmplog-instructions-pass by andreafioraldi@gmail.com\n");
  else
    be_quiet = 1;
  hookInstrs(M);
  verifyModule(M);

  return true;

}

static void registerCmpLogInstructionsPass(const PassManagerBuilder &,
                                           legacy::PassManagerBase &PM) {

  auto p = new CmpLogInstructions();
  PM.add(p);

}

static RegisterStandardPasses RegisterCmpLogInstructionsPass(
    PassManagerBuilder::EP_OptimizerLast, registerCmpLogInstructionsPass);

static RegisterStandardPasses RegisterCmpLogInstructionsPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerCmpLogInstructionsPass);

#if LLVM_VERSION_MAJOR >= 11
static RegisterStandardPasses RegisterCmpLogInstructionsPassLTO(
    PassManagerBuilder::EP_FullLinkTimeOptimizationLast,
    registerCmpLogInstructionsPass);
#endif

