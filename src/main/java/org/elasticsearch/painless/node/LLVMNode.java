/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.painless.node;

import org.bytedeco.javacpp.BytePointer;
import org.bytedeco.javacpp.Pointer;
import org.bytedeco.javacpp.PointerPointer;
import org.bytedeco.llvm.LLVM.LLVMBasicBlockRef;
import org.bytedeco.llvm.LLVM.LLVMBuilderRef;
import org.bytedeco.llvm.LLVM.LLVMModuleRef;
import org.bytedeco.llvm.LLVM.LLVMTypeRef;
import org.bytedeco.llvm.LLVM.LLVMValueRef;
import org.elasticsearch.painless.ir.ExpressionNode;
import org.elasticsearch.painless.symbol.ScriptScope;

import java.util.ArrayList;
import java.util.List;

import static org.bytedeco.llvm.global.LLVM.LLVMAddFunction;
import static org.bytedeco.llvm.global.LLVM.LLVMAppendBasicBlock;
import static org.bytedeco.llvm.global.LLVM.LLVMBuildGEP;
import static org.bytedeco.llvm.global.LLVM.LLVMBuildGEP2;
import static org.bytedeco.llvm.global.LLVM.LLVMBuildLoad;
import static org.bytedeco.llvm.global.LLVM.LLVMConstInt;
import static org.bytedeco.llvm.global.LLVM.LLVMConstReal;
import static org.bytedeco.llvm.global.LLVM.LLVMCreateBuilder;
import static org.bytedeco.llvm.global.LLVM.LLVMDoubleType;
import static org.bytedeco.llvm.global.LLVM.LLVMDumpModule;
import static org.bytedeco.llvm.global.LLVM.LLVMFunctionType;
import static org.bytedeco.llvm.global.LLVM.LLVMGetParam;
import static org.bytedeco.llvm.global.LLVM.LLVMInitializeNativeAsmParser;
import static org.bytedeco.llvm.global.LLVM.LLVMInitializeNativeAsmPrinter;
import static org.bytedeco.llvm.global.LLVM.LLVMInitializeNativeTarget;
import static org.bytedeco.llvm.global.LLVM.LLVMInt32Type;
import static org.bytedeco.llvm.global.LLVM.LLVMModuleCreateWithName;
import static org.bytedeco.llvm.global.LLVM.LLVMPositionBuilderAtEnd;
import static org.bytedeco.llvm.global.LLVM.LLVMPrintMessageAction;
import static org.bytedeco.llvm.global.LLVM.LLVMPrintModuleToFile;
import static org.bytedeco.llvm.global.LLVM.LLVMVerifyModule;
import static org.bytedeco.llvm.global.LLVM.LLVMWriteBitcodeToFile;

public class LLVMNode {

    public List<Object> llvmNodes;

    public List<LLVMTypeRef> args = new ArrayList<>();

    public List<LLVMValueRef> values = new ArrayList<>();

    public LLVMModuleRef module;

    // 创建 LLVMBuilderRef 实例
    public LLVMBuilderRef builder;
    // 创建函数
    public LLVMValueRef function;
    // 创建基本块
    public LLVMBasicBlockRef entry;

    public LLVMNode(){
        llvmNodes = new ArrayList<>();
        // 初始化 LLVM 环境
        LLVMInitializeNativeTarget();
        LLVMInitializeNativeAsmPrinter();
        LLVMInitializeNativeAsmParser();
        builder = LLVMCreateBuilder();
    }
    static public void convert(Object o){

    }
    public void setParamTypesALL(List<LLVMTypeRef> args){
        this.args.addAll(args);
    }

    public void setParamTypes(LLVMTypeRef arg){
        this.args.add(arg);
    }

    public void setParamValueALL(List<LLVMValueRef> args){
        this.values.addAll(args);
    }

    public void setParamValue(String name, LLVMTypeRef typeRef){
        this.values.add(LLVMBuildLoad(builder, LLVMBuildGEP(builder, LLVMGetParam(function, 0), new PointerPointer<>(LLVMConstInt(typeRef, 0, 0)), 1, ""), name));
    }

    public void setConstantParamValue(Object value, LLVMTypeRef typeRef){
        if (LLVMInt32Type().equals(typeRef)) {
            this.values.add(LLVMConstInt(LLVMInt32Type(), (int)value, 0));
        } else {
            this.values.add(LLVMConstReal(LLVMDoubleType(), (double)value));
        }
    }

    public void setllvmNodes(Object o){
        this.llvmNodes.add(o);
    }
    public List<Object> getllvmNodes(){
        return this.llvmNodes;
    }
    public void createModule(String name){
        // 创建模块
        module = LLVMModuleCreateWithName(name);
    }
    public void createFunction(){
        PointerPointer<Pointer> paramTypes = new PointerPointer<>();
        paramTypes.put((LLVMTypeRef[])args.toArray());
        LLVMTypeRef ret_type = LLVMFunctionType(LLVMDoubleType(), paramTypes, args.size(), 0);
        this.function = LLVMAddFunction(module, "compute", ret_type);
        this.entry = LLVMAppendBasicBlock(function, "entry");
        // 在 entry 基本块中插入指令
        LLVMPositionBuilderAtEnd(builder, entry);
    }
    public void createValue(){

    }
    public void createExpression(){

    }
    public void createFiles( String bcName, String llName){
        BytePointer error = new BytePointer();
        LLVMDumpModule(module);
        if (LLVMVerifyModule(module, LLVMPrintMessageAction, error) != 0) {
            System.out.println("Failed to validate module: " + error.getString());
            return;
        }
        // Stage 3: Dump the module to file
        if (LLVMWriteBitcodeToFile(module, bcName) != 0) {
            System.err.println("Failed to write bitcode to file");
            return;
        }
        BytePointer out = new BytePointer((Pointer)null);
        if (LLVMPrintModuleToFile(module, llName ,out) != 0) {
            System.err.println("Failed to write ll to file");
            return;
        }
        return;
    }
}
