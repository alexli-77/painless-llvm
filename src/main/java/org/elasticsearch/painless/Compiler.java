/*
 * Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License
 * 2.0 and the Server Side Public License, v 1; you may not use this file except
 * in compliance with, at your election, the Elastic License 2.0 or the Server
 * Side Public License, v 1.
 */

package org.elasticsearch.painless;


import org.elasticsearch.bootstrap.BootstrapInfo;
import org.elasticsearch.painless.antlr.Walker;
import org.elasticsearch.painless.ir.ClassNode;
import org.elasticsearch.painless.lookup.PainlessLookup;

import org.elasticsearch.painless.node.ECall;
import org.elasticsearch.painless.node.ECallLocal;
import org.elasticsearch.painless.node.EDot;
import org.elasticsearch.painless.node.EString;
import org.elasticsearch.painless.node.SClass;

import org.elasticsearch.painless.phase.DefaultConstantFoldingOptimizationPhase;
import org.elasticsearch.painless.phase.DefaultIRTreeToASMBytesPhase;
import org.elasticsearch.painless.phase.DefaultStaticConstantExtractionPhase;
import org.elasticsearch.painless.phase.DefaultStringConcatenationOptimizationPhase;
import org.elasticsearch.painless.phase.IRTreeVisitor;
import org.elasticsearch.painless.phase.PainlessSemanticAnalysisPhase;
import org.elasticsearch.painless.phase.PainlessSemanticHeaderPhase;
import org.elasticsearch.painless.phase.PainlessUserTreeToIRTreePhase;
import org.elasticsearch.painless.phase.UserTreeVisitor;
import org.elasticsearch.painless.spi.Whitelist;
import org.elasticsearch.painless.symbol.Decorations.IRNodeDecoration;
import org.elasticsearch.painless.symbol.ScriptScope;
import org.elasticsearch.painless.symbol.WriteScope;
import org.objectweb.asm.util.Printer;

import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.CodeSource;
import java.security.SecureClassLoader;
import java.security.cert.Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.elasticsearch.painless.node.AExpression;
import org.elasticsearch.painless.node.AStatement;
import org.elasticsearch.painless.node.EAssignment;
import org.elasticsearch.painless.node.EBinary;
import org.elasticsearch.painless.node.EBooleanComp;
import org.elasticsearch.painless.node.EBrace;
import org.elasticsearch.painless.node.EComp;
import org.elasticsearch.painless.node.ENewArray;
import org.elasticsearch.painless.node.ENumeric;
import org.elasticsearch.painless.node.ESymbol;
import org.elasticsearch.painless.node.EUnary;
import org.elasticsearch.painless.node.SBlock;
import org.elasticsearch.painless.node.SDeclBlock;
import org.elasticsearch.painless.node.SDeclaration;
import org.elasticsearch.painless.node.SExpression;
import org.elasticsearch.painless.node.SFor;
import org.elasticsearch.painless.node.SFunction;
import org.elasticsearch.painless.node.SIfElse;
import org.elasticsearch.painless.node.SReturn;
import org.bytedeco.javacpp.BytePointer;
import org.bytedeco.javacpp.Pointer;
import org.bytedeco.javacpp.PointerPointer;
import org.bytedeco.llvm.LLVM.LLVMBasicBlockRef;
import org.bytedeco.llvm.LLVM.LLVMBuilderRef;
import org.bytedeco.llvm.LLVM.LLVMContextRef;
import org.bytedeco.llvm.LLVM.LLVMModuleRef;
import org.bytedeco.llvm.LLVM.LLVMOrcThreadSafeContextRef;
import org.bytedeco.llvm.LLVM.LLVMTypeRef;
import org.bytedeco.llvm.LLVM.LLVMValueRef;
import static org.antlr.v4.runtime.atn.PredictionMode.LL;
import static org.bytedeco.llvm.global.LLVM.LLVMABISizeOfType;
import static org.bytedeco.llvm.global.LLVM.LLVMAddFunction;
import static org.bytedeco.llvm.global.LLVM.LLVMAddGlobal;
import static org.bytedeco.llvm.global.LLVM.LLVMAppendBasicBlock;
import static org.bytedeco.llvm.global.LLVM.LLVMAppendBasicBlockInContext;
import static org.bytedeco.llvm.global.LLVM.LLVMArrayType;
import static org.bytedeco.llvm.global.LLVM.LLVMBuildAdd;
import static org.bytedeco.llvm.global.LLVM.LLVMBuildAlloca;
import static org.bytedeco.llvm.global.LLVM.LLVMBuildAnd;
import static org.bytedeco.llvm.global.LLVM.LLVMBuildArrayAlloca;
import static org.bytedeco.llvm.global.LLVM.LLVMBuildBr;
import static org.bytedeco.llvm.global.LLVM.LLVMBuildCall2;
import static org.bytedeco.llvm.global.LLVM.LLVMBuildCondBr;
import static org.bytedeco.llvm.global.LLVM.LLVMBuildFDiv;
import static org.bytedeco.llvm.global.LLVM.LLVMBuildGEP2;
import static org.bytedeco.llvm.global.LLVM.LLVMBuildICmp;
import static org.bytedeco.llvm.global.LLVM.LLVMBuildLoad2;
import static org.bytedeco.llvm.global.LLVM.LLVMBuildMul;
import static org.bytedeco.llvm.global.LLVM.LLVMBuildRet;
import static org.bytedeco.llvm.global.LLVM.LLVMBuildRetVoid;
import static org.bytedeco.llvm.global.LLVM.LLVMBuildSRem;
import static org.bytedeco.llvm.global.LLVM.LLVMBuildStore;
import static org.bytedeco.llvm.global.LLVM.LLVMBuildSub;
import static org.bytedeco.llvm.global.LLVM.LLVMCCallConv;
import static org.bytedeco.llvm.global.LLVM.LLVMCodeModelDefault;
import static org.bytedeco.llvm.global.LLVM.LLVMConstArray;
import static org.bytedeco.llvm.global.LLVM.LLVMConstInt;
import static org.bytedeco.llvm.global.LLVM.LLVMConstIntOfString;
import static org.bytedeco.llvm.global.LLVM.LLVMConstNull;
import static org.bytedeco.llvm.global.LLVM.LLVMConstReal;
import static org.bytedeco.llvm.global.LLVM.LLVMConstString;
import static org.bytedeco.llvm.global.LLVM.LLVMContextCreate;
import static org.bytedeco.llvm.global.LLVM.LLVMContextDispose;
import static org.bytedeco.llvm.global.LLVM.LLVMCreateBuilderInContext;
import static org.bytedeco.llvm.global.LLVM.LLVMCreateTargetMachine;
import static org.bytedeco.llvm.global.LLVM.LLVMDisposeBuilder;
import static org.bytedeco.llvm.global.LLVM.LLVMDisposeMessage;
import static org.bytedeco.llvm.global.LLVM.LLVMDisposeModule;
import static org.bytedeco.llvm.global.LLVM.LLVMDoubleType;
import static org.bytedeco.llvm.global.LLVM.LLVMDoubleTypeInContext;
import static org.bytedeco.llvm.global.LLVM.LLVMDumpModule;
import static org.bytedeco.llvm.global.LLVM.LLVMExternalLinkage;
import static org.bytedeco.llvm.global.LLVM.LLVMFP128Type;
import static org.bytedeco.llvm.global.LLVM.LLVMFunctionType;
import static org.bytedeco.llvm.global.LLVM.LLVMGenericValueToPointer;
import static org.bytedeco.llvm.global.LLVM.LLVMGetDefaultTargetTriple;
import static org.bytedeco.llvm.global.LLVM.LLVMGetElementType;
import static org.bytedeco.llvm.global.LLVM.LLVMGetGlobalContext;
import static org.bytedeco.llvm.global.LLVM.LLVMGetGlobalPassRegistry;
import static org.bytedeco.llvm.global.LLVM.LLVMGetIntTypeWidth;
import static org.bytedeco.llvm.global.LLVM.LLVMGetParam;
import static org.bytedeco.llvm.global.LLVM.LLVMGetTargetFromTriple;
import static org.bytedeco.llvm.global.LLVM.LLVMGetTypeByName;
import static org.bytedeco.llvm.global.LLVM.LLVMGetTypeByName2;
import static org.bytedeco.llvm.global.LLVM.LLVMInitializeCore;
import static org.bytedeco.llvm.global.LLVM.LLVMInitializeNativeAsmParser;
import static org.bytedeco.llvm.global.LLVM.LLVMInitializeNativeAsmPrinter;
import static org.bytedeco.llvm.global.LLVM.LLVMInitializeNativeDisassembler;
import static org.bytedeco.llvm.global.LLVM.LLVMInitializeNativeTarget;
import static org.bytedeco.llvm.global.LLVM.LLVMInt32Type;
import static org.bytedeco.llvm.global.LLVM.LLVMInt32TypeInContext;
import static org.bytedeco.llvm.global.LLVM.LLVMInt64Type;
import static org.bytedeco.llvm.global.LLVM.LLVMInt64TypeInContext;
import static org.bytedeco.llvm.global.LLVM.LLVMInt8Type;
import static org.bytedeco.llvm.global.LLVM.LLVMIntEQ;
import static org.bytedeco.llvm.global.LLVM.LLVMIntSGE;
import static org.bytedeco.llvm.global.LLVM.LLVMIntSGT;
import static org.bytedeco.llvm.global.LLVM.LLVMIntSLE;
import static org.bytedeco.llvm.global.LLVM.LLVMIntSLT;
import static org.bytedeco.llvm.global.LLVM.LLVMInternalLinkage;
import static org.bytedeco.llvm.global.LLVM.LLVMLinkInMCJIT;
import static org.bytedeco.llvm.global.LLVM.LLVMLoadLibraryPermanently;
import static org.bytedeco.llvm.global.LLVM.LLVMModuleCreateWithNameInContext;
import static org.bytedeco.llvm.global.LLVM.LLVMObjectFile;
import static org.bytedeco.llvm.global.LLVM.LLVMOrcCreateNewThreadSafeContext;
import static org.bytedeco.llvm.global.LLVM.LLVMOrcThreadSafeContextGetContext;
import static org.bytedeco.llvm.global.LLVM.LLVMPointerType;
import static org.bytedeco.llvm.global.LLVM.LLVMPositionBuilderAtEnd;
import static org.bytedeco.llvm.global.LLVM.LLVMPrintMessageAction;
import static org.bytedeco.llvm.global.LLVM.LLVMPrintModuleToFile;
import static org.bytedeco.llvm.global.LLVM.LLVMSetDataLayout;
import static org.bytedeco.llvm.global.LLVM.LLVMSetFunctionCallConv;
import static org.bytedeco.llvm.global.LLVM.LLVMSetInitializer;
import static org.bytedeco.llvm.global.LLVM.LLVMSetLinkage;
import static org.bytedeco.llvm.global.LLVM.LLVMTargetMachineEmitToFile;
import static org.bytedeco.llvm.global.LLVM.LLVMTypeOf;
import static org.bytedeco.llvm.global.LLVM.LLVMVerifyModule;
import static org.bytedeco.llvm.global.LLVM.LLVMVoidType;
import static org.elasticsearch.painless.WriterConstants.CLASS_NAME;

/**
 * The Compiler is the entry point for generating a Painless script.  The compiler will receive a Painless
 * tree based on the type of input passed in (currently only ANTLR).  Two passes will then be run over the tree,
 * one for analysis and another to generate the actual byte code using ASM using the root of the tree {@link SClass}.
 */
final class Compiler {

    /**
     * Define the class with lowest privileges.
     */
    private static final CodeSource CODESOURCE;

    /**
     * Setup the code privileges.
     */
    static {
        try {
            // Setup the code privileges.
            CODESOURCE = new CodeSource(new URL("file:" + BootstrapInfo.UNTRUSTED_CODEBASE), (Certificate[]) null);
        } catch (MalformedURLException impossible) {
            throw new RuntimeException(impossible);
        }
    }

    /**
     * A secure class loader used to define Painless scripts.
     */
    final class Loader extends SecureClassLoader {
        private final AtomicInteger lambdaCounter = new AtomicInteger(0);

        /**
         * @param parent The parent ClassLoader.
         */
        Loader(ClassLoader parent) {
            super(parent);
        }

        /**
         * Will check to see if the {@link Class} has already been loaded when
         * the {@link PainlessLookup} was initially created.  Allows for {@link Whitelist}ed
         * classes to be loaded from other modules/plugins without a direct relationship
         * to the module's/plugin's {@link ClassLoader}.
         */
        @Override
        public Class<?> findClass(String name) throws ClassNotFoundException {
            Class<?> found = additionalClasses.get(name);
            if (found != null) {
                return found;
            }
            found = painlessLookup.javaClassNameToClass(name);

            return found != null ? found : super.findClass(name);
        }

        /**
         * Generates a Class object from the generated byte code.
         * @param name The name of the class.
         * @param bytes The generated byte code.
         * @return A Class object defining a factory.
         */
        Class<?> defineFactory(String name, byte[] bytes) {
            return defineClass(name, bytes, 0, bytes.length, CODESOURCE);
        }

        /**
         * Generates a Class object from the generated byte code.
         * @param name The name of the class.
         * @param bytes The generated byte code.
         * @return A Class object extending {@link PainlessScript}.
         */
        Class<? extends PainlessScript> defineScript(String name, byte[] bytes) {
            return defineClass(name, bytes, 0, bytes.length, CODESOURCE).asSubclass(PainlessScript.class);
        }

        /**
         * Generates a Class object for a lambda method.
         * @param name The name of the class.
         * @param bytes The generated byte code.
         * @return A Class object.
         */
        Class<?> defineLambda(String name, byte[] bytes) {
            return defineClass(name, bytes, 0, bytes.length, CODESOURCE);
        }

        /**
         * A counter used to generate a unique name for each lambda
         * function/reference class in this classloader.
         */
        int newLambdaIdentifier() {
            return lambdaCounter.getAndIncrement();
        }
    }

    /**
     * Return a new {@link Loader} for a script using the
     * {@link Compiler}'s specified {@link PainlessLookup}.
     */
    public Loader createLoader(ClassLoader parent) {
        return new Loader(parent);
    }

    /**
     * The class/interface the script will implement.
     */
    private final Class<?> scriptClass;

    /**
     * The whitelist the script will use.
     */
    private final PainlessLookup painlessLookup;

    /**
     * Classes that do not exist in the lookup, but are needed by the script factories.
     */
    private final Map<String, Class<?>> additionalClasses;

    /**
     * Standard constructor.
     * @param scriptClass The class/interface the script will implement.
     * @param factoryClass An optional class/interface to create the {@code scriptClass} instance.
     * @param statefulFactoryClass An optional class/interface to create the {@code factoryClass} instance.
     * @param painlessLookup The whitelist the script will use.
     */
    Compiler(Class<?> scriptClass, Class<?> factoryClass, Class<?> statefulFactoryClass, PainlessLookup painlessLookup) {
        this.scriptClass = scriptClass;
        this.painlessLookup = painlessLookup;
        Map<String, Class<?>> additionalClassMap = new HashMap<>();
        additionalClassMap.put(scriptClass.getName(), scriptClass);
        addFactoryMethod(additionalClassMap, factoryClass, "newInstance");
        addFactoryMethod(additionalClassMap, statefulFactoryClass, "newFactory");
        addFactoryMethod(additionalClassMap, statefulFactoryClass, "newInstance");
        this.additionalClasses = Collections.unmodifiableMap(additionalClassMap);
    }

    private static void addFactoryMethod(Map<String, Class<?>> additionalClasses, Class<?> factoryClass, String methodName) {
        if (factoryClass == null) {
            return;
        }

        Method factoryMethod = null;
        for (Method method : factoryClass.getMethods()) {
            if (methodName.equals(method.getName())) {
                factoryMethod = method;
                break;
            }
        }
        if (factoryMethod == null) {
            return;
        }

        additionalClasses.put(factoryClass.getName(), factoryClass);
        for (int i = 0; i < factoryMethod.getParameterTypes().length; ++i) {
            Class<?> parameterClazz = factoryMethod.getParameterTypes()[i];
            additionalClasses.put(parameterClazz.getName(), parameterClazz);
        }
    }

    /**
     * Runs the two-pass compiler to generate a Painless script.
     * @param loader The ClassLoader used to define the script.
     * @param name The name of the script.
     * @param source The source code for the script.
     * @param settings The CompilerSettings to be used during the compilation.
     * @return The ScriptScope used to compile
     */
    ScriptScope compile(Loader loader, String name, String source, CompilerSettings settings) {
        String scriptName = Location.computeSourceName(name);
        ScriptClassInfo scriptClassInfo = new ScriptClassInfo(painlessLookup, scriptClass);
        SClass root = Walker.buildPainlessTree(scriptName, source, settings);
        ScriptScope scriptScope = new ScriptScope(painlessLookup, settings, scriptClassInfo, scriptName, source, root.getIdentifier() + 1);
        new PainlessSemanticHeaderPhase().visitClass(root, scriptScope);
//        new PainlessSemanticAnalysisPhase().visitClass(root, scriptScope);
        getLLVMDoc(root);
        new PainlessUserTreeToIRTreePhase().visitClass(root, scriptScope);
        ClassNode classNode = (ClassNode) scriptScope.getDecoration(root, IRNodeDecoration.class).irNode();

//        scriptScope.getllvmNodes().createModule(name);
//        scriptScope.getllvmNodes().createFunction();
//        scriptScope.getllvmNodes().createFiles("./func.bc","./func.ll");

        new DefaultStringConcatenationOptimizationPhase().visitClass(classNode, null);
        new DefaultConstantFoldingOptimizationPhase().visitClass(classNode, null);
        new DefaultStaticConstantExtractionPhase().visitClass(classNode, scriptScope);
        new DefaultIRTreeToASMBytesPhase().visitScript(classNode);
        byte[] bytes = classNode.getBytes();

        try {
            Class<? extends PainlessScript> clazz = loader.defineScript(CLASS_NAME, bytes);

            for (Map.Entry<String, Object> staticConstant : scriptScope.getStaticConstants().entrySet()) {
                clazz.getField(staticConstant.getKey()).set(null, staticConstant.getValue());
            }

            return scriptScope;
        } catch (Exception exception) {
            // Catch everything to let the user know this is something caused internally.
            throw new IllegalStateException("An internal error occurred attempting to define the script [" + name + "].", exception);
        }
    }

    /**
     * Runs the two-pass compiler to generate a Painless script.  (Used by the debugger.)
     * @param source The source code for the script.
     * @param settings The CompilerSettings to be used during the compilation.
     * @return The bytes for compilation.
     */
    byte[] compile(String name, String source, CompilerSettings settings, Printer debugStream) {
        String scriptName = Location.computeSourceName(name);
        ScriptClassInfo scriptClassInfo = new ScriptClassInfo(painlessLookup, scriptClass);
        SClass root = Walker.buildPainlessTree(scriptName, source, settings);
        ScriptScope scriptScope = new ScriptScope(painlessLookup, settings, scriptClassInfo, scriptName, source, root.getIdentifier() + 1);
        new PainlessSemanticHeaderPhase().visitClass(root, scriptScope);
        new PainlessSemanticAnalysisPhase().visitClass(root, scriptScope);
        new PainlessUserTreeToIRTreePhase().visitClass(root, scriptScope);
        ClassNode classNode = (ClassNode) scriptScope.getDecoration(root, IRNodeDecoration.class).irNode();
        new DefaultStringConcatenationOptimizationPhase().visitClass(classNode, null);
        new DefaultConstantFoldingOptimizationPhase().visitClass(classNode, null);
        new DefaultStaticConstantExtractionPhase().visitClass(classNode, scriptScope);
        classNode.setDebugStream(debugStream);
        new DefaultIRTreeToASMBytesPhase().visitScript(classNode);

        return classNode.getBytes();
    }

    /**
     * Runs the two-pass compiler to generate a Painless script with option visitors for each major phase.
     */
    byte[] compile(
        String name,
        String source,
        CompilerSettings settings,
        Printer debugStream,
        UserTreeVisitor<ScriptScope> semanticPhaseVisitor,
        UserTreeVisitor<ScriptScope> irPhaseVisitor,
        IRTreeVisitor<WriteScope> asmPhaseVisitor
    ) {
        String scriptName = Location.computeSourceName(name);
        ScriptClassInfo scriptClassInfo = new ScriptClassInfo(painlessLookup, scriptClass);
        SClass root = Walker.buildPainlessTree(scriptName, source, settings);
        ScriptScope scriptScope = new ScriptScope(painlessLookup, settings, scriptClassInfo, scriptName, source, root.getIdentifier() + 1);

        new PainlessSemanticHeaderPhase().visitClass(root, scriptScope);
        new PainlessSemanticAnalysisPhase().visitClass(root, scriptScope);
        if (semanticPhaseVisitor != null) {
            semanticPhaseVisitor.visitClass(root, scriptScope);
        }

        new PainlessUserTreeToIRTreePhase().visitClass(root, scriptScope);
        if (irPhaseVisitor != null) {
            irPhaseVisitor.visitClass(root, scriptScope);
        }

        ClassNode classNode = (ClassNode) scriptScope.getDecoration(root, IRNodeDecoration.class).irNode();
        new DefaultStringConcatenationOptimizationPhase().visitClass(classNode, null);
        new DefaultConstantFoldingOptimizationPhase().visitClass(classNode, null);
        new DefaultStaticConstantExtractionPhase().visitClass(classNode, scriptScope);
        classNode.setDebugStream(debugStream);

        WriteScope writeScope = WriteScope.newScriptScope();
        new DefaultIRTreeToASMBytesPhase().visitClass(classNode, writeScope);
        if (asmPhaseVisitor != null) {
            asmPhaseVisitor.visitClass(classNode, writeScope);
        }

        return classNode.getBytes();
    }

    /***
     * String script = "return doc['infoId'].value * 20 + doc['int'].value * 19 + decayNumericLinear(params.origin, params.scale, params.offset, params.decay, doc['int'].value) - Math.log10(randomScore(7, '_seq_no')) + _score";
     * @param root
     */
    public void getLLVMDoc(SClass root) {
        // Stage 1: Initialize LLVM components
        LLVMInitializeCore(LLVMGetGlobalPassRegistry());
        LLVMInitializeNativeAsmPrinter();
        LLVMInitializeNativeAsmParser();
        LLVMInitializeNativeDisassembler();
        LLVMInitializeNativeTarget();
//        LLVMLoadLibraryPermanently("/Users/files/code/testPainless/sum.ll");

        // Stage 2: Build the sum function
        LLVMOrcThreadSafeContextRef threadContext = LLVMOrcCreateNewThreadSafeContext();
        LLVMContextRef context = LLVMOrcThreadSafeContextGetContext(threadContext);
        LLVMModuleRef module = LLVMModuleCreateWithNameInContext(root.getLocation().getSourceName(), context);
        LLVMBuilderRef builder = LLVMCreateBuilderInContext(context);
        LLVMTypeRef i64Type = LLVMInt64TypeInContext(context);

        //获取外层function
        final SFunction functionNode = root.getFunctionNodes().get(0);
        LLVMValueRef functionValueRef;
        // 定义函数及其对应的参数配置
        final int paramsSize = functionNode.getCanonicalTypeNameParameters().size();
        PointerPointer<Pointer> argumentTypes = new PointerPointer<>(paramsSize);
        for (int i = 0; i < paramsSize; i++) {
            argumentTypes.put(i, i64Type);
        }
        //定义外层入口function
        functionValueRef = LLVMAddFunction(module, functionNode.getFunctionName(), LLVMFunctionType(i64Type, argumentTypes, paramsSize, 0)); // LLVMGetTypeByName2(context, functionNode.getReturnCanonicalTypeName())
        LLVMSetFunctionCallConv(functionValueRef, LLVMCCallConv);
        LLVMSetLinkage(functionValueRef, LLVMExternalLinkage);

        // 定义函数体
        // 创建entry基本块
        LLVMBasicBlockRef entryBlock = LLVMAppendBasicBlockInContext(context, functionValueRef, "entry");

        // 在基本块中添加指令,
        // 这句话如果放在ret函数后面，会导致coredump。暂时还不知原因

        // 最终等式的valueRef
        LLVMValueRef outputRef = new LLVMValueRef();

        //return 出口
        LLVMValueRef retRef = new LLVMValueRef();

        //记录函数值类型
        Map<String, LLVMValueRef> func = new HashMap<>();
        //记录函数类型
        Map<String, LLVMTypeRef> funcType = new HashMap<>();
        //函数声明部分
        for (AStatement statementNode : functionNode.getBlockNode().getStatementNodes()) {
            //SReturn
            if (statementNode instanceof SReturn) {
                final SReturn sReturn = (SReturn) statementNode;
                declareFunc(module, builder, i64Type, sReturn.getValueNode(), funcType, func);
            } else if (statementNode instanceof SExpression) {
                final SExpression sExpression = (SExpression) statementNode;
                declareFunc(module, builder, i64Type, sExpression.getStatementNode(), funcType, func);
            }
        }
        LLVMPositionBuilderAtEnd(builder, entryBlock);

        //函数体部分
        for (AStatement statementNode : functionNode.getBlockNode().getStatementNodes()) {
                //SReturn
            if (statementNode instanceof SReturn) {
                final SReturn sReturn = (SReturn) statementNode;
                if (sReturn.getValueNode() instanceof EBinary) {
                    EBinary eBinary = (EBinary) sReturn.getValueNode();
                    AExpression leftNode = eBinary.getLeftNode();
                    AExpression rightNode = eBinary.getRightNode();
                    final Operation operation = eBinary.getOperation();
                    outputRef = operator2llvm(builder,i64Type, operation,node2llvm(module,builder,i64Type,leftNode,funcType,func),node2llvm(module,builder,i64Type,rightNode,funcType,func));
                }
            }
        }
        //return
        LLVMBuildRet(builder, outputRef);

        LLVMDumpModule(module);

        BytePointer error = new BytePointer();
        if (LLVMVerifyModule(module, LLVMPrintMessageAction, error) != 0) {
            System.out.println("Failed to validate module: " + error.getString());
            return;
        }

        BytePointer out = new BytePointer((Pointer)null);
        if (LLVMPrintModuleToFile(module, "./demo.ll" ,out) != 0) {
            System.err.println("Failed to write ll to file");
            return;
        }

        // Stage 5: Dispose of allocated resources
        LLVMDisposeBuilder(builder);
        LLVMDisposeModule(module);
        LLVMContextDispose(context);
    }

    public LLVMValueRef node2llvm(LLVMModuleRef module, LLVMBuilderRef builder,LLVMTypeRef typeRef, AExpression expression, Map<String, LLVMTypeRef> funcType, Map<String, LLVMValueRef> func) {
        LLVMValueRef llvmValueRef = new LLVMValueRef();
        if(expression instanceof ESymbol) {
            ESymbol eSymbol = (ESymbol) expression;
            LLVMValueRef alloca = LLVMBuildAlloca(builder, typeRef, eSymbol.getSymbol() + "_ptr");
            LLVMValueRef num = LLVMConstInt(typeRef,Integer.parseInt("10",10),0);
            LLVMBuildStore(builder, num, alloca);
            llvmValueRef = LLVMBuildLoad2(builder, typeRef, alloca, eSymbol.getSymbol());

        } else if (expression instanceof ECall) {
            ECall eCall = (ECall) expression;
            List<AExpression> list = eCall.getArgumentNodes();
            ESymbol eSymbol = (ESymbol)eCall.getPrefixNode();
            String name = "java_lang_" + eSymbol.getSymbol() + "_" + eCall.getMethodName();

            PointerPointer<Pointer> paramsT = new PointerPointer<>(list.size());
            //获取类型
            LLVMValueRef valueRef = new LLVMValueRef();
            for(int i = 0; i < list.size(); i++){
                AExpression e  = list.get(i);
                if (e instanceof ECallLocal) {
                    //本例
                    ECallLocal eCallLocal = (ECallLocal) e;
                    valueRef = LLVMBuildAlloca(builder, typeRef, eSymbol.getSymbol());
                    LLVMValueRef num = node2llvm(module, builder, typeRef, eCallLocal, funcType, func);
                    LLVMBuildStore(builder, num, valueRef);
                } else if (e instanceof ENumeric) {
                    ENumeric eNumeric = (ENumeric)e;
                    valueRef = LLVMBuildAlloca(builder, LLVMInt64Type(), "param_ptr");
                    LLVMValueRef num = LLVMConstInt(LLVMInt64Type(),Integer.parseInt(eNumeric.getNumeric(),eNumeric.getRadix()),0);
                    LLVMBuildStore(builder, num, valueRef);
                }
                paramsT.put(i, valueRef);
            }
            //获取函数的Function
            LLVMValueRef function = func.get(name);
            LLVMTypeRef functionType = funcType.get(name);
            //这里使用load来加载指针中的值
            LLVMValueRef llvmValueRef1 = LLVMBuildLoad2(builder, typeRef, valueRef, "param");
            // 调用函数
            llvmValueRef = LLVMBuildCall2(builder, functionType, function,  llvmValueRef1, 1, new BytePointer(name));
            //赋值
//            LLVMBuildStore(builder, function, result);
        } else if (expression instanceof ECallLocal) {
            ECallLocal eCallLocal = (ECallLocal) expression;
            List<AExpression> list = eCallLocal.getArgumentNodes();
            PointerPointer<Pointer> paramsT = new PointerPointer<>(list.size());
            //获取类型
            for(int i = 0; i < list.size(); ++i){
                LLVMValueRef intValue = node2llvm(module, builder, typeRef, list.get(i), funcType, func);
                paramsT.put(i, intValue);
            }
            //获取函数的Function
            LLVMValueRef function = func.get(eCallLocal.getMethodName());
            LLVMTypeRef functionType = funcType.get(eCallLocal.getMethodName());
            // 调用函数
            llvmValueRef = LLVMBuildCall2(builder, functionType, function,  paramsT, list.size(), eCallLocal.getMethodName());

        } else if (expression instanceof EBinary) {
            EBinary eBinary = (EBinary) expression;
            AExpression leftNode = eBinary.getLeftNode();
            AExpression rightNode = eBinary.getRightNode();
            final Operation operation = eBinary.getOperation();

            llvmValueRef = operator2llvm(builder,typeRef, operation, node2llvm(module,builder,typeRef,leftNode,funcType,func),node2llvm(module,builder,typeRef,rightNode,funcType,func));

        } else if (expression instanceof ENumeric) {
            ENumeric eNumeric = (ENumeric)expression;
            //分配空间 + 赋值
            llvmValueRef = LLVMConstInt(typeRef,Integer.parseInt(eNumeric.getNumeric(),eNumeric.getRadix()),0);
        } else if (expression instanceof EDot) {
            EDot eDot = (EDot)expression;
            if (eDot.getPrefixNode() instanceof EBrace) {
                EBrace eBrace = (EBrace) eDot.getPrefixNode();
                ESymbol prefix = (ESymbol) eBrace.getPrefixNode();
                EString index = (EString) eBrace.getIndexNode();
                String name = prefix.getSymbol() + "_" + eDot.getIndex()  + "_" + index.getString();
                //String类型
                LLVMTypeRef int_array_type = LLVMArrayType(LLVMInt8Type(), index.getString().length());
                //分配string值空间
                final LLVMValueRef valueRef2 = LLVMBuildAlloca(builder, int_array_type, "field");
                LLVMValueRef strValue = LLVMConstString(new BytePointer(index.getString()), index.getString().length(), 1);
                LLVMBuildStore(builder, strValue, valueRef2);
                //获取函数的Function
                LLVMValueRef function = func.get(name);
                LLVMTypeRef functionType = funcType.get(name);
                // 调用函数
                llvmValueRef = LLVMBuildCall2(builder, functionType, function,  valueRef2, 1, new BytePointer(name));
            } else {
                //param.origin
                ESymbol eSymbol = (ESymbol) eDot.getPrefixNode();
                String index = eDot.getIndex();

                LLVMValueRef alloca = LLVMBuildAlloca(builder, typeRef, eSymbol.getSymbol() + "." + index + "_ptr");
                LLVMValueRef num = LLVMConstInt(typeRef,Integer.parseInt("10",10),0);
                LLVMBuildStore(builder, num, alloca);
                llvmValueRef = LLVMBuildLoad2(builder, typeRef, alloca, eSymbol.getSymbol() + "." + index);
            }

        }
        return llvmValueRef;
    }

    public LLVMValueRef declareFunc(LLVMModuleRef module, LLVMBuilderRef builder,LLVMTypeRef typeRef, AExpression expression, Map<String, LLVMTypeRef> funcType, Map<String, LLVMValueRef> func) {
        LLVMValueRef llvmValueRef = new LLVMValueRef();
        if (expression instanceof ECall) {
            ECall eCall = (ECall) expression;
            List<AExpression> list = eCall.getArgumentNodes();
            ESymbol eSymbol = (ESymbol)eCall.getPrefixNode();
            String name = "java_lang_" + eSymbol.getSymbol() + "_" + eCall.getMethodName();
            if (func.containsKey(name)){
                return llvmValueRef;
            }
            PointerPointer<Pointer> paramsT = new PointerPointer<>(list.size());
            //获取类型
            for(int i = 0; i < list.size(); ++i){
                paramsT.put(i, typeRef);
            }
            //声明参数中调用的行数
            for(int i = 0; i < list.size(); ++i){
                declareFunc(module, builder, typeRef, list.get(i), funcType, func);
            }
            //声明函数
            LLVMTypeRef llvmTypeRef = LLVMFunctionType(typeRef, paramsT, list.size(), 0);
            llvmValueRef = LLVMAddFunction(module, name, llvmTypeRef);

            LLVMSetFunctionCallConv(llvmValueRef, LLVMCCallConv);
            LLVMSetLinkage(llvmValueRef, LLVMExternalLinkage);
            func.put(name,llvmValueRef);
            funcType.put(name, llvmTypeRef);
        } else if (expression instanceof ECallLocal) {
            ECallLocal eCallLocal = (ECallLocal) expression;
            List<AExpression> list = eCallLocal.getArgumentNodes();
            if (func.containsKey(eCallLocal.getMethodName())){
                return llvmValueRef;
            }
            PointerPointer<Pointer> paramsT = new PointerPointer<>(list.size());
            //获取类型
            for(int i = 0; i < list.size(); ++i){
                paramsT.put(i,typeRef);
            }
            //声明函数
            LLVMTypeRef llvmTypeRef = LLVMFunctionType(typeRef, paramsT, list.size(), 0);
            llvmValueRef = LLVMAddFunction(module, eCallLocal.getMethodName(), llvmTypeRef);
            LLVMSetFunctionCallConv(llvmValueRef, LLVMCCallConv);
            LLVMSetLinkage(llvmValueRef, LLVMExternalLinkage);
            func.put(eCallLocal.getMethodName(),llvmValueRef);
            funcType.put(eCallLocal.getMethodName(), llvmTypeRef);
        } else if (expression instanceof EDot) {
            EDot eDot = (EDot)expression;
            if (eDot.getPrefixNode() instanceof EBrace) {
                EBrace eBrace = (EBrace) eDot.getPrefixNode();
                ESymbol prefix = (ESymbol) eBrace.getPrefixNode();
                EString index = (EString) eBrace.getIndexNode();

                String name = prefix.getSymbol() + "_" + eDot.getIndex() + "_" + index.getString();
                if (func.containsKey(name)){
                    return llvmValueRef;
                }
                //String类型
                LLVMTypeRef int_array_type = LLVMArrayType(LLVMInt8Type(), index.getString().length());
                LLVMTypeRef stringType = LLVMPointerType(int_array_type, 0);

                //声明函数
                LLVMTypeRef functionType = LLVMFunctionType(typeRef, stringType, 1, 0);
                llvmValueRef = LLVMAddFunction(module, name, functionType);
                LLVMSetFunctionCallConv(llvmValueRef, LLVMCCallConv);
                LLVMSetLinkage(llvmValueRef, LLVMExternalLinkage);
                func.put(name,llvmValueRef);
                funcType.put(name, functionType);
            }

        } else if (expression instanceof EBinary) {
            EBinary eBinary = (EBinary) expression;
            AExpression leftNode = eBinary.getLeftNode();
            AExpression rightNode = eBinary.getRightNode();
            declareFunc(module,builder,typeRef,leftNode,funcType,func);
            declareFunc(module,builder,typeRef,rightNode,funcType,func);
        }  else {
            return null;
        }
        return llvmValueRef;
    }

    public LLVMValueRef operator2llvm(LLVMBuilderRef builder,LLVMTypeRef typeRef,Operation operation, LLVMValueRef first, LLVMValueRef second) {
        LLVMValueRef llvmValueRef = new LLVMValueRef();

        switch (operation.symbol) {
            case "+":
                llvmValueRef = LLVMBuildAdd(builder, first, second, "AND");
                break;
            case "-":
                llvmValueRef = LLVMBuildSub(builder, first, second, "SUB");
                break;
            case "*":
                llvmValueRef = LLVMBuildMul(builder, first, second, "MUL");
                break;
            case "/":
                llvmValueRef = LLVMBuildFDiv(builder, first, second, "DIV");
                break;
            case "%":
                llvmValueRef = LLVMBuildSRem(builder, first, second, "SRem");
                break;
            default:
                break;
        }
        return llvmValueRef;
    }

}
