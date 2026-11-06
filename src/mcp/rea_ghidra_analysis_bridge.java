// Copyright 2026 Muvon Un Limited
// Copyright 2026 TrillionniumFoundation
// SPDX-License-Identifier: Apache-2.0
// Fixed ELF analysis over admitted bytes. No target execution or caller script.
import java.io.*;
import java.math.BigInteger;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.TimeUnit;
import ghidra.GhidraApplicationLayout;
import ghidra.framework.Application;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.app.util.importer.ProgramLoader;
import ghidra.app.util.bin.ByteArrayProvider;
import ghidra.app.util.opinion.ElfLoader;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressIterator;
import ghidra.program.model.address.AddressRange;
import ghidra.program.model.address.AddressRangeIterator;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.task.TimeoutTaskMonitor;

class HeptaGhidraAnalysis {
    static final List<String> ANALYZERS=List.of(
        "Disassemble Entry Points","Function Start Search","Stack","Subroutine References");
    static final int SCAN_LIMIT=4096,ROW_LIMIT=128,ANALYSIS_SECONDS=30,DECOMPILE_SECONDS=15;

    static String bounded(String text,int limit) {
        if(text.length()<=limit)return text;
        int end=limit;
        if(end>0 && Character.isHighSurrogate(text.charAt(end-1)))end--;
        return text.substring(0,end);
    }
    static String digest(byte[] bytes) throws Exception {
        return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    }
    static String digest(String text) throws Exception {
        return digest(text.getBytes(StandardCharsets.UTF_8));
    }
    static String address(Address value) {
        return value.isMemoryAddress() && !value.isExternalAddress()
            ? "0x"+Long.toUnsignedString(value.getOffset(),16) : value.toString(true);
    }
    static boolean validAddress(String value) {
        return value.matches("0x(?:0|[1-9a-f][0-9a-f]{0,15})");
    }
    static String json(Object value) {
        if(value==null)return "null";
        if(value instanceof Boolean || value instanceof Number)return value.toString();
        if(value instanceof String text) {
            StringBuilder out=new StringBuilder("\"");
            for(int i=0;i<text.length();i++) {
                char c=text.charAt(i);
                if(c=='"' || c=='\\')out.append('\\').append(c);
                else if(c<32 || Character.isSurrogate(c))out.append(String.format("\\u%04x",(int)c));
                else out.append(c);
            }
            return out.append('"').toString();
        }
        if(value instanceof Map<?,?> map) {
            List<String> parts=new ArrayList<>();
            for(var entry:map.entrySet())parts.add(json(entry.getKey().toString())+":"+json(entry.getValue()));
            return "{"+String.join(",",parts)+"}";
        }
        if(value instanceof List<?> list) {
            List<String> parts=new ArrayList<>();
            for(Object item:list)parts.add(json(item));
            return "["+String.join(",",parts)+"]";
        }
        throw new IllegalArgumentException("unsupported JSON observation");
    }

    static Map<String,Object> functionRow(Function function) throws Exception {
        Map<String,Object> row=new LinkedHashMap<>();
        String name=function.getName(true);
        String signature=function.getPrototypeString(false,false);
        row.put("entry_address",address(function.getEntryPoint()));
        row.put("name",bounded(name,256));
        row.put("name_complete",name.length()<=256);
        row.put("name_sha256",digest(name));
        row.put("signature",bounded(signature,1024));
        row.put("signature_complete",signature.length()<=1024);
        row.put("signature_sha256",digest(signature));
        row.put("external",function.isExternal());
        row.put("thunk",function.isThunk());
        row.put("body_min_address",address(function.getBody().getMinAddress()));
        row.put("body_max_address",address(function.getBody().getMaxAddress()));
        row.put("body_address_count",Long.toUnsignedString(function.getBody().getNumAddresses()));
        return row;
    }


    static final int INSTRUCTION_LIMIT=4096,INSTRUCTION_SECONDS=10;
    static final List<String> INSTRUCTION_LIMITATIONS=List.of(
        "Instruction text and ordering are Ghidra-specific representations.",
        "The fast path does not invoke the decompiler or scan whole-program names and strings.",
        "Completeness covers the selected function's observed Listing after the fixed restricted analyzer profile; it does not prove complete machine-code discovery.",
        "The original provider's terminal-call and Borland SEH boundary heuristics are not reproduced by this bounded ELF adapter.",
        "The byte rows describe Ghidra's initialized instruction memory, including loader adjustments; they are not file-offset mappings.");

    static String completeInstructionText(String text,int maximum,String role) {
        if(text==null || text.isEmpty() || text.indexOf('\0')>=0 ||
            text.indexOf('\r')>=0 || text.indexOf('\n')>=0)
            throw new IllegalStateException(role+" is empty or is not one complete text line");
        for(int i=0;i<text.length();i++) {
            char c=text.charAt(i);
            if(Character.isHighSurrogate(c)) {
                if(i+1==text.length() || !Character.isLowSurrogate(text.charAt(i+1)))
                    throw new IllegalStateException(role+" contains an unpaired surrogate");
                i++;
            } else if(Character.isLowSurrogate(c))
                throw new IllegalStateException(role+" contains an unpaired surrogate");
        }
        if(text.getBytes(StandardCharsets.UTF_8).length>maximum)
            throw new IllegalStateException(role+" exceeds its complete-text byte budget");
        return text;
    }

    static String instructionAddress(Program program,Address value) {
        String offset="0x"+Long.toUnsignedString(value.getOffset(),16);
        if(value.getAddressSpace().equals(program.getAddressFactory().getDefaultAddressSpace()))
            return offset;
        byte[] name=value.getAddressSpace().getName().getBytes(StandardCharsets.UTF_8);
        StringBuilder encoded=new StringBuilder();
        for(byte item:name) {
            int b=item&255;
            if((b>='a' && b<='z') || (b>='A' && b<='Z') || (b>='0' && b<='9') ||
                b=='.' || b=='_' || b=='~' || b=='-')encoded.append((char)b);
            else encoded.append(String.format(Locale.ROOT,"%%%02X",b));
        }
        if(encoded.length()==0 || encoded.length()>1024)
            throw new IllegalStateException("instruction address-space name exceeds its budget");
        return encoded+":"+offset;
    }

    static long instructionBodyCount(BigInteger value) {
        if(value.signum()<0 || value.compareTo(BigInteger.valueOf(9007199254740991L))>0)
            throw new IllegalStateException("complete function body exceeds exact JSON byte-count range");
        return value.longValueExact();
    }

    static Map<String,Object> instructionBody(Program program,Function function,TimeoutTaskMonitor monitor)
            throws Exception {
        List<Map<String,Object>> ranges=new ArrayList<>();
        BigInteger total=BigInteger.ZERO;
        Address first=null,last=null;
        AddressSpace space=null;
        boolean multipleSpaces=false;
        AddressRangeIterator iterator=function.getBody().getAddressRanges(true);
        while(iterator.hasNext()) {
            monitor.checkCancelled();
            if(ranges.size()==INSTRUCTION_LIMIT)
                throw new IllegalStateException("complete function body exceeds the fixed range budget");
            AddressRange range=iterator.next();
            Address begin=range.getMinAddress(),end=range.getMaxAddress();
            if(begin.getAddressSpace().getAddressableUnitSize()!=1 ||
                !begin.getAddressSpace().equals(end.getAddressSpace()))
                throw new IllegalStateException("complete instruction body requires byte-addressed ranges");
            Map<String,Object> row=new LinkedHashMap<>();
            row.put("start",instructionAddress(program,begin));
            row.put("end",instructionAddress(program,end));
            ranges.add(row);
            total=total.add(new BigInteger(Long.toUnsignedString(end.getOffset()))
                .subtract(new BigInteger(Long.toUnsignedString(begin.getOffset()))).add(BigInteger.ONE));
            if(first==null) { first=begin;space=begin.getAddressSpace(); }
            else if(!space.equals(begin.getAddressSpace()))multipleSpaces=true;
            last=end;
        }
        BigInteger span=first==null?BigInteger.ZERO:
            new BigInteger(Long.toUnsignedString(last.getOffset()))
                .subtract(new BigInteger(Long.toUnsignedString(first.getOffset()))).add(BigInteger.ONE);
        Map<String,Object> body=new LinkedHashMap<>();
        body.put("available",true);
        body.put("provenance","ghidra-function-body-address-set");
        body.put("ranges",ranges);
        body.put("total_bytes",instructionBodyCount(total));
        body.put("span_bytes",multipleSpaces?null:instructionBodyCount(span));
        body.put("non_contiguous",ranges.size()>1);
        body.put("contains_entry",function.getBody().contains(function.getEntryPoint()));
        if(!function.getBody().contains(function.getEntryPoint()))
            throw new IllegalStateException("selected internal function body omits its entry");
        return body;
    }

    static Map<String,Object> instructionProcedure(Program program,Function function,TimeoutTaskMonitor monitor)
            throws Exception {
        Symbol symbol=function.getSymbol();
        String name=symbol==null?function.getName():symbol.getName(true);
        Map<String,Object> metadata=null;
        if(symbol!=null) {
            String type=symbol.getSymbolType().toString().toLowerCase(Locale.ROOT)
                .replaceAll("[^a-z0-9]+","_").replaceAll("^_+|_+$","");
            metadata=new LinkedHashMap<>();
            metadata.put("primary",symbol.isPrimary());
            metadata.put("dynamic",symbol.isDynamic());
            metadata.put("external",symbol.isExternal());
            metadata.put("type",type.isEmpty()?"unknown":completeInstructionText(type,128,"symbol type"));
            metadata.put("source",symbol.getSource().name().toLowerCase(Locale.ROOT));
        }
        Function target=function.isThunk()?function.getThunkedFunction(false):null;
        Map<String,Object> classification=new LinkedHashMap<>();
        classification.put("external",function.isExternal());
        classification.put("thunk",function.isThunk());
        classification.put("thunk_target",target==null?null:instructionAddress(program,target.getEntryPoint()));
        classification.put("provenance","ghidra-function-manager");
        Map<String,Object> result=new LinkedHashMap<>();
        result.put("address",instructionAddress(program,function.getEntryPoint()));
        result.put("name",completeInstructionText(name,1024,"complete procedure name"));
        result.put("symbol",metadata);
        result.put("classification",classification);
        result.put("body",instructionBody(program,function,monitor));
        return result;
    }

    static void instructions(Program program,Function function,Map<String,Object> report) throws Exception {
        TimeoutTaskMonitor monitor=TimeoutTaskMonitor.timeoutIn(INSTRUCTION_SECONDS,TimeUnit.SECONDS);
        try {
            Map<String,Object> procedure=instructionProcedure(program,function,monitor);
            InstructionIterator iterator=program.getListing().getInstructions(function.getBody(),true);
            List<String> lines=new ArrayList<>();
            List<Map<String,Object>> bytes=new ArrayList<>();
            long textBytes=0;
            while(iterator.hasNext()) {
                monitor.checkCancelled();
                if(lines.size()==INSTRUCTION_LIMIT)
                    throw new IllegalStateException("complete function instruction list exceeds the fixed instruction budget");
                Instruction instruction=iterator.next();
                if(!function.getBody().contains(instruction.getMinAddress(),instruction.getMaxAddress()))
                    throw new IllegalStateException("instruction extends outside the selected complete function body");
                String at=instructionAddress(program,instruction.getAddress());
                StringBuilder line=new StringBuilder(at).append(": ").append(instruction.getMnemonicString());
                for(int index=0;index<instruction.getNumOperands();index++)
                    line.append(index==0?" ":", ").append(instruction.getDefaultOperandRepresentation(index));
                String rendered=completeInstructionText(line.toString(),4096,"complete Listing line");
                textBytes+=rendered.getBytes(StandardCharsets.UTF_8).length+(lines.isEmpty()?0:1);
                if(textBytes>65536)
                    throw new IllegalStateException("complete instruction text exceeds the fixed byte budget");
                byte[] encoded=instruction.getBytes();
                if(encoded.length==0 || encoded.length>1024 || encoded.length!=instruction.getLength())
                    throw new IllegalStateException("instruction memory bytes disagree with its bounded length");
                Map<String,Object> row=new LinkedHashMap<>();
                row.put("address",at);
                row.put("length",encoded.length);
                row.put("bytes_hex",HexFormat.of().formatHex(encoded));
                lines.add(rendered);bytes.add(row);
            }
            monitor.checkCancelled();
            Map<String,Object> window=new LinkedHashMap<>();
            window.put("procedure",procedure);
            window.put("instructions",lines);
            window.put("limitations",INSTRUCTION_LIMITATIONS);
            report.put("upstream_operation","read_function_instructions");
            report.put("instruction_provenance","ghidra-listing");
            report.put("instruction_scope","selected_function_body_address_set");
            report.put("instruction_window",window);
            report.put("instruction_bytes",bytes);
            report.put("instruction_count",lines.size());
            report.put("instructions_complete",true);
            report.put("omitted_instructions",0);
            report.put("instruction_text_sha256",digest(String.join("\n",lines)));
            report.put("instruction_text_utf8_bytes",textBytes);
            report.put("instruction_timeout_seconds",INSTRUCTION_SECONDS);
            report.put("decompiler_invoked",false);
        } finally {
            monitor.cancel();
        }
    }

    static Map<String,Object> referenceRow(Reference reference) {
        Map<String,Object> row=new LinkedHashMap<>();
        row.put("from_address",address(reference.getFromAddress()));
        row.put("to_address",address(reference.getToAddress()));
        row.put("from_space",reference.getFromAddress().getAddressSpace().getName());
        row.put("to_space",reference.getToAddress().getAddressSpace().getName());
        row.put("reference_type",reference.getReferenceType().toString());
        row.put("source_type",reference.getSource().toString());
        row.put("operand_index",reference.getOperandIndex());
        row.put("call",reference.getReferenceType().isCall());
        row.put("primary",reference.isPrimary());
        return row;
    }

    static void analyze(Program program,Map<String,Object> report) throws Exception {
        AutoAnalysisManager manager=AutoAnalysisManager.getAnalysisManager(program);
        TimeoutTaskMonitor monitor=TimeoutTaskMonitor.timeoutIn(ANALYSIS_SECONDS,TimeUnit.SECONDS);
        int transaction=program.startTransaction("Fixed Hepta ELF function analysis");
        boolean commit=false;
        try {
            Options options=program.getOptions(Program.ANALYSIS_PROPERTIES);
            List<String> disabled=new ArrayList<>(),enabled=new ArrayList<>();
            for(String name:options.getOptionNames()) {
                if(manager.getAnalyzer(name)==null)continue;
                boolean allow=ANALYZERS.contains(name);
                options.setBoolean(name,allow);
                (allow?enabled:disabled).add(name);
            }
            Collections.sort(enabled);
            Collections.sort(disabled);
            if(!enabled.equals(ANALYZERS))
                throw new IllegalStateException("fixed analysis profile is unavailable for this program");
            options.setInt("Stack.Max Threads",1);
            manager.initializeOptions();
            manager.reAnalyzeAll(null);
            manager.startAnalysis(monitor,false);
            monitor.checkCancelled();
            String log=manager.getMessageLog().toString();
            report.put("enabled_analyzers",enabled);
            report.put("disabled_analyzer_count",disabled.size());
            report.put("disabled_analyzers_sha256",digest(json(disabled)));
            report.put("analysis_log",bounded(log,2048));
            report.put("analysis_log_complete",log.length()<=2048);
            report.put("analysis_log_sha256",digest(log));
            report.put("analysis_completed",true);
            report.put("analysis_timeout_seconds",ANALYSIS_SECONDS);
            report.put("instruction_count_after_analysis",program.getListing().getNumInstructions());
            report.put("reported_function_count_after_analysis",program.getFunctionManager().getFunctionCount());
            commit=true;
        } finally {
            monitor.cancel();
            manager.dispose();
            program.endTransaction(transaction,commit);
        }
    }

    static void functions(Program program,Map<String,Object> report) throws Exception {
        FunctionIterator iterator=program.getFunctionManager().getFunctions(true);
        List<Map<String,Object>> rows=new ArrayList<>();
        int scanned=0;
        while(iterator.hasNext() && scanned<SCAN_LIMIT) {
            Function function=iterator.next();
            if(function.isExternal())continue;
            scanned++;
            if(rows.size()<ROW_LIMIT)rows.add(functionRow(function));
        }
        report.put("functions",rows);
        report.put("scanned_functions",scanned);
        report.put("returned_functions",rows.size());
        report.put("omitted_functions_in_scan",scanned-rows.size());
        report.put("function_scan_complete",!iterator.hasNext());
    }

    static void xrefs(Program program,Function function,Map<String,Object> report) {
        List<Map<String,Object>> incoming=new ArrayList<>(),outgoing=new ArrayList<>();
        ReferenceIterator incomingIterator=program.getReferenceManager().getReferencesTo(function.getEntryPoint());
        int scannedIn=0,scannedOut=0;
        while(incomingIterator.hasNext() && scannedIn<SCAN_LIMIT) {
            Reference reference=incomingIterator.next();
            scannedIn++;
            if(incoming.size()<ROW_LIMIT)incoming.add(referenceRow(reference));
        }
        boolean incomingComplete=!incomingIterator.hasNext(),outgoingComplete=true;
        AddressIterator sources=program.getReferenceManager().getReferenceSourceIterator(function.getBody(),true);
        outer: while(sources.hasNext()) {
            Address source=sources.next();
            for(Reference reference:program.getReferenceManager().getReferencesFrom(source)) {
                if(scannedOut==SCAN_LIMIT) { outgoingComplete=false;break outer; }
                scannedOut++;
                if(outgoing.size()<ROW_LIMIT)outgoing.add(referenceRow(reference));
            }
        }
        report.put("incoming_scope","exact_function_entry");
        report.put("outgoing_scope","selected_function_body");
        report.put("incoming_references",incoming);
        report.put("outgoing_references",outgoing);
        report.put("scanned_incoming_references",scannedIn);
        report.put("scanned_outgoing_references",scannedOut);
        report.put("returned_incoming_references",incoming.size());
        report.put("returned_outgoing_references",outgoing.size());
        report.put("omitted_incoming_references_in_scan",scannedIn-incoming.size());
        report.put("omitted_outgoing_references_in_scan",scannedOut-outgoing.size());
        report.put("incoming_scan_complete",incomingComplete);
        report.put("outgoing_scan_complete",outgoingComplete);
    }

    static void decompile(Program program,Function function,Map<String,Object> report) throws Exception {
        DecompInterface decompiler=new DecompInterface();
        TimeoutTaskMonitor monitor=TimeoutTaskMonitor.timeoutIn(DECOMPILE_SECONDS,TimeUnit.SECONDS);
        List<ProcessHandle> children=new ArrayList<>();
        try {
            if(!decompiler.openProgram(program))
                throw new IllegalStateException("fixed native decompiler could not open the selected program");
            children=ProcessHandle.current().descendants().toList();
            DecompileResults result=decompiler.decompileFunction(function,DECOMPILE_SECONDS,monitor);
            monitor.checkCancelled();
            if(result==null || !result.decompileCompleted() || result.getDecompiledFunction()==null)
                throw new IllegalStateException("selected function decompilation did not complete: "+
                    (result==null?"no result":bounded(result.getErrorMessage(),1024)));
            String code=result.getDecompiledFunction().getC();
            byte[] encoded=code.getBytes(StandardCharsets.UTF_8);
            if(encoded.length>1024*1024)throw new IllegalStateException("decompiled C exceeds the fixed observation budget");
            String preview=bounded(code,8192);
            report.put("c_code",preview);
            report.put("c_code_sha256",digest(encoded));
            report.put("c_code_preview_sha256",digest(preview));
            report.put("c_code_utf8_bytes",encoded.length);
            report.put("c_code_complete",code.equals(preview));
            report.put("decompilation_completed",true);
            report.put("decompilation_timeout_seconds",DECOMPILE_SECONDS);
            report.put("decompiler_message",bounded(result.getErrorMessage(),1024));
        } finally {
            monitor.cancel();
            decompiler.stopProcess();
            decompiler.closeProgram();
            decompiler.dispose();
            for(ProcessHandle child:children) {
                if(child.isAlive()) {
                    child.onExit().get(2,TimeUnit.SECONDS);
                }
                if(child.isAlive())throw new IllegalStateException("native decompiler child cleanup is unconfirmed");
            }
        }
        if(ProcessHandle.current().descendants().anyMatch(ProcessHandle::isAlive))
            throw new IllegalStateException("analysis bridge retains a live native descendant");
        report.put("native_child_cleanup_confirmed",true);
        report.put("observed_native_children",children.size());
    }

    @SuppressWarnings("unchecked")
    static String fit(Map<String,Object> report,int budget) throws Exception {
        while(true) {
            String encoded=json(report);
            if(encoded.getBytes(StandardCharsets.UTF_8).length+1<=budget)return encoded;
            String operation=(String)report.get("operation");
            if(operation.equals("instructions"))
                throw new IllegalStateException("complete instruction window exceeds response budget");
            if(operation.equals("functions")) {
                List<?> rows=(List<?>)report.get("functions");
                if(rows.isEmpty())throw new IllegalStateException("analysis summary exceeds response budget");
                rows.subList(rows.size()/2,rows.size()).clear();
                report.put("returned_functions",rows.size());
                report.put("omitted_functions_in_scan",(Integer)report.get("scanned_functions")-rows.size());
            } else if(operation.equals("xrefs")) {
                List<?> incoming=(List<?>)report.get("incoming_references"),outgoing=(List<?>)report.get("outgoing_references");
                if(incoming.isEmpty() && outgoing.isEmpty())
                    throw new IllegalStateException("analysis summary exceeds response budget");
                List<?> rows=incoming.size()>=outgoing.size()?incoming:outgoing;
                rows.subList(rows.size()/2,rows.size()).clear();
                report.put("returned_incoming_references",incoming.size());
                report.put("returned_outgoing_references",outgoing.size());
                report.put("omitted_incoming_references_in_scan",(Integer)report.get("scanned_incoming_references")-incoming.size());
                report.put("omitted_outgoing_references_in_scan",(Integer)report.get("scanned_outgoing_references")-outgoing.size());
            } else if(operation.equals("decompile")) {
                String code=(String)report.get("c_code");
                if(code.isEmpty())throw new IllegalStateException("analysis summary exceeds response budget");
                code=bounded(code,code.length()/2);
                report.put("c_code",code);
                report.put("c_code_preview_sha256",digest(code));
                report.put("c_code_complete",false);
            } else throw new IllegalStateException("selected function summary exceeds response budget");
        }
    }

    public static void main(String[] input) throws Exception {
        if(input.length!=5)throw new IllegalArgumentException("fixed installation, captured ELF, response budget, operation and address required");
        int budget=Integer.parseInt(input[2]);
        String operation=input[3],selected=input[4];
        if(budget<2048 || budget>65536)throw new IllegalArgumentException("invalid response budget");
        if(!List.of("functions","function","decompile","xrefs","instructions").contains(operation))
            throw new IllegalArgumentException("unsupported fixed analysis operation");
        if(operation.equals("functions")?!selected.equals("-"):!validAddress(selected))
            throw new IllegalArgumentException("one exact canonical function entry is required for this operation");
        byte[] bytes=Files.readAllBytes(Path.of(input[1]));
        if(bytes.length<4 || bytes.length>8*1024*1024 || bytes[0]!=0x7f || bytes[1]!='E' || bytes[2]!='L' || bytes[3]!='F')
            throw new IllegalArgumentException("bounded captured ELF required");
        PrintStream result=System.out;
        System.setOut(new PrintStream(OutputStream.nullOutputStream()));
        var config=new HeadlessGhidraApplicationConfiguration();
        config.setInitializeLogging(false);
        Application.initializeApplication(new GhidraApplicationLayout(new File(input[0])),config);
        if(!Application.getApplicationVersion().equals("12.2"))throw new IllegalStateException("unexpected Ghidra version");
        var loader=ProgramLoader.builder().source(new ByteArrayProvider("hepta-owned-input",bytes)).name("hepta-owned-input")
            .loaders(ElfLoader.class)
            .addLoaderArg("-loader-loadLibraries","false")
            .addLoaderArg("-loader-linkExistingProjectLibraries","false");
        try(var loaded=loader.load()) {
            Program program=loaded.getPrimary().getDomainObject();
            Map<String,Object> report=new LinkedHashMap<>();
            report.put("schema","hepta.rea.ghidra-analysis.v1");
            report.put("bridge_revision",2);
            report.put("engine_version",Application.getApplicationVersion());
            report.put("operation",operation);
            report.put("analysis_profile","hepta.ghidra.elf-functions.v1");
            report.put("source_sha256",digest(bytes));
            report.put("source_bytes",bytes.length);
            report.put("function_address_requested",operation.equals("functions")?null:selected);
            report.put("loader","ghidra.app.util.opinion.ElfLoader");
            report.put("format",program.getExecutableFormat());
            report.put("language_id",program.getLanguageID().toString());
            report.put("compiler_spec_id",program.getCompilerSpec().getCompilerSpecID().toString());
            report.put("image_base",address(program.getImageBase()));
            report.put("target_executed",false);
            report.put("auto_analysis_performed",true);
            report.put("decompilation_performed",operation.equals("decompile"));
            report.put("source_semantics_validated",false);
            report.put("external_libraries_loaded",false);
            report.put("project_saved",false);
            report.put("coverage","partial");
            analyze(program,report);
            if(operation.equals("functions"))functions(program,report);
            else {
                long offset=Long.parseUnsignedLong(selected.substring(2),16);
                Address entry=program.getAddressFactory().getDefaultAddressSpace().getAddress(offset);
                Function function=program.getFunctionManager().getFunctionAt(entry);
                if(function==null || function.isExternal() || !address(function.getEntryPoint()).equals(selected))
                    throw new IllegalArgumentException("requested address is not an exact internal analyzed function entry");
                report.put("function",functionRow(function));
                if(operation.equals("xrefs"))xrefs(program,function,report);
                if(operation.equals("decompile"))decompile(program,function,report);
                if(operation.equals("instructions"))instructions(program,function,report);
            }
            result.println(fit(report,budget));
        }
    }
}
